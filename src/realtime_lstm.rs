use crate::falco_integration::{falco_event_to_lstm_timestep, FalcoEvent};
use crate::lstm_online::{LSTMOnlineDetector, LSTM_INPUT_SIZE};
use crate::ml_eval::binary_metrics;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex as TokioMutex;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct RealtimeLSTMConfig {
    pub window_size: usize,
    pub step_size: usize,
    pub threshold: f64,
    pub model_path: String,
    pub hidden_size: usize,
    pub learning_rate: f64,
    pub epochs: usize,
    pub min_train_samples: usize,
    pub grad_clip: f64,
}

impl Default for RealtimeLSTMConfig {
    fn default() -> Self {
        Self {
            window_size: 20,
            step_size: 10,
            threshold: 0.7,
            model_path: "data/lstm_model.json".to_string(),
            hidden_size: 32,
            learning_rate: 0.05,
            epochs: 30,
            min_train_samples: 100,
            grad_clip: 5.0,
        }
    }
}

#[derive(Default)]
struct LSTMStats {
    total_predictions: u64,
    anomalies_detected: u64,
    avg_inference_time_us: f64,
    last_anomaly_time: Option<Instant>,
    last_training: Option<Instant>,
}

pub struct RealtimeLSTM {
    config: RealtimeLSTMConfig,
    detector: Arc<LSTMOnlineDetector>,
    stats: Arc<TokioMutex<LSTMStats>>,
    running: Arc<AtomicBool>,
    training: Arc<AtomicBool>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TrainingResult {
    pub accuracy: f64,
    pub f1_score: f64,
    pub loss: f64,
    pub train_samples: usize,
    pub val_samples: usize,
    pub epochs_run: usize,
    pub model_saved: bool,
}

impl RealtimeLSTM {
    pub async fn new(config: RealtimeLSTMConfig) -> Self {
        let window_size = config.window_size;
        let model_path = config.model_path.clone();
        let hidden_size = config.hidden_size;

        let grad_clip = config.grad_clip;
        let detector = match LSTMOnlineDetector::load_from_path(
            &model_path,
            LSTM_INPUT_SIZE,
            hidden_size,
            window_size,
            grad_clip,
        )
        .await
        {
            Ok(Some(d)) => Arc::new(d),
            Ok(None) => {
                warn!("No trained LSTM at {}, starting fresh", model_path);
                Arc::new(LSTMOnlineDetector::new(
                    LSTM_INPUT_SIZE,
                    hidden_size,
                    window_size,
                    grad_clip,
                ))
            }
            Err(e) => {
                warn!("LSTM load error: {e:#}, starting fresh");
                Arc::new(LSTMOnlineDetector::new(
                    LSTM_INPUT_SIZE,
                    hidden_size,
                    window_size,
                    grad_clip,
                ))
            }
        };

        Self {
            config,
            detector,
            stats: Arc::new(TokioMutex::new(LSTMStats::default())),
            running: Arc::new(AtomicBool::new(true)),
            training: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn is_ready(&self) -> bool {
        self.detector.is_trained().await
    }

    pub async fn predict_single(&self, features: &[f64]) -> f64 {
        if features.len() == LSTM_INPUT_SIZE {
            self.detector
                .score_window(&[features.to_vec()])
                .await
        } else {
            warn!("predict_single: expected {} features, got {}", LSTM_INPUT_SIZE, features.len());
            0.0
        }
    }

    pub async fn process_event(&self, event: FalcoEvent) -> Option<f64> {
        let features = falco_event_to_lstm_timestep(&event);
        let start = Instant::now();
        let score = self.detector.process_step(features).await?;
        let inference_us = start.elapsed().as_micros() as f64;

        let mut stats = self.stats.lock().await;
        stats.total_predictions += 1;
        stats.avg_inference_time_us = (stats.avg_inference_time_us
            * (stats.total_predictions - 1) as f64
            + inference_us)
            / stats.total_predictions as f64;

        if score > self.config.threshold {
            stats.anomalies_detected += 1;
            stats.last_anomaly_time = Some(Instant::now());
            let anomalies = stats.anomalies_detected;
            drop(stats);
            warn!(
                "🚨 LSTM ANOMALY! Score: {:.3}, Total anomalies: {}",
                score, anomalies
            );
        }

        Some(score)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub async fn get_stats(&self) -> serde_json::Value {
        let stats = self.stats.lock().await;
        let trained = self.detector.is_trained().await;
        serde_json::json!({
            "total_predictions": stats.total_predictions,
            "anomalies_detected": stats.anomalies_detected,
            "avg_inference_time_us": stats.avg_inference_time_us,
            "last_anomaly_time_secs": stats.last_anomaly_time.map(|t| t.elapsed().as_secs()),
            "last_training_secs_ago": stats.last_training.map(|t| t.elapsed().as_secs()),
            "threshold": self.config.threshold,
            "window_size": self.config.window_size,
            "hidden_size": self.config.hidden_size,
            "model_trained": trained,
            "training_samples": self.detector.training_samples().await,
            "model_type": "LSTM",
            "model_version": crate::lstm_online::MODEL_VERSION,
            "bptt_enabled": true,
            "grad_clip": self.config.grad_clip,
        })
    }

    pub async fn train_from_data(&self, steps: &[Vec<f64>], labels: &[f64]) -> TrainingResult {
        let w = self.config.window_size;
        let min = self.config.min_train_samples;

        if steps.len() < min || labels.len() != steps.len() {
            warn!(
                "train_from_data: need >= {} aligned steps (got {} / {})",
                min,
                steps.len(),
                labels.len()
            );
            return TrainingResult {
                accuracy: 0.0,
                f1_score: 0.0,
                loss: 0.0,
                train_samples: 0,
                val_samples: 0,
                epochs_run: 0,
                model_saved: false,
            };
        }

        if self
            .training
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            warn!("training already in progress");
            return TrainingResult {
                accuracy: 0.0,
                f1_score: 0.0,
                loss: 0.0,
                train_samples: 0,
                val_samples: 0,
                epochs_run: 0,
                model_saved: false,
            };
        }

        let result = self.train_from_data_inner(steps, labels, w).await;
        self.training.store(false, Ordering::Relaxed);
        result
    }

    async fn train_from_data_inner(
        &self,
        steps: &[Vec<f64>],
        labels: &[f64],
        w: usize,
    ) -> TrainingResult {
        info!("🚀 LSTM training: {} steps, window {}", steps.len(), w);

        let windows: Vec<(Vec<Vec<f64>>, f64)> = (0..=(steps.len() - w))
            .map(|i| {
                let seq = steps[i..i + w].to_vec();
                let label = labels[i + w - 1];
                (seq, label)
            })
            .collect();

        let split = (windows.len() as f64 * 0.8).floor() as usize;
        let split = split.max(1).min(windows.len().saturating_sub(1));
        let (train_set, val_set) = windows.split_at(split);

        let lr = self.config.learning_rate;
        let mut best_val_loss = f64::MAX;
        let mut epochs_run = 0usize;
        let mut epoch_train_loss = 0.0;
        for epoch in 0..self.config.epochs {
            epochs_run = epoch + 1;
            epoch_train_loss = 0.0;

            for (seq, label) in train_set {
                epoch_train_loss += self.detector.train_step(seq, *label, lr).await;
            }
            if !train_set.is_empty() {
                epoch_train_loss /= train_set.len() as f64;
            }

            let mut val_preds = Vec::with_capacity(val_set.len());
            let mut val_labels = Vec::with_capacity(val_set.len());
            for (seq, label) in val_set {
                val_preds.push(self.detector.score_window(seq).await);
                val_labels.push(*label);
            }
            let val_metrics = binary_metrics(&val_preds, &val_labels, self.config.threshold);

            if epoch % 5 == 0 {
                info!(
                    "  epoch {}: train_loss={:.6} val_loss={:.6} val_f1={:.3}",
                    epoch, epoch_train_loss, val_metrics.loss, val_metrics.f1_score
                );
            }

            if val_metrics.loss < best_val_loss {
                best_val_loss = val_metrics.loss;
            }
        }

        let model_saved = self
            .detector
            .save_to_path(&self.config.model_path)
            .await
            .is_ok();

        if model_saved {
            let mut stats = self.stats.lock().await;
            stats.last_training = Some(Instant::now());
        } else {
            warn!("Failed to persist LSTM model to {}", self.config.model_path);
        }

        let mut val_preds = Vec::with_capacity(val_set.len());
        let mut val_labels = Vec::with_capacity(val_set.len());
        for (seq, label) in val_set {
            val_preds.push(self.detector.score_window(seq).await);
            val_labels.push(*label);
        }
        let final_val = binary_metrics(&val_preds, &val_labels, self.config.threshold);

        TrainingResult {
            accuracy: final_val.accuracy,
            f1_score: final_val.f1_score,
            loss: final_val.loss,
            train_samples: train_set.len(),
            val_samples: val_set.len(),
            epochs_run,
            model_saved,
        }
    }
}
