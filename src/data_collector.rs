// src/data_collector.rs

use crate::falco_integration::{falco_event_to_lstm_timestep, FalcoEvent};
use crate::training_metrics::TrainingMetrics;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

pub struct DataCollector {
    buffer: Arc<Mutex<Vec<FalcoEvent>>>,
    labels: Arc<Mutex<Vec<f64>>>,
    output_path: String,
    max_samples: usize,
}

impl DataCollector {
    pub fn new(output_path: &str, max_samples: usize) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::new())),
            labels: Arc::new(Mutex::new(Vec::new())),
            output_path: output_path.to_string(),
            max_samples,
        }
    }

    pub async fn get_buffer_len(&self) -> usize {
        self.buffer.lock().await.len()
    }

    pub async fn anomaly_count(&self) -> usize {
        self.labels
            .lock()
            .await
            .iter()
            .filter(|&&l| l > 0.5)
            .count()
    }

    pub fn evaluate(&self, predictions: &[f64], labels: &[f64], threshold: f64) -> TrainingMetrics {
        let mut tp = 0;
        let mut tn = 0;
        let mut fp = 0;
        let mut false_neg = 0;

        for (&pred, &label) in predictions.iter().zip(labels.iter()) {
            let predicted = pred > threshold;
            let actual = label > 0.5;
            match (predicted, actual) {
                (true, true) => tp += 1,
                (true, false) => fp += 1,
                (false, true) => false_neg += 1,
                (false, false) => tn += 1,
            }
        }

        let total = (tp + tn + fp + false_neg) as f64;
        let precision = if tp + fp > 0 {
            tp as f64 / (tp + fp) as f64
        } else {
            0.0
        };
        let recall = if tp + false_neg > 0 {
            tp as f64 / (tp + false_neg) as f64
        } else {
            0.0
        };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };

        TrainingMetrics {
            timestamp: chrono::Utc::now(),
            total_samples: (tp + tn + fp + false_neg) as usize,
            normal_samples: (tn + fp) as usize,
            anomaly_samples: (tp + false_neg) as usize,
            training_loss: 0.0,
            validation_accuracy: if total > 0.0 {
                (tp + tn) as f64 / total
            } else {
                0.0
            },
            precision,
            recall,
            f1_score: f1,
            false_positive_rate: if fp + tn > 0 {
                fp as f64 / (fp + tn) as f64
            } else {
                0.0
            },
            false_negative_rate: if false_neg + tp > 0 {
                false_neg as f64 / (false_neg + tp) as f64
            } else {
                0.0
            },
        }
    }

    pub async fn add_event(&self, event: FalcoEvent, label: f64) {
        let mut buffer = self.buffer.lock().await;
        let mut labels = self.labels.lock().await;

        buffer.push(event);
        labels.push(label.clamp(0.0, 1.0));

        while buffer.len() > self.max_samples {
            buffer.remove(0);
            labels.remove(0);
        }

        if buffer.len().is_multiple_of(100) {
            info!(
                "Collector: {} samples ({} anomalies)",
                buffer.len(),
                labels.iter().filter(|&&l| l > 0.5).count()
            );
        }
    }

    pub async fn save_to_json(&self) -> Result<()> {
        let buffer = self.buffer.lock().await;
        let labels = self.labels.lock().await;

        let data: Vec<_> = buffer
            .iter()
            .zip(labels.iter())
            .map(|(event, &label)| {
                serde_json::json!({
                    "event": event,
                    "label": label
                })
            })
            .collect();

        let path = Path::new(&self.output_path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_string_pretty(&data)?;
        fs::write(&tmp, json)?;
        fs::rename(&tmp, path).context("atomic rename collector export")?;

        info!("✅ Saved {} events to {}", data.len(), self.output_path);
        Ok(())
    }

    pub async fn get_training_data(&self) -> (Vec<Vec<f64>>, Vec<f64>) {
        let buffer = self.buffer.lock().await;
        let labels = self.labels.lock().await;

        let features: Vec<Vec<f64>> = buffer
            .iter()
            .map(falco_event_to_lstm_timestep)
            .collect();

        (features, labels.clone())
    }

    /// После обучения оставляем хвост для непрерывного дообучения.
    pub async fn retain_tail(&self, keep: usize) {
        let mut buffer = self.buffer.lock().await;
        let mut labels = self.labels.lock().await;
        if buffer.len() <= keep {
            return;
        }
        let drop = buffer.len() - keep;
        buffer.drain(0..drop);
        labels.drain(0..drop);
        info!("Collector trimmed to last {} samples", keep);
    }
}
