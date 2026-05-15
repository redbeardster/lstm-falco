// src/lstm_online.rs — онлайн LSTM-детектор с полной персистентностью.

use crate::ml::lstm_bptt::train_sequence_bptt;
use crate::ml::lstm_cell::{LSTMCell, LSTMCellState};
use anyhow::{Context, Result};
use ndarray::Array1;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

pub const LSTM_INPUT_SIZE: usize = 8;
pub const MODEL_VERSION: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LSTMClassifierState {
    pub weights: Vec<f64>,
    pub bias: f64,
    pub hidden_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LSTMModelFile {
    pub version: u32,
    pub lstm: LSTMCellState,
    pub classifier: LSTMClassifierState,
    pub training_samples: u64,
    pub trained_at: Option<String>,
}

pub struct LSTMOnlineDetector {
    lstm: Arc<Mutex<LSTMCell>>,
    classifier: Arc<Mutex<LSTMClassifierState>>,
    sequence_buffer: Arc<Mutex<VecDeque<Vec<f64>>>>,
    seq_length: usize,
    hidden_size: usize,
    input_size: usize,
    training_samples: Arc<Mutex<u64>>,
    grad_clip: f64,
}

impl LSTMOnlineDetector {
    pub fn new(input_size: usize, hidden_size: usize, seq_length: usize, grad_clip: f64) -> Self {
        let classifier = LSTMClassifierState {
            weights: vec![0.0; hidden_size],
            bias: 0.0,
            hidden_size,
        };

        Self {
            lstm: Arc::new(Mutex::new(LSTMCell::new(input_size, hidden_size))),
            classifier: Arc::new(Mutex::new(classifier)),
            sequence_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(seq_length))),
            seq_length,
            hidden_size,
            input_size,
            training_samples: Arc::new(Mutex::new(0)),
            grad_clip,
        }
    }

    pub async fn load_from_path(
        path: &str,
        input_size: usize,
        hidden_size: usize,
        seq_length: usize,
        grad_clip: f64,
    ) -> Result<Option<Self>> {
        let path = Path::new(path);
        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(path).context("read LSTM model")?;
        let file: LSTMModelFile = serde_json::from_str(&content).context("parse LSTM model")?;

        if file.version != MODEL_VERSION {
            warn!(
                "LSTM model version {} != {}, reinitializing weights",
                file.version, MODEL_VERSION
            );
            return Ok(None);
        }

        if file.lstm.input_size != input_size || file.lstm.hidden_size != hidden_size {
            warn!(
                "LSTM model shape mismatch (file {}x{}, expected {}x{})",
                file.lstm.input_size,
                file.lstm.hidden_size,
                input_size,
                hidden_size
            );
            return Ok(None);
        }

        if file.classifier.weights.len() != hidden_size {
            warn!("Classifier dimension mismatch");
            return Ok(None);
        }

        let detector = Self {
            lstm: Arc::new(Mutex::new(LSTMCell::from_state(&file.lstm)?)),
            classifier: Arc::new(Mutex::new(file.classifier)),
            sequence_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(seq_length))),
            seq_length,
            hidden_size,
            input_size,
            training_samples: Arc::new(Mutex::new(file.training_samples)),
            grad_clip,
        };

        info!(
            "✅ LSTM model loaded from {} ({} training samples)",
            path.display(),
            file.training_samples
        );
        Ok(Some(detector))
    }

    pub async fn save_to_path(&self, path: &str) -> Result<()> {
        let lstm = self.lstm.lock().await;
        let classifier = self.classifier.lock().await.clone();
        let training_samples = *self.training_samples.lock().await;

        let file = LSTMModelFile {
            version: MODEL_VERSION,
            lstm: lstm.to_state(),
            classifier,
            training_samples,
            trained_at: Some(chrono::Utc::now().to_rfc3339()),
        };

        let json = serde_json::to_string_pretty(&file)?;
        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json)?;
        fs::rename(&tmp, path).context("atomic rename LSTM model")?;
        info!("💾 LSTM model saved to {}", path.display());
        Ok(())
    }

    /// Потоковая обработка одного шага; при заполнении окна возвращает score.
    pub async fn process_step(&self, features: Vec<f64>) -> Option<f64> {
        if features.len() != self.input_size {
            warn!(
                "LSTM step size mismatch: expected {}, got {}",
                self.input_size,
                features.len()
            );
            return None;
        }

        let mut buffer = self.sequence_buffer.lock().await;
        buffer.push_back(features);

        if buffer.len() >= self.seq_length {
            let seq: Vec<Vec<f64>> = buffer.drain(0..self.seq_length).collect();
            drop(buffer);
            self.score_sequence(&seq).await
        } else {
            None
        }
    }

    pub async fn score_window(&self, sequence: &[Vec<f64>]) -> f64 {
        self.score_sequence(sequence).await.unwrap_or(0.0)
    }

    pub async fn train_step(&self, sequence: &[Vec<f64>], label: f64, lr: f64) -> f64 {
        let mut lstm = self.lstm.lock().await;
        let mut classifier = self.classifier.lock().await;
        let loss = train_sequence_bptt(
            &mut lstm,
            &mut classifier,
            sequence,
            label,
            lr,
            self.grad_clip,
        );
        drop(lstm);
        drop(classifier);
        let mut samples = self.training_samples.lock().await;
        *samples += 1;
        loss
    }

    async fn score_sequence(&self, sequence: &[Vec<f64>]) -> Option<f64> {
        let (score, _) = self.forward_final_hidden(sequence).await?;
        Some(score)
    }

    async fn forward_final_hidden(&self, sequence: &[Vec<f64>]) -> Option<(f64, Vec<f64>)> {
        if sequence.is_empty() {
            return None;
        }

        let lstm = self.lstm.lock().await;
        let h0 = Array1::zeros(self.hidden_size);
        let mut c = Array1::zeros(self.hidden_size);
        let mut h = h0;

        for step in sequence {
            if step.len() != self.input_size {
                continue;
            }
            let x = Array1::from_vec(step.to_vec());
            let (h_new, c_new) = lstm.forward(&x, &h, &c);
            h = h_new;
            c = c_new;
        }

        let hidden: Vec<f64> = h.iter().copied().collect();
        let classifier = self.classifier.lock().await;
        let score = predict_hidden(&classifier, &hidden);
        Some((score, hidden))
    }

    pub async fn is_trained(&self) -> bool {
        let classifier = self.classifier.lock().await;
        classifier.weights.iter().any(|w| w.abs() > 1e-6)
    }

    pub async fn training_samples(&self) -> u64 {
        *self.training_samples.lock().await
    }
}

pub(crate) fn predict_hidden(classifier: &LSTMClassifierState, hidden: &[f64]) -> f64 {
    let mut sum = classifier.bias;
    let n = classifier.weights.len().min(hidden.len());
    for i in 0..n {
        sum += classifier.weights[i] * hidden[i];
    }
    (1.0 / (1.0 + (-sum).exp())).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn train_and_predict() {
        let det = LSTMOnlineDetector::new(8, 16, 4, 5.0);
        let seq: Vec<Vec<f64>> = (0..4).map(|_| vec![0.5; 8]).collect();
        for _ in 0..20 {
            det.train_step(&seq, 1.0, 0.1).await;
        }
        let score = det.score_window(&seq).await;
        assert!(score > 0.5);
    }

    #[tokio::test]
    async fn save_load_roundtrip() {
        let path = std::env::temp_dir().join("lstm_test_model.json");
        let path_str = path.to_string_lossy().to_string();

        let det = LSTMOnlineDetector::new(8, 16, 4, 5.0);
        let seq: Vec<Vec<f64>> = (0..4).map(|_| vec![0.2; 8]).collect();
        det.train_step(&seq, 0.0, 0.05).await;
        det.save_to_path(&path_str).await.unwrap();

        let loaded = LSTMOnlineDetector::load_from_path(&path_str, 8, 16, 4, 5.0)
            .await
            .unwrap()
            .expect("model should load");
        assert!(loaded.is_trained().await);
        let _ = fs::remove_file(path);
    }
}
