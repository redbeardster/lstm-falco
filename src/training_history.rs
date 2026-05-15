//! История запусков обучения LSTM (in-memory + JSON на диске).

use crate::time_window_detector::TrainingResult;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tracing::{info, warn};

const MAX_ENTRIES: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingSource {
    ApiTrain,
    AutoFalco,
    TrainReal,
}

impl TrainingSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ApiTrain => "api_train",
            Self::AutoFalco => "auto_falco",
            Self::TrainReal => "train_real",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingRunRecord {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub step_samples: usize,
    pub anomaly_labels: usize,
    pub train_windows: usize,
    pub val_windows: usize,
    pub epochs_run: usize,
    pub loss: f64,
    pub accuracy: f64,
    pub f1_score: f64,
    pub model_saved: bool,
    pub model_path: String,
    pub duration_ms: u64,
    pub bptt: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TrainingHistoryFile {
    next_id: u64,
    runs: Vec<TrainingRunRecord>,
}

pub struct TrainingHistoryStore {
    runs: VecDeque<TrainingRunRecord>,
    next_id: u64,
    output_path: String,
}

impl TrainingHistoryStore {
    pub fn new(output_path: &str) -> Self {
        let mut store = Self {
            runs: VecDeque::with_capacity(MAX_ENTRIES),
            next_id: 1,
            output_path: output_path.to_string(),
        };
        store.load_from_disk();
        store
    }

    pub fn record(
        &mut self,
        source: TrainingSource,
        result: &TrainingResult,
        step_samples: usize,
        anomaly_labels: usize,
        model_path: &str,
        duration: Duration,
    ) -> TrainingRunRecord {
        let record = TrainingRunRecord {
            id: self.next_id,
            timestamp: Utc::now(),
            source: source.as_str().to_string(),
            step_samples,
            anomaly_labels,
            train_windows: result.train_samples,
            val_windows: result.val_samples,
            epochs_run: result.epochs_run,
            loss: result.loss,
            accuracy: result.accuracy,
            f1_score: result.f1_score,
            model_saved: result.model_saved,
            model_path: model_path.to_string(),
            duration_ms: duration.as_millis() as u64,
            bptt: true,
        };
        self.next_id += 1;

        if self.runs.len() >= MAX_ENTRIES {
            self.runs.pop_front();
        }
        self.runs.push_back(record.clone());

        info!(
            "📈 Training run #{} [{}]: steps={}, loss={:.6}, f1={:.3}, saved={}, {}ms",
            record.id,
            record.source,
            step_samples,
            record.loss,
            record.f1_score,
            record.model_saved,
            record.duration_ms
        );

        if let Err(e) = self.persist() {
            warn!("Failed to persist training history: {}", e);
        }

        record
    }

    pub fn latest(&self) -> Option<&TrainingRunRecord> {
        self.runs.back()
    }

    pub fn history(&self) -> Vec<TrainingRunRecord> {
        self.runs.iter().cloned().collect()
    }

    pub fn summary(&self) -> serde_json::Value {
        let latest = self.latest().cloned();
        serde_json::json!({
            "total_runs": self.runs.len(),
            "latest": latest,
            "history": self.history(),
        })
    }

    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = Path::new(&self.output_path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let file = TrainingHistoryFile {
            next_id: self.next_id,
            runs: self.history(),
        };
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_string_pretty(&file)?)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    fn load_from_disk(&mut self) {
        let path = Path::new(&self.output_path);
        if !path.exists() {
            return;
        }
        let Ok(content) = fs::read_to_string(path) else {
            return;
        };
        let Ok(file) = serde_json::from_str::<TrainingHistoryFile>(&content) else {
            warn!("Could not parse training history at {:?}", path);
            return;
        };
        self.next_id = file.next_id.max(1);
        self.runs = file.runs.into_iter().collect();
        while self.runs.len() > MAX_ENTRIES {
            self.runs.pop_front();
        }
        info!("Loaded {} training history entries", self.runs.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_summary() {
        let mut store = TrainingHistoryStore::new("/tmp/lstm_training_history_test.json");
        let result = TrainingResult {
            accuracy: 0.9,
            f1_score: 0.8,
            loss: 0.1,
            train_samples: 10,
            val_samples: 2,
            epochs_run: 5,
            model_saved: true,
        };
        store.record(
            TrainingSource::ApiTrain,
            &result,
            50,
            5,
            "data/lstm_model.json",
            Duration::from_millis(100),
        );
        assert_eq!(store.history().len(), 1);
        assert!(store.latest().unwrap().model_saved);
        let _ = fs::remove_file("/tmp/lstm_training_history_test.json");
    }
}
