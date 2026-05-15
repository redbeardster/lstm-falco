// src/training_metrics.rs

use serde::{Serialize, Deserialize};
use std::collections::VecDeque;
use std::fs;
use chrono::{DateTime, Utc};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingMetrics {
    pub timestamp: DateTime<Utc>,
    pub total_samples: usize,
    pub normal_samples: usize,
    pub anomaly_samples: usize,
    pub training_loss: f64,
    pub validation_accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
}

pub struct TrainingMetricsCollector {
    history: VecDeque<TrainingMetrics>,
    current_metrics: Option<TrainingMetrics>,
    output_path: String,
}

impl TrainingMetricsCollector {
    pub fn new(output_path: &str) -> Self {
        Self {
            history: VecDeque::with_capacity(100),
            current_metrics: None,
            output_path: output_path.to_string(),
        }
    }

    pub fn record_training(&mut self, metrics: TrainingMetrics) {
        let normal_samples = metrics.normal_samples;
        let anomaly_samples = metrics.anomaly_samples;
        let loss = metrics.training_loss;
        let accuracy = metrics.validation_accuracy;
        let precision = metrics.precision;
        let recall = metrics.recall;
        let f1 = metrics.f1_score;
        let fpr = metrics.false_positive_rate;
        let fnr = metrics.false_negative_rate;

        self.history.push_back(metrics.clone());
        self.current_metrics = Some(metrics);

        let _ = self.save_to_file();

        info!("📊 Training metrics:");
        info!("   Total samples: {}", self.current_metrics.as_ref().unwrap().total_samples);
        info!("   Normal: {}, Anomaly: {}", normal_samples, anomaly_samples);
        info!("   Loss: {:.4}, Accuracy: {:.2}%", loss, accuracy * 100.0);
        info!("   Precision: {:.2}%, Recall: {:.2}%, F1: {:.2}%",
              precision * 100.0, recall * 100.0, f1 * 100.0);
        info!("   False Positive Rate: {:.2}%, False Negative Rate: {:.2}%",
              fpr * 100.0, fnr * 100.0);
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
        let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 0.0 };
        let recall = if tp + false_neg > 0 { tp as f64 / (tp + false_neg) as f64 } else { 0.0 };
        let f1 = if precision + recall > 0.0 { 2.0 * precision * recall / (precision + recall) } else { 0.0 };

        TrainingMetrics {
            timestamp: Utc::now(),
            total_samples: (tp + tn + fp + false_neg) as usize,
            normal_samples: (tn + fp) as usize,
            anomaly_samples: (tp + false_neg) as usize,
            training_loss: 0.0,
            validation_accuracy: (tp + tn) as f64 / total,
            precision,
            recall,
            f1_score: f1,
            false_positive_rate: if fp + tn > 0 { fp as f64 / (fp + tn) as f64 } else { 0.0 },
            false_negative_rate: if false_neg + tp > 0 { false_neg as f64 / (false_neg + tp) as f64 } else { 0.0 },
        }
    }

    fn save_to_file(&self) -> Result<(), Box<dyn std::error::Error>> {
        let data = self.get_history();
        let json = serde_json::to_string_pretty(&data)?;
        fs::write(&self.output_path, json)?;
        Ok(())
    }

    pub fn get_history(&self) -> Vec<TrainingMetrics> {
        self.history.iter().cloned().collect()
    }

    pub fn get_latest(&self) -> Option<TrainingMetrics> {
        self.current_metrics.clone()
    }

    pub fn get_summary(&self) -> serde_json::Value {
        let latest = self.get_latest();
        let total_trainings = self.history.len();

        serde_json::json!({
            "total_trainings": total_trainings,
            "latest": latest,
            "history": self.history.iter().map(|m| serde_json::json!({
                "timestamp": m.timestamp,
                "accuracy": m.validation_accuracy,
                "f1_score": m.f1_score
            })).collect::<Vec<_>>()
        })
    }
}
