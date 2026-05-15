//! Конфигурация ML/LSTM из переменных окружения.

use anyhow::{Context, Result};
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct MlConfig {
    pub enabled: bool,
    pub anomaly_threshold: f64,
    pub model_path: PathBuf,
    pub training_data_path: PathBuf,
    pub labels_path: PathBuf,
    pub collector_path: PathBuf,
    pub bootstrap_train: bool,
    pub force_retrain: bool,
    pub window_size: usize,
    pub step_size: usize,
    pub hidden_size: usize,
    pub learning_rate: f64,
    pub grad_clip: f64,
    pub epochs: usize,
    pub min_train_samples: usize,
    pub auto_train_samples: usize,
    pub max_collector_samples: usize,
    pub falco_webhook_bind: String,
    pub api_bind: String,
}

impl MlConfig {
    pub fn from_env() -> Result<Self> {
        let cfg = Self {
            enabled: env_bool("ML_ENABLED", true),
            anomaly_threshold: env_f64("ML_ANOMALY_THRESHOLD", 0.7)?,
            model_path: PathBuf::from(env_str("ML_MODEL_PATH", "data/lstm_model.json")),
            training_data_path: PathBuf::from(env_str(
                "ML_TRAINING_DATA_PATH",
                "data/training_data.json",
            )),
            labels_path: PathBuf::from(env_str("ML_LABELS_PATH", "data/labels.json")),
            collector_path: PathBuf::from(env_str(
                "ML_COLLECTOR_PATH",
                "data/lstm_training.json",
            )),
            window_size: env_usize("ML_WINDOW_SIZE", 20)?,
            step_size: env_usize("ML_STEP_SIZE", 10)?,
            hidden_size: env_usize("ML_HIDDEN_SIZE", 32)?,
            learning_rate: env_f64("ML_LEARNING_RATE", 0.05)?,
            grad_clip: env_f64("ML_GRAD_CLIP", 5.0)?,
            epochs: env_usize("ML_EPOCHS", 30)?,
            min_train_samples: env_usize("ML_MIN_TRAIN_SAMPLES", 100)?,
            auto_train_samples: env_usize("ML_AUTO_TRAIN_SAMPLES", 500)?,
            max_collector_samples: env_usize("ML_MAX_COLLECTOR_SAMPLES", 10_000)?,
            bootstrap_train: env_bool("ML_BOOTSTRAP_TRAIN", false),
            force_retrain: env_bool("ML_FORCE_RETRAIN", false),
            falco_webhook_bind: env_str("FALCO_WEBHOOK_BIND", "0.0.0.0:8080"),
            api_bind: env_str("API_BIND", "0.0.0.0:3000"),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn ensure_data_dirs(&self) -> Result<()> {
        for path in [
            &self.model_path,
            &self.training_data_path,
            &self.labels_path,
            &self.collector_path,
        ] {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("create data dir {:?}", parent))?;
                }
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.anomaly_threshold > 0.0 && self.anomaly_threshold < 1.0,
            "ML_ANOMALY_THRESHOLD must be in (0, 1)"
        );
        anyhow::ensure!(self.window_size >= 4, "ML_WINDOW_SIZE must be >= 4");
        anyhow::ensure!(
            self.step_size > 0 && self.step_size <= self.window_size,
            "ML_STEP_SIZE must be in 1..=window_size"
        );
        anyhow::ensure!(self.hidden_size >= 8, "ML_HIDDEN_SIZE must be >= 8");
        anyhow::ensure!(self.grad_clip > 0.0, "ML_GRAD_CLIP must be > 0");
        anyhow::ensure!(
            self.min_train_samples >= self.window_size,
            "ML_MIN_TRAIN_SAMPLES must be >= window_size"
        );
        anyhow::ensure!(
            self.auto_train_samples >= self.min_train_samples,
            "ML_AUTO_TRAIN_SAMPLES must be >= ML_MIN_TRAIN_SAMPLES"
        );
        Ok(())
    }

    pub fn to_lstm_config(&self) -> crate::realtime_lstm::RealtimeLSTMConfig {
        crate::realtime_lstm::RealtimeLSTMConfig {
            window_size: self.window_size,
            step_size: self.step_size,
            threshold: self.anomaly_threshold,
            model_path: self.model_path.to_string_lossy().into_owned(),
            hidden_size: self.hidden_size,
            learning_rate: self.learning_rate,
            epochs: self.epochs,
            min_train_samples: self.min_train_samples,
            grad_clip: self.grad_clip,
        }
    }

    pub fn to_falco_ml_config(&self) -> crate::falco_integration::FalcoMlConfig {
        crate::falco_integration::FalcoMlConfig {
            enabled: self.enabled,
            anomaly_threshold: self.anomaly_threshold,
            auto_train_samples: self.auto_train_samples,
            min_train_samples: self.min_train_samples,
        }
    }
}

fn env_str(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

fn env_usize(key: &str, default: usize) -> Result<usize> {
    match env::var(key) {
        Ok(v) => v
            .parse()
            .with_context(|| format!("invalid usize for {key}")),
        Err(_) => Ok(default),
    }
}

fn env_f64(key: &str, default: f64) -> Result<f64> {
    match env::var(key) {
        Ok(v) => v.parse().with_context(|| format!("invalid f64 for {key}")),
        Err(_) => Ok(default),
    }
}
