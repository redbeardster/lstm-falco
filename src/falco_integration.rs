// src/falco_integration.rs

use crate::ml::data_collector::DataCollector;
use crate::ml::event_labeling::{label_event, SharedLabelStore};
use crate::ml::realtime_lstm::{RealtimeLSTM, TrainingResult};
use crate::ml::training_history::{TrainingHistoryStore, TrainingSource};
use anyhow::Result;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tracing::{error, info, warn};

use crate::automated_response::AutomatedResponseEngine;

#[derive(Debug, Clone)]
pub struct FalcoMlConfig {
    pub enabled: bool,
    pub anomaly_threshold: f64,
    pub auto_train_samples: usize,
    pub min_train_samples: usize,
}

pub struct FalcoEventHandler {
    event_sender: UnboundedSender<FalcoEvent>,
    response_engine: Arc<AutomatedResponseEngine>,
    ml_config: FalcoMlConfig,
    realtime_lstm: Arc<RealtimeLSTM>,
    data_collector: Arc<DataCollector>,
    training: Arc<AtomicBool>,
    window_size: usize,
    training_history: Arc<Mutex<TrainingHistoryStore>>,
    model_path: String,
    label_store: SharedLabelStore,
}

impl FalcoEventHandler {
    pub fn new(
        event_sender: UnboundedSender<FalcoEvent>,
        response_engine: Arc<AutomatedResponseEngine>,
        ml_config: FalcoMlConfig,
        realtime_lstm: Arc<RealtimeLSTM>,
        data_collector: Arc<DataCollector>,
        window_size: usize,
        training_history: Arc<Mutex<TrainingHistoryStore>>,
        model_path: String,
        label_store: SharedLabelStore,
    ) -> Self {
        Self {
            event_sender,
            response_engine,
            ml_config,
            realtime_lstm,
            data_collector,
            training: Arc::new(AtomicBool::new(false)),
            window_size,
            training_history,
            model_path,
            label_store,
        }
    }

    pub async fn init(&self) -> Result<()> {
        if self.ml_config.enabled {
            let ready = self.realtime_lstm.is_ready().await;
            info!(
                "LSTM detector: threshold={:.2}, trained={}, auto_train_at={}",
                self.ml_config.anomaly_threshold, ready, self.ml_config.auto_train_samples
            );
        }
        Ok(())
    }

    async fn trigger(&self, event: FalcoEvent) {
        self.response_engine.handle_falco_event(&event).await;
    }

    pub async fn process(&self, event: &FalcoEvent) {
        if !self.ml_config.enabled {
            return;
        }

        let store = self.label_store.read().await;
        let labeled = label_event(event, &store);
        drop(store);
        self.data_collector
            .add_event_labeled(event.clone(), labeled.label, Some(labeled.source))
            .await;

        if self.should_auto_train().await {
            self.train_from_collected_data().await;
        }

        let Some(score) = self.realtime_lstm.process_event(event.clone()).await else {
            return;
        };

        if score > self.ml_config.anomaly_threshold {
            warn!(
                "🚨 LSTM ANOMALY! Score: {:.3}, Rule: {}, Priority: {}",
                score, event.rule, event.priority
            );
            self.trigger(event.clone()).await;
        }
    }

    async fn should_auto_train(&self) -> bool {
        let len = self.data_collector.get_buffer_len().await;
        len >= self.ml_config.auto_train_samples
    }

    async fn train_from_collected_data(&self) -> Option<TrainingResult> {
        if self
            .training
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }

        let (features, labels) = self.data_collector.get_training_data().await;
        if features.len() < self.ml_config.min_train_samples {
            self.training.store(false, Ordering::Relaxed);
            return None;
        }

        let anomaly_count = labels.iter().filter(|&&l| l > 0.5).count();
        info!(
            "Auto-training LSTM on {} samples ({} anomalies)",
            features.len(),
            anomaly_count
        );

        let started = Instant::now();
        let result = self
            .realtime_lstm
            .train_from_data(&features, &labels)
            .await;

        self.training_history.lock().unwrap().record(
            TrainingSource::AutoFalco,
            &result,
            features.len(),
            anomaly_count,
            &self.model_path,
            started.elapsed(),
        );

        if result.model_saved {
            self.data_collector
                .retain_tail(self.window_size * 2)
                .await;
            if let Err(e) = self.data_collector.save_to_json().await {
                warn!("Failed to persist collector after auto-train: {e:#}");
            }
        }

        info!(
            "LSTM auto-train done: accuracy={:.2}%, f1={:.3}, saved={}",
            result.accuracy * 100.0,
            result.f1_score,
            result.model_saved
        );

        self.training.store(false, Ordering::Relaxed);
        Some(result)
    }

    pub async fn handle_event(&self, event: FalcoEvent) -> Response {
        if let Err(e) = self.event_sender.send(event.clone()) {
            error!("Failed to send event: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to process").into_response();
        }

        self.process(&event).await;
        (StatusCode::OK, "Event processed").into_response()
    }

    pub async fn get_ml_status(&self) -> serde_json::Value {
        let lstm_stats = self.realtime_lstm.get_stats().await;
        let buffer_len = self.data_collector.get_buffer_len().await;
        let anomalies = self.data_collector.anomaly_count().await;
        let training_summary = self.training_history.lock().unwrap().summary();
        let label_sources = self.data_collector.label_stats_snapshot().await;

        serde_json::json!({
            "enabled": self.ml_config.enabled,
            "threshold": self.ml_config.anomaly_threshold,
            "training_samples_collected": buffer_len,
            "anomaly_labels": anomalies,
            "auto_train_samples": self.ml_config.auto_train_samples,
            "min_train_samples": self.ml_config.min_train_samples,
            "training_in_progress": self.training.load(Ordering::Relaxed),
            "label_sources": label_sources.to_json(),
            "lstm": lstm_stats,
            "training_history": training_summary,
        })
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalcoEvent {
    pub time: chrono::DateTime<chrono::Utc>,
    pub rule: String,
    pub priority: String,
    pub output: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub output_fields: Option<serde_json::Value>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub container_id: Option<String>,
    #[serde(default)]
    pub process_pid: Option<u32>,
    #[serde(default)]
    pub syscall: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalcoRule {
    pub name: String,
    pub condition: String,
    pub output: String,
    pub priority: String,
    pub tags: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalcoRuleYaml {
    pub rule: String,
    pub desc: String,
    pub condition: String,
    pub output: String,
    pub priority: String,
    pub tags: Vec<String>,
}

impl FalcoEvent {
    pub fn validate(&self) -> Result<()> {
        if self.rule.is_empty() {
            anyhow::bail!("Missing required field: 'rule'");
        }
        if self.priority.is_empty() {
            anyhow::bail!("Missing required field: 'priority'");
        }
        if self.output.is_empty() {
            anyhow::bail!("Missing required field: 'output'");
        }
        if self.rule.len() > 256 {
            anyhow::bail!("Field 'rule' exceeds maximum length (256)");
        }
        if self.output.len() > 4096 {
            anyhow::bail!("Field 'output' exceeds maximum length (4096)");
        }
        Ok(())
    }
}

pub fn falco_event_to_lstm_timestep(event: &FalcoEvent) -> Vec<f64> {
    crate::ml::falco_timestep::falco_event_to_lstm_timestep(event)
}

pub async fn handle_falco_event_with_ml(
    body: String,
    handler: Arc<FalcoEventHandler>,
) -> Response {
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty request body").into_response();
    }

    if body.len() > 1024 * 1024 {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Body too large").into_response();
    }

    let event: FalcoEvent = match serde_json::from_str(&body) {
        Ok(e) => e,
        Err(e) => {
            error!("Invalid JSON: {}", e);
            return (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)).into_response();
        }
    };

    if let Err(e) = event.validate() {
        return (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response();
    }

    handler.handle_event(event).await
}

pub struct FalcoIntegration {
    event_sender: UnboundedSender<FalcoEvent>,
    rules: Arc<RwLock<Vec<FalcoRule>>>,
    ml_handler: Arc<FalcoEventHandler>,
}

impl FalcoIntegration {
    pub async fn new(
        response_engine: Arc<AutomatedResponseEngine>,
        realtime_lstm: Arc<RealtimeLSTM>,
        data_collector: Arc<DataCollector>,
        training_history: Arc<Mutex<TrainingHistoryStore>>,
        ml_config: FalcoMlConfig,
        webhook_bind: String,
        window_size: usize,
        model_path: String,
        label_store: SharedLabelStore,
    ) -> Result<Self> {
        let (event_sender, mut event_receiver) = unbounded_channel::<FalcoEvent>();
        let response_clone = response_engine.clone();

        tokio::spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                match event.priority.as_str() {
                    "Critical" | "Alert" | "Emergency" => {
                        error!("🚨 FALCO ALERT: {}", event.rule);
                        response_clone.handle_falco_event(&event).await;
                    }
                    _ => {
                        tracing::debug!("Falco: {}", event.rule);
                    }
                }
            }
        });

        let ml_handler = Arc::new(FalcoEventHandler::new(
            event_sender.clone(),
            response_engine,
            ml_config,
            realtime_lstm,
            data_collector,
            window_size,
            training_history,
            model_path,
            label_store,
        ));

        ml_handler.init().await?;

        let integration = Self {
            event_sender,
            rules: Arc::new(RwLock::new(Vec::new())),
            ml_handler: ml_handler.clone(),
        };

        integration.load_falco_rules().await?;
        integration
            .start_webhook_server(ml_handler, webhook_bind)
            .await?;

        Ok(integration)
    }

    async fn start_webhook_server(
        &self,
        ml_handler: Arc<FalcoEventHandler>,
        bind: String,
    ) -> Result<()> {
        let ml_handler_clone = ml_handler.clone();

        tokio::spawn(async move {
            let app = axum::Router::new()
                .route("/falco-events", axum::routing::post(move |body: String| {
                    let handler = ml_handler_clone.clone();
                    async move { handle_falco_event_with_ml(body, handler).await }
                }))
                .route("/ml/status", axum::routing::get(move || {
                    let handler = ml_handler.clone();
                    async move { (StatusCode::OK, axum::Json(handler.get_ml_status().await)) }
                }));

            let listener = match tokio::net::TcpListener::bind(&bind).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind Falco webhook on {}: {}", bind, e);
                    return;
                }
            };
            info!("Falco webhook listening on {}", bind);

            if let Err(e) = axum::serve(listener, app).await {
                error!("Falco webhook error: {}", e);
            }
        });

        Ok(())
    }

    async fn load_falco_rules(&self) -> Result<()> {
        let rules_path = Path::new("falco/rules/seccomp_rules.yaml");
        if !rules_path.exists() {
            info!("No Falco rules file at {:?}", rules_path);
            return Ok(());
        }

        let content = tokio::fs::read_to_string(rules_path).await?;
        let yaml_rules: Vec<FalcoRuleYaml> = serde_yaml::from_str(&content)?;

        let mut rules = self.rules.write().await;
        for yaml_rule in yaml_rules {
            rules.push(FalcoRule {
                name: yaml_rule.rule,
                condition: yaml_rule.condition,
                output: yaml_rule.output,
                priority: yaml_rule.priority,
                tags: yaml_rule.tags,
                enabled: true,
            });
        }

        info!("Loaded {} Falco rules", rules.len());
        Ok(())
    }

    pub async fn get_rules(&self) -> Vec<FalcoRule> {
        self.rules.read().await.clone()
    }

    pub async fn get_rule(&self, name: &str) -> Option<FalcoRule> {
        let rules = self.rules.read().await;
        rules.iter().find(|r| r.name == name).cloned()
    }

    pub async fn add_rule(&self, rule: FalcoRule) -> Result<()> {
        self.rules.write().await.push(rule);
        Ok(())
    }

    pub async fn update_rule(
        &self,
        name: &str,
        enabled: bool,
        priority: Option<String>,
    ) -> Result<()> {
        let mut rules = self.rules.write().await;
        if let Some(rule) = rules.iter_mut().find(|r| r.name == name) {
            rule.enabled = enabled;
            if let Some(p) = priority {
                rule.priority = p;
            }
            Ok(())
        } else {
            anyhow::bail!("Rule not found: {}", name)
        }
    }

    pub async fn delete_rule(&self, name: &str) -> Result<()> {
        let mut rules = self.rules.write().await;
        let before = rules.len();
        rules.retain(|r| r.name != name);
        if rules.len() < before {
            Ok(())
        } else {
            anyhow::bail!("Rule not found: {}", name)
        }
    }
}
