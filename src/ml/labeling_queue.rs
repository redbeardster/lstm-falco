//! Analyst labeling queue and persisted ground-truth samples.

use crate::falco_integration::FalcoEvent;
use crate::ml::event_labeling::{label_event, LabelSource, LabelStore};
use crate::ml::falco_timestep::falco_event_to_lstm_timestep;
use crate::ml::training_data::LoadedTrainingData;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlabeledAnomaly {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub timestep: Vec<f64>,
    pub predicted_score: f64,
    pub rule: String,
    pub priority: String,
    pub output: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledAnomalyRecord {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub labeled_at: DateTime<Utc>,
    pub timestep: Vec<f64>,
    pub label: f64,
    pub predicted_score: f64,
    pub rule: String,
    pub priority: String,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct ActiveLearningConfig {
    pub enabled: bool,
    pub low_confidence: f64,
    pub high_confidence: f64,
}

impl ActiveLearningConfig {
    pub fn classify(&self, score: f64) -> ActiveLearningBand {
        if !self.enabled {
            return ActiveLearningBand::UseProxy;
        }
        if score >= self.high_confidence {
            ActiveLearningBand::ConfidentAttack
        } else if score <= self.low_confidence {
            ActiveLearningBand::ConfidentNormal
        } else {
            ActiveLearningBand::Uncertain
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveLearningBand {
    ConfidentAttack,
    ConfidentNormal,
    Uncertain,
    UseProxy,
}

#[derive(Debug, Clone)]
pub struct TrainingLabelDecision {
    pub label: f64,
    pub source: LabelSource,
    pub enqueue_for_analyst: bool,
    pub skip_collector: bool,
}

pub fn resolve_training_label(
    score: f64,
    event: &FalcoEvent,
    store: &LabelStore,
    active_learning: &ActiveLearningConfig,
    queue_uncertain: bool,
    queue_all_alerts: bool,
    alert_threshold: f64,
) -> TrainingLabelDecision {
    let manual = label_event(event, store);
    if manual.source == LabelSource::Manual {
        return TrainingLabelDecision {
            label: manual.label,
            source: LabelSource::Manual,
            enqueue_for_analyst: false,
            skip_collector: false,
        };
    }

    match active_learning.classify(score) {
        ActiveLearningBand::ConfidentAttack => TrainingLabelDecision {
            label: 1.0,
            source: LabelSource::ActiveLearning,
            enqueue_for_analyst: false,
            skip_collector: false,
        },
        ActiveLearningBand::ConfidentNormal => TrainingLabelDecision {
            label: 0.0,
            source: LabelSource::ActiveLearning,
            enqueue_for_analyst: false,
            skip_collector: false,
        },
        ActiveLearningBand::Uncertain => TrainingLabelDecision {
            label: manual.label,
            source: manual.source,
            enqueue_for_analyst: queue_uncertain,
            skip_collector: queue_uncertain,
        },
        ActiveLearningBand::UseProxy => {
            let enqueue = queue_all_alerts && score > alert_threshold;
            TrainingLabelDecision {
                label: manual.label,
                source: manual.source,
                enqueue_for_analyst: enqueue,
                skip_collector: false,
            }
        }
    }
}

pub struct LabelingQueue {
    pending: Mutex<Vec<UnlabeledAnomaly>>,
    labeled_path: PathBuf,
    max_pending: usize,
}

impl LabelingQueue {
    pub fn new(labeled_path: PathBuf, max_pending: usize) -> Self {
        Self {
            pending: Mutex::new(Vec::new()),
            labeled_path,
            max_pending,
        }
    }

    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }

    pub async fn list_pending(&self) -> Vec<UnlabeledAnomaly> {
        self.pending.lock().await.clone()
    }

    pub async fn enqueue(&self, event: &FalcoEvent, score: f64, reason: &str) -> Option<String> {
        let mut pending = self.pending.lock().await;
        if pending.len() >= self.max_pending {
            warn!(
                "Labeling queue full ({}), dropping oldest entry",
                self.max_pending
            );
            pending.remove(0);
        }

        let id = Uuid::new_v4().to_string();
        let entry = UnlabeledAnomaly {
            id: id.clone(),
            timestamp: event.time,
            timestep: falco_event_to_lstm_timestep(event),
            predicted_score: score,
            rule: event.rule.clone(),
            priority: event.priority.clone(),
            output: event.output.clone(),
            reason: reason.to_string(),
        };
        pending.push(entry);
        info!(
            "Queued anomaly {} for analyst (score={:.3}, rule={})",
            id, score, event.rule
        );
        Some(id)
    }

    pub async fn submit_label(
        &self,
        id: &str,
        is_real_attack: bool,
    ) -> Result<LabeledAnomalyRecord> {
        let mut pending = self.pending.lock().await;
        let pos = pending
            .iter()
            .position(|a| a.id == id)
            .ok_or_else(|| anyhow::anyhow!("anomaly id not found: {id}"))?;
        let anomaly = pending.remove(pos);
        drop(pending);

        let record = LabeledAnomalyRecord {
            id: anomaly.id.clone(),
            timestamp: anomaly.timestamp,
            labeled_at: Utc::now(),
            timestep: anomaly.timestep,
            label: if is_real_attack { 1.0 } else { 0.0 },
            predicted_score: anomaly.predicted_score,
            rule: anomaly.rule,
            priority: anomaly.priority,
            source: "analyst".to_string(),
        };

        self.append_labeled_record(&record).await?;
        info!(
            "Analyst labeled {} as {} (predicted {:.3})",
            record.id,
            if is_real_attack { "attack" } else { "false_positive" },
            record.predicted_score
        );
        Ok(record)
    }

    async fn append_labeled_record(&self, record: &LabeledAnomalyRecord) -> Result<()> {
        let mut records = self.load_labeled_records().await?;
        records.push(record.clone());
        self.write_labeled_records(&records).await
    }

    async fn load_labeled_records(&self) -> Result<Vec<LabeledAnomalyRecord>> {
        if !self.labeled_path.exists() {
            return Ok(Vec::new());
        }
        let content = tokio::fs::read_to_string(&self.labeled_path)
            .await
            .with_context(|| format!("read {:?}", self.labeled_path))?;
        if content.trim().is_empty() {
            return Ok(Vec::new());
        }
        let records: Vec<LabeledAnomalyRecord> = serde_json::from_str(&content)
            .with_context(|| format!("parse {:?}", self.labeled_path))?;
        Ok(records)
    }

    async fn write_labeled_records(&self, records: &[LabeledAnomalyRecord]) -> Result<()> {
        if let Some(parent) = self.labeled_path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }
        let tmp = self.labeled_path.with_extension("json.tmp");
        let json = serde_json::to_string_pretty(records)?;
        tokio::fs::write(&tmp, json).await?;
        tokio::fs::rename(&tmp, &self.labeled_path).await?;
        Ok(())
    }

    pub async fn list_labeled(&self) -> Result<Vec<LabeledAnomalyRecord>> {
        self.load_labeled_records().await
    }

    pub fn labeled_path(&self) -> &Path {
        &self.labeled_path
    }
}

pub type SharedLabelingQueue = Arc<LabelingQueue>;

pub fn shared_labeling_queue(path: PathBuf, max_pending: usize) -> SharedLabelingQueue {
    Arc::new(LabelingQueue::new(path, max_pending))
}

pub fn records_to_training_data(records: &[LabeledAnomalyRecord]) -> LoadedTrainingData {
    LoadedTrainingData {
        timesteps: records.iter().map(|r| r.timestep.clone()).collect(),
        labels: records.iter().map(|r| r.label).collect(),
    }
}

pub async fn load_labeled_anomalies_training(
    queue: &LabelingQueue,
) -> Result<LoadedTrainingData> {
    let records = queue.load_labeled_records().await?;
    Ok(records_to_training_data(&records))
}
