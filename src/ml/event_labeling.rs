//! Falco event labeling for LSTM training (proxy labels — not ground-truth incidents).

use crate::falco_integration::FalcoEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelSource {
    Manual,
    Rule,
    Priority,
}

#[derive(Debug, Clone, Serialize)]
pub struct LabeledSample {
    pub label: f64,
    pub source: LabelSource,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct LabelSourceStats {
    pub manual_positive: usize,
    pub manual_negative: usize,
    pub rule_positive: usize,
    pub rule_negative: usize,
    pub priority_positive: usize,
    pub priority_negative: usize,
}

impl LabelSourceStats {
    pub fn record(&mut self, source: LabelSource, label: f64) {
        let positive = label > 0.5;
        match (source, positive) {
            (LabelSource::Manual, true) => self.manual_positive += 1,
            (LabelSource::Manual, false) => self.manual_negative += 1,
            (LabelSource::Rule, true) => self.rule_positive += 1,
            (LabelSource::Rule, false) => self.rule_negative += 1,
            (LabelSource::Priority, true) => self.priority_positive += 1,
            (LabelSource::Priority, false) => self.priority_negative += 1,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "manual": { "positive": self.manual_positive, "negative": self.manual_negative },
            "rule": { "positive": self.rule_positive, "negative": self.rule_negative },
            "priority": { "positive": self.priority_positive, "negative": self.priority_negative },
            "note": "priority labels are Falco severity proxies, not confirmed incidents"
        })
    }
}

/// Optional manual overrides loaded from `ML_LABELS_PATH` (JSON array or JSONL).
pub struct LabelStore {
    by_rule: HashMap<String, f64>,
    path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManualLabelEntry {
    pub rule: String,
    pub label: f64,
}

impl LabelStore {
    pub fn load(path: &Path) -> Self {
        let mut store = Self {
            by_rule: HashMap::new(),
            path: path.to_path_buf(),
        };
        if !path.exists() {
            return store;
        }
        match fs::read_to_string(path) {
            Ok(content) => store.parse_content(&content),
            Err(e) => warn!("Failed to read labels file {:?}: {e}", path),
        }
        store
    }

    fn parse_content(&mut self, content: &str) {
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return;
        }
        if let Ok(entries) = serde_json::from_str::<Vec<ManualLabelEntry>>(trimmed) {
            for e in entries {
                self.by_rule.insert(e.rule.to_lowercase(), e.label.clamp(0.0, 1.0));
            }
            return;
        }
        for line in trimmed.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(e) = serde_json::from_str::<ManualLabelEntry>(line) {
                self.by_rule
                    .insert(e.rule.to_lowercase(), e.label.clamp(0.0, 1.0));
            }
        }
    }

    pub fn reload(&mut self) {
        self.by_rule.clear();
        if self.path.exists() {
            if let Ok(content) = fs::read_to_string(&self.path) {
                self.parse_content(&content);
            }
        }
    }

    pub fn manual_label(&self, rule: &str) -> Option<f64> {
        self.by_rule.get(&rule.to_lowercase()).copied()
    }

    pub fn upsert_rule(&mut self, rule: &str, label: f64) {
        self.by_rule
            .insert(rule.to_lowercase(), label.clamp(0.0, 1.0));
    }

    pub fn list_rules(&self) -> Vec<ManualLabelEntry> {
        let mut entries: Vec<_> = self
            .by_rule
            .iter()
            .map(|(rule, &label)| ManualLabelEntry {
                rule: rule.clone(),
                label,
            })
            .collect();
        entries.sort_by(|a, b| a.rule.cmp(&b.rule));
        entries
    }

    pub fn persist(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let entries = self.list_rules();
        let json = serde_json::to_string_pretty(&entries)?;
        fs::write(&self.path, json)?;
        Ok(())
    }
}

fn rule_matches(rule: &str, patterns: &[&str]) -> bool {
    let lower = rule.to_lowercase();
    patterns.iter().any(|p| lower.contains(p))
}

const NOISE_RULE_PATTERNS: &[&str] = &[
    "info",
    "health",
    "heartbeat",
    "container created",
    "k8s audit",
];

const ATTACK_RULE_PATTERNS: &[&str] = &[
    "shell",
    "reverse",
    "miner",
    "cryptominer",
    "exfil",
    "privilege",
    "escalat",
    "bruteforce",
    "lateral",
    "malware",
    "trojan",
    "rootkit",
    "unauthorized",
    "suspicious",
];

fn priority_label(priority: &str) -> f64 {
    if matches!(
        priority,
        "Critical" | "Alert" | "Emergency" | "Error"
    ) {
        1.0
    } else {
        0.0
    }
}

fn rule_heuristic_label(event: &FalcoEvent) -> Option<f64> {
    if rule_matches(&event.rule, NOISE_RULE_PATTERNS) {
        return Some(0.0);
    }
    if rule_matches(&event.rule, ATTACK_RULE_PATTERNS) {
        return Some(1.0);
    }
    if let Some(tags) = &event.tags {
        let tag_lower: Vec<String> = tags.iter().map(|t| t.to_lowercase()).collect();
        if tag_lower.iter().any(|t| t == "attack" || t == "mitre") {
            return Some(1.0);
        }
        if tag_lower.iter().any(|t| t == "normal" || t == "benign") {
            return Some(0.0);
        }
    }
    None
}

pub fn label_event(event: &FalcoEvent, store: &LabelStore) -> LabeledSample {
    if let Some(label) = store.manual_label(&event.rule) {
        return LabeledSample {
            label,
            source: LabelSource::Manual,
        };
    }
    if let Some(label) = rule_heuristic_label(event) {
        return LabeledSample {
            label,
            source: LabelSource::Rule,
        };
    }
    LabeledSample {
        label: priority_label(&event.priority),
        source: LabelSource::Priority,
    }
}

pub type SharedLabelStore = Arc<RwLock<LabelStore>>;

pub fn shared_label_store(path: PathBuf) -> SharedLabelStore {
    Arc::new(RwLock::new(LabelStore::load(&path)))
}
