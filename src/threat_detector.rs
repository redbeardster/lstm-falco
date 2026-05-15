#![allow(dead_code)]

use crate::falco_integration::FalcoEvent;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ThreatPrediction {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub predicted_attack_type: String,
    pub probability: f64,
    pub time_window: Duration,
    pub recommended_actions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub severity: f64,
    pub features: Vec<f64>,
    pub context: String,
}

pub struct ThreatDetector {
    historical_events: Vec<SecurityEvent>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatType {
    Bruteforce,
    LateralMovement,
    DataExfiltration,
    ContainerEscape,
    PrivilegeEscalation,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ThreatDetection {
    pub id: String,
    pub threat_type: ThreatType,
    pub severity: crate::automated_response::Severity,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source: DetectorSource,
    pub description: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectorSource {
    Falco,
    GuardDuty,
    EBPF,
    ML,
    Composite,
}

pub struct CompositeDetector {
    detectors: Vec<Box<dyn ThreatDetectorTrait>>,
}

impl CompositeDetector {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    pub fn add_detector(&mut self, detector: Box<dyn ThreatDetectorTrait>) {
        self.detectors.push(detector);
    }

    pub fn detect(&self, event: &SecurityEvent) -> Vec<ThreatDetection> {
        let mut all_detections = Vec::new();
        for detector in &self.detectors {
            all_detections.extend(detector.detect(event));
        }
        all_detections
    }

    pub async fn health_check_all(&self) -> Vec<(String, bool)> {
        self.detectors
            .iter()
            .map(|detector| (detector.name().to_string(), true))
            .collect()
    }
}

// Трейт для детекторов
pub trait ThreatDetectorTrait: Send + Sync {
    fn detect(&self, event: &SecurityEvent) -> Vec<ThreatDetection>;
    fn name(&self) -> &str;
}

impl ThreatDetector {
    pub fn new() -> Self {
        Self {
            historical_events: Vec::with_capacity(10000),
        }
    }

    pub fn add_event(&mut self, event: SecurityEvent) {
        self.historical_events.push(event);
        if self.historical_events.len() > 10000 {
            self.historical_events.remove(0);
        }
    }

    pub fn detect_threats(&mut self) -> Vec<ThreatPrediction> {
        let mut predictions = Vec::new();

        if self.historical_events.len() < 50 {
            return predictions;
        }

        let recent = &self.historical_events[self.historical_events.len().saturating_sub(100)..];

        if self.detect_bruteforce(recent) {
            predictions.push(ThreatPrediction {
                timestamp: chrono::Utc::now(),
                predicted_attack_type: "bruteforce".to_string(),
                probability: 0.85,
                time_window: Duration::from_secs(300),
                recommended_actions: vec![
                    "Enable rate limiting".to_string(),
                    "Block suspicious IPs".to_string(),
                ],
            });
        }

        if self.detect_lateral_movement(recent) {
            predictions.push(ThreatPrediction {
                timestamp: chrono::Utc::now(),
                predicted_attack_type: "lateral_movement".to_string(),
                probability: 0.75,
                time_window: Duration::from_secs(600),
                recommended_actions: vec![
                    "Isolate compromised pods".to_string(),
                    "Enable enhanced monitoring".to_string(),
                ],
            });
        }

        predictions
    }

    fn detect_bruteforce(&self, events: &[SecurityEvent]) -> bool {
        let failed_count: usize = events.iter()
            .filter(|e| e.event_type.contains("failed_login"))
            .count();
        failed_count > 10
    }

    fn detect_lateral_movement(&self, events: &[SecurityEvent]) -> bool {
        let unique_hosts: std::collections::HashSet<_> = events.iter()
            .filter(|e| e.event_type.contains("execve"))
            .map(|e| e.context.clone())
            .collect();
        unique_hosts.len() > 3
    }

    pub fn extract_features(&self, event: &FalcoEvent) -> HashMap<String, f64> {
        let mut features = HashMap::new();

        let container_name = event.output_fields
            .as_ref()
            .and_then(|fields| fields.get("container.name"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        features.insert("has_container".to_string(),
            if container_name != "unknown" { 1.0 } else { 0.0 });

        let process_name = event.output_fields
            .as_ref()
            .and_then(|fields| fields.get("proc.name"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        features.insert("is_suspicious".to_string(),
            if process_name.contains("sh") || process_name.contains("bash") || process_name.contains("nc") {
                1.0
            } else {
                0.0
            });

        let priority_score = match event.priority.as_str() {
            "Emergency" => 5.0,
            "Alert" => 4.0,
            "Critical" => 4.0,
            "Error" => 3.0,
            "Warning" => 2.0,
            _ => 1.0,
        };
        features.insert("priority_score".to_string(), priority_score);

        features
    }

    pub fn from_falco_event(event: &FalcoEvent) -> SecurityEvent {
        let severity = match event.priority.as_str() {
            "Emergency" => 5.0,
            "Alert" | "Critical" => 4.0,
            "Error" => 3.0,
            "Warning" => 2.0,
            _ => 1.0,
        };

        SecurityEvent {
            timestamp: event.time,
            event_type: event.rule.clone(),
            severity,
            features: vec![severity],
            context: event.hostname.clone().unwrap_or_else(|| "unknown".to_string()),
        }
    }
}

impl Default for ThreatDetector {
    fn default() -> Self {
        Self::new()
    }
}
