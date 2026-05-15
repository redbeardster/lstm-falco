#![allow(dead_code)]

use crate::threat_detector::{
    ThreatDetectorTrait, SecurityEvent, ThreatDetection, ThreatType, DetectorSource
};
use crate::automated_response::Severity;
use uuid::Uuid;

pub struct GuarddDetector {
    findings: Vec<serde_json::Value>,
}

impl GuarddDetector {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    pub fn add_finding(&mut self, finding: serde_json::Value) {
        self.findings.push(finding);
        if self.findings.len() > 1000 {
            self.findings.remove(0);
        }
    }
}

impl ThreatDetectorTrait for GuarddDetector {
    fn detect(&self, event: &SecurityEvent) -> Vec<ThreatDetection> {
        let mut detections = Vec::new();
        
        if event.event_type.contains("unauthorized") {
            detections.push(ThreatDetection {
                id: Uuid::new_v4().to_string(),
                threat_type: ThreatType::PrivilegeEscalation,
                severity: Severity::Critical,
                timestamp: chrono::Utc::now(),
                source: DetectorSource::GuardDuty,
                description: format!("Unauthorized access detected: {}", event.event_type),
                confidence: event.severity,
                evidence: vec![event.context.clone()],
            });
        }
        
        detections
    }

    fn name(&self) -> &str {
        "GuarddDetector"
    }
}

impl Default for GuarddDetector {
    fn default() -> Self {
        Self::new()
    }
}
