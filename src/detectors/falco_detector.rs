#![allow(dead_code)]

use crate::threat_detector::{
    ThreatDetectorTrait, SecurityEvent, ThreatDetection, ThreatType, DetectorSource
};
use crate::automated_response::Severity;
use crate::falco_integration::FalcoEvent;
use uuid::Uuid;

pub struct FalcoDetector {
    events: Vec<FalcoEvent>,
}

impl FalcoDetector {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
        }
    }

    pub fn add_event(&mut self, event: FalcoEvent) {
        self.events.push(event);
        if self.events.len() > 1000 {
            self.events.remove(0);
        }
    }
}

impl ThreatDetectorTrait for FalcoDetector {
    fn detect(&self, event: &SecurityEvent) -> Vec<ThreatDetection> {
        let mut detections = Vec::new();
        
        if event.event_type.contains("bruteforce") {
            detections.push(ThreatDetection {
                id: Uuid::new_v4().to_string(),
                threat_type: ThreatType::Bruteforce,
                severity: Severity::High,
                timestamp: chrono::Utc::now(),
                source: DetectorSource::Falco,
                description: format!("Bruteforce detected: {}", event.event_type),
                confidence: event.severity,
                evidence: vec![event.context.clone()],
            });
        }
        
        if event.event_type.contains("lateral") {
            detections.push(ThreatDetection {
                id: Uuid::new_v4().to_string(),
                threat_type: ThreatType::LateralMovement,
                severity: Severity::Critical,
                timestamp: chrono::Utc::now(),
                source: DetectorSource::Falco,
                description: format!("Lateral movement detected: {}", event.event_type),
                confidence: event.severity,
                evidence: vec![event.context.clone()],
            });
        }
        
        detections
    }

    fn name(&self) -> &str {
        "FalcoDetector"
    }
}

impl Default for FalcoDetector {
    fn default() -> Self {
        Self::new()
    }
}
