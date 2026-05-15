use crate::threat_detector::{
    ThreatDetectorTrait, SecurityEvent, ThreatDetection, ThreatType, DetectorSource
};
use crate::automated_response::Severity;
use uuid::Uuid;
use std::collections::HashMap;

pub struct MLDetector {
    model_weights: HashMap<String, f64>,
    threshold: f64,
}

impl MLDetector {
    pub fn new() -> Self {
        let mut weights = HashMap::new();
        weights.insert("priority".to_string(), 0.4);
        weights.insert("frequency".to_string(), 0.3);
        weights.insert("severity".to_string(), 0.3);
        
        Self {
            model_weights: weights,
            threshold: 0.7,
        }
    }
    
    fn calculate_risk_score(&self, event: &SecurityEvent) -> f64 {
        let priority_score = match event.severity as i32 {
            s if s >= 4 => 1.0,
            s if s >= 3 => 0.75,
            s if s >= 2 => 0.5,
            _ => 0.25,
        };
        
        priority_score * self.model_weights.get("priority").unwrap_or(&0.4)
            + 0.3 * event.severity / 5.0
    }
}

impl ThreatDetectorTrait for MLDetector {
    fn detect(&self, event: &SecurityEvent) -> Vec<ThreatDetection> {
        let mut detections = Vec::new();
        let risk_score = self.calculate_risk_score(event);
        
        if risk_score > self.threshold {
            let threat_type = if event.event_type.contains("network") {
                ThreatType::DataExfiltration
            } else if event.event_type.contains("exec") {
                ThreatType::PrivilegeEscalation
            } else {
                ThreatType::Unknown
            };
            
            let severity = if risk_score > 0.9 {
                Severity::Critical
            } else if risk_score > 0.8 {
                Severity::High
            } else if risk_score > 0.7 {
                Severity::Medium
            } else {
                Severity::Low
            };
            
            detections.push(ThreatDetection {
                id: Uuid::new_v4().to_string(),
                threat_type,
                severity,
                timestamp: chrono::Utc::now(),
                source: DetectorSource::ML,
                description: format!("ML model detected anomaly: {}", event.event_type),
                confidence: risk_score,
                evidence: vec![format!("Risk score: {:.2}", risk_score)],
            });
        }
        
        detections
    }

    fn name(&self) -> &str {
        "MLDetector"
    }
}

impl Default for MLDetector {
    fn default() -> Self {
        Self::new()
    }
}
