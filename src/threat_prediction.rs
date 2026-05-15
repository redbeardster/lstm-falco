#![allow(dead_code)]

use anyhow::Result;
use std::collections::{VecDeque, HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::Timelike;

pub struct ThreatPredictionEngine {
    historical_data: Arc<RwLock<VecDeque<SecurityEvent>>>,
    predictions: Arc<RwLock<Vec<ThreatPrediction>>>,
    anomaly_threshold: f64,
}

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub severity: f64,
    pub features: Vec<f64>,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPrediction {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub predicted_attack_type: String,
    pub probability: f64,
    pub time_window: std::time::Duration,
    pub recommended_actions: Vec<String>,
}

impl ThreatPredictionEngine {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            historical_data: Arc::new(RwLock::new(VecDeque::with_capacity(10000))),
            predictions: Arc::new(RwLock::new(Vec::new())),
            anomaly_threshold: 0.85,
        })
    }

    pub async fn add_event(&self, event: SecurityEvent) {
        let mut history = self.historical_data.write().await;
        history.push_back(event);

        // ИСПРАВЛЕНИЕ: Ограничиваем размер истории для предотвращения утечки памяти
        // Максимум 10000 событий, при превышении удаляем старые
        while history.len() > 10000 {
            history.pop_front();
        }
        
        drop(history); // Освобождаем lock перед тяжелыми операциями

        // ИСПРАВЛЕНИЕ: Запускаем предсказание в отдельной задаче, чтобы не блокировать
        let historical_data = Arc::clone(&self.historical_data);
        let predictions = Arc::clone(&self.predictions);
        let anomaly_threshold = self.anomaly_threshold;
        
        tokio::spawn(async move {
            Self::predict_threats_async(historical_data, predictions, anomaly_threshold).await;
        });
    }

    async fn predict_threats(&self) {
        Self::predict_threats_async(
            Arc::clone(&self.historical_data),
            Arc::clone(&self.predictions),
            self.anomaly_threshold,
        ).await;
    }
    
    // ИСПРАВЛЕНИЕ: Вынесли в отдельную функцию для использования в spawn
    async fn predict_threats_async(
        historical_data: Arc<RwLock<VecDeque<SecurityEvent>>>,
        predictions: Arc<RwLock<Vec<ThreatPrediction>>>,
        _anomaly_threshold: f64,
    ) {
        let history = historical_data.read().await;

        if history.len() < 100 {
            return; // Недостаточно данных
        }

        // Анализируем временные ряды
        let patterns = Self::analyze_temporal_patterns_static(&history).await;

        // Используем модель для классификации
        let new_predictions = Self::classify_threats_static(&history, patterns).await;
        
        drop(history); // Освобождаем lock

        let mut preds = predictions.write().await;
        *preds = new_predictions;
    }

    async fn analyze_temporal_patterns(
        &self,
        history: &VecDeque<SecurityEvent>,
    ) -> Vec<TimePattern> {
        Self::analyze_temporal_patterns_static(history).await
    }
    
    // ИСПРАВЛЕНИЕ: Статическая версия для использования без self
    async fn analyze_temporal_patterns_static(
        history: &VecDeque<SecurityEvent>,
    ) -> Vec<TimePattern> {
        // ИСПРАВЛЕНИЕ: Используем spawn_blocking для CPU-интенсивных операций
        let history_clone: Vec<SecurityEvent> = history.iter().cloned().collect();
        
        tokio::task::spawn_blocking(move || {
            let mut patterns = Vec::new();

            // Анализируем частоту событий
            let mut event_counts: HashMap<String, Vec<u64>> = HashMap::new();

            for event in history_clone.iter() {
                let hour = event.timestamp.hour() as u64;
                event_counts
                    .entry(event.event_type.clone())
                    .or_insert_with(Vec::new)
                    .push(hour);
            }

            // Ищем аномальные паттерны
            for (event_type, hours) in event_counts {
                if hours.len() > 10 {
                    let avg_hour: f64 = hours.iter().sum::<u64>() as f64 / hours.len() as f64;
                    let std_dev = Self::calculate_std_dev_static(&hours, avg_hour);

                    if std_dev < 2.0 {
                        // Сезонный паттерн
                        patterns.push(TimePattern {
                            event_type,
                            hour: avg_hour as u64,
                            confidence: 1.0 - (std_dev / 12.0),
                        });
                    }
                }
            }

            patterns
        })
        .await
        .unwrap_or_default()
    }

    async fn classify_threats(
        &self,
        history: &VecDeque<SecurityEvent>,
        patterns: Vec<TimePattern>,
    ) -> Vec<ThreatPrediction> {
        Self::classify_threats_static(history, patterns).await
    }
    
    // ИСПРАВЛЕНИЕ: Статическая версия для использования без self
    async fn classify_threats_static(
        history: &VecDeque<SecurityEvent>,
        _patterns: Vec<TimePattern>,
    ) -> Vec<ThreatPrediction> {
        let mut predictions = Vec::new();

        // Последние события
        let recent: Vec<&SecurityEvent> = history.iter().rev().take(50).collect();

        // Проверяем на известные атаки
        if Self::detect_bruteforce_static(&recent) {
            predictions.push(ThreatPrediction {
                timestamp: chrono::Utc::now(),
                predicted_attack_type: "bruteforce".to_string(),
                probability: 0.9,
                time_window: std::time::Duration::from_secs(300),
                recommended_actions: vec![
                    "Увеличить rate limiting".to_string(),
                    "Включить CAPTCHA".to_string(),
                    "Блокировать подозрительные IP".to_string(),
                ],
            });
        }

        if Self::detect_lateral_movement_static(&recent) {
            predictions.push(ThreatPrediction {
                timestamp: chrono::Utc::now(),
                predicted_attack_type: "lateral_movement".to_string(),
                probability: 0.85,
                time_window: std::time::Duration::from_secs(600),
                recommended_actions: vec![
                    "Изолировать скомпрометированные поды".to_string(),
                    "Сбросить credentials".to_string(),
                    "Усилить мониторинг сети".to_string(),
                ],
            });
        }

        if Self::detect_data_exfiltration_static(&recent) {
            predictions.push(ThreatPrediction {
                timestamp: chrono::Utc::now(),
                predicted_attack_type: "data_exfiltration".to_string(),
                probability: 0.95,
                time_window: std::time::Duration::from_secs(60),
                recommended_actions: vec![
                    "Блокировать исходящий трафик".to_string(),
                    "Создать снапшот для анализа".to_string(),
                    "Активировать DLP политики".to_string(),
                ],
            });
        }

        predictions
    }

    fn detect_bruteforce(&self, events: &[&SecurityEvent]) -> bool {
        Self::detect_bruteforce_static(events)
    }
    
    fn detect_bruteforce_static(events: &[&SecurityEvent]) -> bool {
        let failed_logins: Vec<&SecurityEvent> = events
            .iter()
            .filter(|e| e.event_type == "failed_login")
            .copied()
            .collect();

        // Более 10 неудачных попыток за минуту
        failed_logins.len() > 10
    }

    fn detect_lateral_movement(&self, events: &[&SecurityEvent]) -> bool {
        Self::detect_lateral_movement_static(events)
    }
    
    fn detect_lateral_movement_static(events: &[&SecurityEvent]) -> bool {
        let unique_hosts: HashSet<_> = events
            .iter()
            .filter(|e| e.event_type == "process_start")
            .map(|e| e.context.clone())
            .collect();

        // Процесс распространился на более чем 3 хоста
        unique_hosts.len() > 3
    }

    fn detect_data_exfiltration(&self, events: &[&SecurityEvent]) -> bool {
        Self::detect_data_exfiltration_static(events)
    }
    
    fn detect_data_exfiltration_static(events: &[&SecurityEvent]) -> bool {
        let large_outbound: Vec<&SecurityEvent> = events
            .iter()
            .filter(|e| {
                e.event_type == "network_outbound"
                    && e.features
                        .get(0)
                        .map(|&size| size > 1000000.0)
                        .unwrap_or(false)
            })
            .copied()
            .collect();

        large_outbound.len() > 5
    }

    fn calculate_std_dev(&self, values: &[u64], mean: f64) -> f64 {
        Self::calculate_std_dev_static(values, mean)
    }
    
    fn calculate_std_dev_static(values: &[u64], mean: f64) -> f64 {
        let variance = values
            .iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>()
            / values.len() as f64;
        variance.sqrt()
    }

    pub async fn get_predictions(&self) -> Vec<ThreatPrediction> {
        self.predictions.read().await.clone()
    }

    pub async fn get_risk_score(&self) -> f64 {
        let predictions = self.predictions.read().await;

        let max_probability = predictions
            .iter()
            .map(|p| p.probability)
            .fold(0.0, f64::max);

        max_probability
    }
}

#[derive(Debug, Clone)]
struct TimePattern {
    event_type: String,
    hour: u64,
    confidence: f64,
}
