use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, IntGaugeVec, Opts, Registry,
};
use std::sync::Arc;

lazy_static::lazy_static! {
    // Registry для всех метрик
    pub static ref REGISTRY: Registry = Registry::new();

    // === Метрики детекторов ===
    
    /// Количество обнаруженных угроз по типу
    pub static ref THREATS_DETECTED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("security_threats_detected_total", "Total number of threats detected by type"),
        &["threat_type", "detector"]
    ).unwrap();

    /// Количество активных угроз
    pub static ref ACTIVE_THREATS: IntGauge = IntGauge::new(
        "security_active_threats",
        "Number of currently active threats"
    ).unwrap();

    /// Текущий уровень риска (0.0 - 1.0)
    pub static ref RISK_SCORE: Gauge = Gauge::new(
        "security_risk_score",
        "Current security risk score (0.0 - 1.0)"
    ).unwrap();

    /// Статус детекторов (1 = healthy, 0 = unhealthy)
    pub static ref DETECTOR_HEALTH: IntGaugeVec = IntGaugeVec::new(
        Opts::new("security_detector_health", "Health status of threat detectors (1=healthy, 0=unhealthy)"),
        &["detector"]
    ).unwrap();

    // === Метрики автоматического реагирования ===
    
    /// Количество выполненных действий по типу
    pub static ref ACTIONS_EXECUTED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("security_actions_executed_total", "Total number of automated actions executed"),
        &["action_type", "status"]
    ).unwrap();

    /// Количество подозрительных активностей, ожидающих подтверждения
    pub static ref PENDING_CONFIRMATIONS: IntGaugeVec = IntGaugeVec::new(
        Opts::new("security_pending_confirmations", "Number of suspicious activities pending confirmation"),
        &["pod", "threat_type"]
    ).unwrap();

    /// Количество подтвержденных угроз
    pub static ref CONFIRMED_THREATS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("security_confirmed_threats_total", "Total number of confirmed threats"),
        &["threat_type"]
    ).unwrap();

    /// Количество ложных срабатываний (истекло окно подтверждения)
    pub static ref FALSE_POSITIVES_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("security_false_positives_total", "Total number of false positives (confirmation window expired)"),
        &["threat_type"]
    ).unwrap();

    /// Время до подтверждения угрозы (секунды)
    pub static ref CONFIRMATION_TIME_SECONDS: HistogramVec = HistogramVec::new(
        prometheus::HistogramOpts::new(
            "security_confirmation_time_seconds",
            "Time taken to confirm a threat (seconds)"
        ).buckets(vec![5.0, 10.0, 20.0, 30.0, 45.0, 60.0, 90.0, 120.0]),
        &["threat_type"]
    ).unwrap();

    // === Метрики событий ===
    
    /// Количество обработанных событий Falco
    pub static ref FALCO_EVENTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("security_falco_events_total", "Total number of Falco events processed"),
        &["priority", "rule"]
    ).unwrap();

    /// Количество обработанных событий Guardd
    pub static ref GUARDD_EVENTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("security_guardd_events_total", "Total number of Guardd events processed"),
        &["event_type"]
    ).unwrap();

    /// Размер буфера событий
    pub static ref EVENTS_BUFFER_SIZE: IntGauge = IntGauge::new(
        "security_events_buffer_size",
        "Current size of events buffer"
    ).unwrap();

    // === Метрики производительности ===
    
    /// Время обработки события (миллисекунды)
    pub static ref EVENT_PROCESSING_TIME_MS: HistogramVec = HistogramVec::new(
        prometheus::HistogramOpts::new(
            "security_event_processing_time_ms",
            "Time taken to process an event (milliseconds)"
        ).buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0]),
        &["event_type"]
    ).unwrap();

    /// Время выполнения ML предсказания (миллисекунды)
    pub static ref ML_PREDICTION_TIME_MS: Histogram = Histogram::with_opts(
        prometheus::HistogramOpts::new(
            "security_ml_prediction_time_ms",
            "Time taken for ML prediction (milliseconds)"
        ).buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0])
    ).unwrap();

    // === Метрики системы ===
    
    /// Время работы системы (секунды)
    pub static ref UPTIME_SECONDS: IntGauge = IntGauge::new(
        "security_uptime_seconds",
        "System uptime in seconds"
    ).unwrap();

    /// Количество записей в аудит-логе
    pub static ref AUDIT_LOG_SIZE: IntGauge = IntGauge::new(
        "security_audit_log_size",
        "Number of records in audit log"
    ).unwrap();

    // === Метрики API ===
    
    /// Количество HTTP запросов
    pub static ref HTTP_REQUESTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("security_http_requests_total", "Total number of HTTP requests"),
        &["method", "endpoint", "status"]
    ).unwrap();

    /// Время обработки HTTP запроса (миллисекунды)
    pub static ref HTTP_REQUEST_DURATION_MS: HistogramVec = HistogramVec::new(
        prometheus::HistogramOpts::new(
            "security_http_request_duration_ms",
            "HTTP request duration in milliseconds"
        ).buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0]),
        &["method", "endpoint"]
    ).unwrap();
}

/// Инициализация метрик
pub fn init_metrics() -> Result<(), prometheus::Error> {
    // Регистрируем все метрики
    REGISTRY.register(Box::new(THREATS_DETECTED_TOTAL.clone()))?;
    REGISTRY.register(Box::new(ACTIVE_THREATS.clone()))?;
    REGISTRY.register(Box::new(RISK_SCORE.clone()))?;
    REGISTRY.register(Box::new(DETECTOR_HEALTH.clone()))?;
    
    REGISTRY.register(Box::new(ACTIONS_EXECUTED_TOTAL.clone()))?;
    REGISTRY.register(Box::new(PENDING_CONFIRMATIONS.clone()))?;
    REGISTRY.register(Box::new(CONFIRMED_THREATS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(FALSE_POSITIVES_TOTAL.clone()))?;
    REGISTRY.register(Box::new(CONFIRMATION_TIME_SECONDS.clone()))?;
    
    REGISTRY.register(Box::new(FALCO_EVENTS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(GUARDD_EVENTS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(EVENTS_BUFFER_SIZE.clone()))?;
    
    REGISTRY.register(Box::new(EVENT_PROCESSING_TIME_MS.clone()))?;
    REGISTRY.register(Box::new(ML_PREDICTION_TIME_MS.clone()))?;
    
    REGISTRY.register(Box::new(UPTIME_SECONDS.clone()))?;
    REGISTRY.register(Box::new(AUDIT_LOG_SIZE.clone()))?;
    
    REGISTRY.register(Box::new(HTTP_REQUESTS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(HTTP_REQUEST_DURATION_MS.clone()))?;
    
    tracing::info!("✅ Prometheus метрики инициализированы");
    
    Ok(())
}

/// Получить все метрики в формате Prometheus
pub fn gather_metrics() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = REGISTRY.gather();
    
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    
    String::from_utf8(buffer).unwrap()
}

/// Обновить метрики детекторов
pub fn update_detector_metrics(detector_name: &str, healthy: bool) {
    DETECTOR_HEALTH
        .with_label_values(&[detector_name])
        .set(if healthy { 1 } else { 0 });
}

/// Записать обнаруженную угрозу
pub fn record_threat_detected(threat_type: &str, detector: &str) {
    THREATS_DETECTED_TOTAL
        .with_label_values(&[threat_type, detector])
        .inc();
}

/// Записать выполненное действие
pub fn record_action_executed(action_type: &str, status: &str) {
    ACTIONS_EXECUTED_TOTAL
        .with_label_values(&[action_type, status])
        .inc();
}

/// Записать подтвержденную угрозу
pub fn record_confirmed_threat(threat_type: &str, confirmation_time_secs: f64) {
    CONFIRMED_THREATS_TOTAL
        .with_label_values(&[threat_type])
        .inc();
    
    CONFIRMATION_TIME_SECONDS
        .with_label_values(&[threat_type])
        .observe(confirmation_time_secs);
}

/// Записать ложное срабатывание
pub fn record_false_positive(threat_type: &str) {
    FALSE_POSITIVES_TOTAL
        .with_label_values(&[threat_type])
        .inc();
}

/// Записать событие Falco
pub fn record_falco_event(priority: &str, rule: &str) {
    FALCO_EVENTS_TOTAL
        .with_label_values(&[priority, rule])
        .inc();
}

/// Записать событие Guardd
pub fn record_guardd_event(event_type: &str) {
    GUARDD_EVENTS_TOTAL
        .with_label_values(&[event_type])
        .inc();
}

/// Записать HTTP запрос
pub fn record_http_request(method: &str, endpoint: &str, status: u16, duration_ms: f64) {
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, endpoint, &status.to_string()])
        .inc();
    
    HTTP_REQUEST_DURATION_MS
        .with_label_values(&[method, endpoint])
        .observe(duration_ms);
}
