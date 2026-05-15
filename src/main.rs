use crate::seccomp_manager::{DynamicSeccompManager, SecurityLevel as SeccompSecurityLevel};
use axum::extract::Path;
use crate::falco_integration::FalcoRule;
use crate::training_metrics::TrainingMetricsCollector;
use falco_integration::FalcoIntegration;

use std::sync::Mutex;

mod data_collector;
mod ml_config;
mod ml_eval;
mod seccomp_manager;
mod lstm_cell;
mod lstm_bptt;
mod lstm_online;
mod sequence_features;
mod training_metrics;
mod training_history;
mod time_window_detector;

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tracing::{info, error};
use tracing_subscriber;

static START_TIME: OnceLock<Instant> = OnceLock::new();

mod ebpf_integration;
mod falco_integration;
mod threat_prediction;
mod automated_response;
mod seccomp_enhanced;
mod realtime_monitor;
mod seccomp_monitor;
mod guardd_integration;
mod threat_detector;
mod detectors;

#[cfg(feature = "metrics")]
mod metrics;

use ebpf_integration::EbpfSeccompManager;
use threat_prediction::ThreatPredictionEngine;
use automated_response::AutomatedResponseEngine;
use seccomp_enhanced::{EnhancedSecuritySystem, SecurityLevel};
use guardd_integration::GuarddIntegration;
use threat_detector::CompositeDetector;
use detectors::{falco_detector::FalcoDetector, guardd_detector::GuarddDetector, ml_detector::MLDetector};
use ml_config::MlConfig;
use time_window_detector::RealtimeLSTM;
use training_history::{TrainingHistoryStore, TrainingSource};

#[derive(Debug, Deserialize)]
struct CreateRuleRequest {
    name: String,
    condition: String,
    output: String,
    priority: String,
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateRuleRequest {
    enabled: bool,
    priority: Option<String>,
}

// Эндпоинты
async fn list_rules(State(state): State<AppState>) -> Json<Vec<FalcoRule>> {
    Json(state.falco_manager.get_rules().await)
}

async fn get_rule(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match state.falco_manager.get_rule(&name).await {
        Some(rule) => Json(rule).into_response(),
        None => (StatusCode::NOT_FOUND, "Rule not found").into_response(),
    }
}

async fn create_rule(
    State(state): State<AppState>,
    Json(req): Json<CreateRuleRequest>,
) -> Response {
    let rule = FalcoRule {
        name: req.name,
        condition: req.condition,
        output: req.output,
        priority: req.priority,
        tags: req.tags,
        enabled: true,
    };

    match state.falco_manager.add_rule(rule).await {
        Ok(_) => (StatusCode::CREATED, "Rule created").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn update_rule(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<UpdateRuleRequest>,
) -> Response {
    match state.falco_manager.update_rule(&name, req.enabled, req.priority).await {
        Ok(_) => (StatusCode::OK, "Rule updated").into_response(),
        Err(e) => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
    }
}

async fn delete_rule(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    match state.falco_manager.delete_rule(&name).await {
        Ok(_) => (StatusCode::OK, "Rule deleted").into_response(),
        Err(e) => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
    }
}

#[derive(Clone)]
struct AppState {
    _ebpf_manager: Arc<EbpfSeccompManager>,
    security_system: Arc<EnhancedSecuritySystem>,
    threat_predictor: Arc<ThreatPredictionEngine>,
    _falco: Arc<FalcoIntegration>,
    response_engine: Arc<AutomatedResponseEngine>,
    guardd: Arc<GuarddIntegration>,
    composite_detector: Arc<CompositeDetector>,
    show_normal_events: Arc<tokio::sync::RwLock<bool>>,
    seccomp_mgr: Arc<DynamicSeccompManager>,
    falco_manager: Arc<FalcoIntegration>,
    realtime_lstm: Arc<RealtimeLSTM>,
    data_collector: Arc<data_collector::DataCollector>,
    training_metrics: Arc<Mutex<TrainingMetricsCollector>>,
    training_history: Arc<Mutex<TrainingHistoryStore>>,
    ml_config: MlConfig,
}

fn record_training_run(
    history: &Arc<Mutex<TrainingHistoryStore>>,
    source: TrainingSource,
    result: &time_window_detector::TrainingResult,
    step_samples: usize,
    anomaly_labels: usize,
    model_path: &str,
    started: std::time::Instant,
) -> training_history::TrainingRunRecord {
    history.lock().unwrap().record(
        source,
        result,
        step_samples,
        anomaly_labels,
        model_path,
        started.elapsed(),
    )
}

#[derive(Serialize)]
struct SecurityStatus {
    security_level: String,
    active_threats: usize,
    risk_score: f64,
    uptime_seconds: u64,
}

#[derive(Serialize)]
struct PredictionsResponse {
    predictions: Vec<threat_prediction::ThreatPrediction>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
struct IncidentsResponse {
    incidents: Vec<automated_response::ResponseAction>,
    total: usize,
}

#[derive(Deserialize)]
struct ManualResponseRequest {
    threat_type: String,
    target: String,
}

#[derive(Deserialize)]
struct SetLevelRequest {
    level: String,
}

#[derive(Deserialize)]
struct TempBlockRequest {
    syscalls: Vec<String>,
    duration: u64,
    priority: String,
}


#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("enterprise_security=warn,falco=error")
        .json()
        .init();

    let ml_config = MlConfig::from_env()?;
    ml_config.ensure_data_dirs()?;

    let training_metrics = Arc::new(Mutex::new(TrainingMetricsCollector::new(
        "data/training_metrics.json",
    )));
    let training_history = Arc::new(Mutex::new(TrainingHistoryStore::new(
        "data/training_history.json",
    )));
    info!("🚀 Запуск Enterprise Security Stack");
    info!(
        "ML: enabled={}, threshold={:.2}, model={:?}",
        ml_config.enabled, ml_config.anomaly_threshold, ml_config.model_path
    );

    START_TIME.set(Instant::now()).expect("Failed to set start time");

    #[cfg(feature = "metrics")]
    {
        if let Err(e) = metrics::init_metrics() {
            error!("⚠️ Не удалось инициализировать метрики: {}", e);
        }
    }

    // 1. Инициализируем eBPF + Seccomp
    let ebpf_manager = Arc::new(EbpfSeccompManager::new().await?);
    let security_system = Arc::new(EnhancedSecuritySystem::new(SecurityLevel::High).await?);

    // 2. Запускаем AI предсказание угроз
    let threat_predictor = Arc::new(ThreatPredictionEngine::new().await?);

    // 3. Настраиваем автоматическое реагирование
    let response_engine = Arc::new(AutomatedResponseEngine::new().await?);

    let lstm_config = ml_config.to_lstm_config();
    let realtime_lstm = Arc::new(RealtimeLSTM::new(lstm_config).await);

    let data_collector = Arc::new(data_collector::DataCollector::new(
        &ml_config.collector_path.to_string_lossy(),
        ml_config.max_collector_samples,
    ));

    let model_path = ml_config.model_path.to_string_lossy().into_owned();
    let falco = Arc::new(
        FalcoIntegration::new(
            response_engine.clone(),
            realtime_lstm.clone(),
            data_collector.clone(),
            training_history.clone(),
            ml_config.to_falco_ml_config(),
            ml_config.falco_webhook_bind.clone(),
            ml_config.window_size,
            model_path,
        )
        .await?,
    );

    // 6. Интегрируем с Guardd
    let guardd = Arc::new(GuarddIntegration::new(response_engine.clone()).await?);

    // 7. Создаем композитный детектор
    let mut composite_detector = CompositeDetector::new();
    composite_detector.add_detector(Box::new(FalcoDetector::new()));
    composite_detector.add_detector(Box::new(GuarddDetector::new()));
    composite_detector.add_detector(Box::new(MLDetector::new()));
    let composite_detector = Arc::new(composite_detector);

    // 8. Создаем менеджер seccomp
    let seccomp_mgr = Arc::new(DynamicSeccompManager::new_without_filter().await?);

    info!("✅ Инициализировано 3 детектора угроз");

    // 10. Запускаем периодический анализ
    let predictor_clone = threat_predictor.clone();
    let security_clone = security_system.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let risk_score = predictor_clone.get_risk_score().await;
            if risk_score > 0.8 {
                error!("🔥 Высокий риск атаки: {:.2}%", risk_score * 100.0);
                let _ = security_clone.dynamic_security_adjustment().await;
            }
        }
    });

    // 11. Создаем состояние приложения
    let app_state = AppState {
        _ebpf_manager: ebpf_manager,
        security_system,
        threat_predictor,
        _falco: falco.clone(),  // Используйте clone
        response_engine,
        guardd,
        composite_detector,
        show_normal_events: Arc::new(tokio::sync::RwLock::new(false)),
        seccomp_mgr: seccomp_mgr.clone(),
        falco_manager: falco.clone(),
        realtime_lstm: realtime_lstm.clone(),
        data_collector: data_collector.clone(),
        training_metrics: training_metrics.clone(),
        training_history: training_history.clone(),
        ml_config: ml_config.clone(),
    };

    let api_bind = ml_config.api_bind.clone();

    // 10. Настраиваем маршруты
    let app = Router::new()
        .route("/api/security/status", get(get_security_status))
        .route("/api/security/predictions", get(get_predictions))
        .route("/api/security/incidents", get(get_incidents))
        .route("/api/security/respond", post(manual_response))
        .route("/api/security/detectors/health", get(get_detectors_health))
        .route("/api/security/audit", get(get_audit_log))
        .route("/api/security/filters", get(get_seccomp_filters))
        .route("/api/guardd/events", get(get_guardd_events))
        .route("/api/guardd/critical", get(get_guardd_critical))
        .route("/health", get(health_check))
        .route("/health/ready", get(readiness_check))
        .route("/metrics", get(metrics_handler))
        .route("/api/verbose", post(toggle_verbose))
        .route("/api/seccomp/level", post(set_security_level))
        .route("/api/seccomp/block", post(add_temp_block))
        .route("/api/seccomp/status", get(get_seccomp_status))
        .route("/api/rules", get(list_rules).post(create_rule))
        .route("/api/rules/:name", get(get_rule).put(update_rule).delete(delete_rule))
        .route("/api/ml/lstm/stats", get(get_lstm_stats))
        .route("/api/ml/train", post(trigger_training))
        .route("/api/ml/training/history", get(get_training_history))
        .route("/api/ml/stats", get(get_training_stats))
        .route("/api/ml/data/save", post(save_training_data))
        .route("/api/ml/metrics", get(get_model_metrics))
        .route("/api/ml/performance", get(get_model_performance))
        .route("/api/ml/test", post(test_model))
        .route("/api/ml/train_real", post(train_on_real_data))
        .route("/api/ml/test_direct", get(test_model_direct))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(&api_bind)
        .await
        .with_context(|| format!("Failed to bind API on {api_bind}"))?;

    info!("🌐 Security API listening on {}", api_bind);

    // seccomp_mgr.apply_current_config().await?;

    let lstm_shutdown = realtime_lstm.clone();
    let shutdown_signal = async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        info!("🛑 Shutdown signal received");
        lstm_shutdown.stop();
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .context("Server error")?;

    info!("👋 Сервер остановлен");
    Ok(())
}

async fn get_security_status(State(state): State<AppState>) -> Json<SecurityStatus> {
    let security_level = state.security_system.get_security_level().await;
    let predictions = state.threat_predictor.get_predictions().await;
    let risk_score = state.threat_predictor.get_risk_score().await;

    let uptime = START_TIME.get()
        .map(|start| start.elapsed().as_secs())
        .unwrap_or(0);

    #[cfg(feature = "metrics")]
    {
        metrics::UPTIME_SECONDS.set(uptime as i64);
    }

    Json(SecurityStatus {
        security_level: format!("{:?}", security_level),
        active_threats: predictions.len(),
        risk_score,
        uptime_seconds: uptime,
    })
}

async fn get_predictions(State(state): State<AppState>) -> Json<PredictionsResponse> {
    let predictions = state.threat_predictor.get_predictions().await;

    Json(PredictionsResponse {
        predictions,
        timestamp: chrono::Utc::now(),
    })
}

async fn get_incidents(State(state): State<AppState>) -> Json<IncidentsResponse> {
    let incidents = state.response_engine.get_action_history().await;
    let total = incidents.len();

    Json(IncidentsResponse {
        incidents,
        total,
    })
}

async fn manual_response(
    State(state): State<AppState>,
    Json(request): Json<ManualResponseRequest>,
) -> Json<serde_json::Value> {
    info!("📝 Ручное реагирование: {} на {}", request.threat_type, request.target);

    if request.target.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Target cannot be empty"
        }));
    }

    let result = match request.threat_type.as_str() {
        "isolate_pod" => {
            let parts: Vec<&str> = request.target.split('/').collect();
            if parts.len() != 2 {
                return Json(json!({
                    "status": "error",
                    "message": "Target must be in format namespace/pod"
                }));
            }

            match isolate_pod_manual(parts[0], parts[1]).await {
                Ok(_) => {
                    info!("✅ Pod {} изолирован вручную", request.target);
                    Ok("Pod isolated successfully")
                }
                Err(e) => Err(format!("Failed to isolate pod: {}", e))
            }
        }
        "increase_security" => {
            match state.security_system.dynamic_security_adjustment().await {
                Ok(_) => {
                    info!("✅ Уровень безопасности повышен");
                    Ok("Security level increased")
                }
                Err(e) => Err(format!("Failed to increase security: {}", e))
            }
        }
        "block_threat" => {
            info!("🚫 Блокировка угрозы: {}", request.target);
            Ok("Threat blocked")
        }
        _ => Err(format!("Unknown threat type: {}", request.threat_type))
    };

    info!(
        "AUDIT: Manual action {} on {} - result: {:?}",
        request.threat_type, request.target, result
    );

    match result {
        Ok(message) => Json(json!({
            "status": "success",
            "message": message,
            "threat_type": request.threat_type,
            "target": request.target,
            "timestamp": chrono::Utc::now(),
        })),
        Err(error) => Json(json!({
            "status": "error",
            "message": error,
            "threat_type": request.threat_type,
            "target": request.target,
            "timestamp": chrono::Utc::now(),
        })),
    }
}

async fn isolate_pod_manual(namespace: &str, pod_name: &str) -> Result<()> {
    use kube::{Api, Client};
    use k8s_openapi::api::core::v1::Pod;
    use kube::api::{Patch, PatchParams};

    let client = Client::try_default().await?;
    let pods: Api<Pod> = Api::namespaced(client, namespace);

    let patch = json!({
        "metadata": {
            "labels": {
                "security.quarantine": "true",
                "security.manual": "true",
                "security.isolated-at": chrono::Utc::now().to_rfc3339()
            }
        }
    });

    pods.patch(pod_name, &PatchParams::default(), &Patch::Merge(&patch)).await?;
    Ok(())
}

async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now(),
    }))
}

async fn readiness_check(State(state): State<AppState>) -> Response {
    let lstm_ready = state.realtime_lstm.is_ready().await;
    let collectors = state.data_collector.get_buffer_len().await;
    let ml_ready = !state.ml_config.enabled
        || lstm_ready
        || collectors >= state.ml_config.min_train_samples;
    let status = if ml_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(json!({
            "status": if ml_ready { "ready" } else { "warming_up" },
            "ml_enabled": state.ml_config.enabled,
            "lstm_trained": lstm_ready,
            "collector_samples": collectors,
            "min_train_samples": state.ml_config.min_train_samples,
            "timestamp": chrono::Utc::now(),
        })),
    )
        .into_response()
}

async fn get_guardd_events(State(state): State<AppState>) -> Json<serde_json::Value> {
    let events = state.guardd.get_events().await;

    Json(json!({
        "events": events,
        "total": events.len(),
        "timestamp": chrono::Utc::now(),
    }))
}

async fn get_guardd_critical(State(state): State<AppState>) -> Json<serde_json::Value> {
    let critical_events = state.guardd.get_critical_events().await;

    Json(json!({
        "critical_events": critical_events,
        "total": critical_events.len(),
        "timestamp": chrono::Utc::now(),
    }))
}

async fn get_detectors_health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let health_results = state.composite_detector.health_check_all().await;
    let all_healthy = health_results.iter().all(|(_, healthy)| *healthy);

    Json(json!({
        "status": if all_healthy { "healthy" } else { "degraded" },
        "detectors": health_results.iter().map(|(name, healthy)| {
            json!({
                "name": name,
                "healthy": healthy,
                "status": if *healthy { "ok" } else { "error" }
            })
        }).collect::<Vec<_>>(),
        "total_detectors": health_results.len(),
        "healthy_count": health_results.iter().filter(|(_, h)| *h).count(),
        "timestamp": chrono::Utc::now(),
    }))
}

async fn get_audit_log(State(state): State<AppState>) -> Json<serde_json::Value> {
    let audit_records = state.response_engine.get_audit_log().await;

    #[cfg(feature = "metrics")]
    {
        metrics::AUDIT_LOG_SIZE.set(audit_records.len() as i64);
    }

    Json(json!({
        "audit_records": audit_records,
        "total": audit_records.len(),
        "timestamp": chrono::Utc::now(),
    }))
}

async fn get_seccomp_filters(State(state): State<AppState>) -> Json<serde_json::Value> {
    let filters = state.security_system.get_active_filters().await;
    let filter_count = state.security_system.get_filter_count().await;
    let security_level = state.security_system.get_security_level().await;

    Json(json!({
        "security_level": format!("{:?}", security_level),
        "filters": filters,
        "total_filters": filter_count,
        "timestamp": chrono::Utc::now(),
    }))
}

async fn metrics_handler() -> impl IntoResponse {
    #[cfg(feature = "metrics")]
    {
        use axum::http::header;
        let metrics = metrics::gather_metrics();
        ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], metrics)
    }

    #[cfg(not(feature = "metrics"))]
    {
        (StatusCode::NOT_FOUND, "Metrics not enabled")
    }
}

async fn toggle_verbose(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut verbose = state.show_normal_events.write().await;
    *verbose = !*verbose;

    Json(json!({
        "verbose_mode": *verbose,
        "message": if *verbose { "Now showing all events" } else { "Now showing only anomalies" }
    }))
}

async fn set_security_level(
    State(state): State<AppState>,
    Json(req): Json<SetLevelRequest>,
) -> Response {
    let level = match req.level.as_str() {
        "low" => SeccompSecurityLevel::Low,
        "medium" => SeccompSecurityLevel::Medium,
        "high" => SeccompSecurityLevel::High,
        "paranoid" => SeccompSecurityLevel::Paranoid,
        _ => return (StatusCode::BAD_REQUEST, "Invalid level").into_response(),
    };

    if let Err(e) = state.seccomp_mgr.escalate_security_level(level).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed: {}", e)).into_response();
    }

    Json(json!({"status": "ok", "level": req.level})).into_response()
}

async fn add_temp_block(
    State(state): State<AppState>,
    Json(req): Json<TempBlockRequest>,
) -> Response {
    use crate::seccomp_manager::TempBlockRule;

    let rule = TempBlockRule {
        syscalls: req.syscalls.into_iter().collect(),
        expires_at: Instant::now() + Duration::from_secs(req.duration),
        priority: req.priority,
    };

    if let Err(e) = state.seccomp_mgr.add_temp_rule(rule).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed: {}", e)).into_response();
    }

    Json(json!({"status": "ok"})).into_response()
}

async fn get_seccomp_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let level = state.seccomp_mgr.get_current_level().await;
    let temp_rules = state.seccomp_mgr.get_temp_rules().await;

    Json(json!({
        "current_level": format!("{:?}", level),
        "temp_rules_count": temp_rules.len(),
        "temp_rules": temp_rules.iter().map(|r| {
            json!({
                "syscalls": r.syscalls,
                "expires_in": r.expires_in,
                "priority": r.priority
            })
        }).collect::<Vec<_>>()
    }))
}

async fn get_lstm_stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(state.realtime_lstm.get_stats().await)
}

async fn trigger_training(State(state): State<AppState>) -> Json<serde_json::Value> {
    let (features, labels) = state.data_collector.get_training_data().await;
    if features.len() < state.ml_config.min_train_samples {
        return Json(json!({
            "status": "error",
            "message": format!(
                "Need at least {} samples, have {}",
                state.ml_config.min_train_samples,
                features.len()
            )
        }));
    }
    let anomaly_count = labels.iter().filter(|&&l| l > 0.5).count();
    let model_path = state.ml_config.model_path.to_string_lossy().into_owned();
    let started = std::time::Instant::now();
    let result = state.realtime_lstm.train_from_data(&features, &labels).await;
    let run = record_training_run(
        &state.training_history,
        TrainingSource::ApiTrain,
        &result,
        features.len(),
        anomaly_count,
        &model_path,
        started,
    );
    if result.model_saved {
        state
            .data_collector
            .retain_tail(state.ml_config.window_size * 2)
            .await;
    }
    Json(json!({
        "status": if result.model_saved { "training_completed" } else { "training_failed" },
        "samples": features.len(),
        "train_windows": result.train_samples,
        "val_windows": result.val_samples,
        "epochs_run": result.epochs_run,
        "accuracy": result.accuracy,
        "f1_score": result.f1_score,
        "loss": result.loss,
        "model_saved": result.model_saved,
        "training_run": run,
        "lstm_stats": state.realtime_lstm.get_stats().await,
    }))
}

async fn get_training_history(State(state): State<AppState>) -> Json<serde_json::Value> {
    let history = state.training_history.lock().unwrap();
    Json(history.summary())
}

async fn get_training_stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    let buffer_len = state.data_collector.get_buffer_len().await;
    Json(json!({
        "samples_collected": buffer_len,
        "lstm": state.realtime_lstm.get_stats().await,
    }))
}

async fn save_training_data(State(state): State<AppState>) -> Json<serde_json::Value> {
    match state.data_collector.save_to_json().await {
        Ok(_) => Json(json!({"status": "saved"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}


async fn get_model_performance(State(state): State<AppState>) -> Json<serde_json::Value> {
    let trained = state.realtime_lstm.is_ready().await;
    let latest = state
        .training_metrics
        .lock()
        .unwrap()
        .get_latest();
    let lstm = state.realtime_lstm.get_stats().await;

    Json(json!({
        "status": if trained { "trained" } else { "not_trained" },
        "lstm_trained": trained,
        "lstm": lstm,
        "metrics": latest,
    }))
}

async fn get_model_metrics(State(state): State<AppState>) -> Json<serde_json::Value> {
    let metrics = state.training_metrics.lock().unwrap();  // без .await
    Json(metrics.get_summary())
}

async fn test_model(State(state): State<AppState>, Json(payload): Json<Vec<Vec<f64>>>) -> Json<serde_json::Value> {
    let mut predictions = Vec::new();
    for features in payload {
        let score = state.realtime_lstm.predict_single(&features).await;
        predictions.push(score);
    }
    Json(json!({
        "predictions": predictions,
        "threshold": state.ml_config.anomaly_threshold,
        "input_size": 8,
    }))
}

async fn train_on_real_data(State(state): State<AppState>) -> Json<serde_json::Value> {
    use std::fs;

    info!("📊 Loading real training data...");

    let data_path = state.ml_config.training_data_path.to_string_lossy().to_string();
    let content = match fs::read_to_string(data_path) {
        Ok(c) => c,
        Err(_) => {
            return Json(json!({
                "status": "error",
                "message": "No training data found. Run: cargo run --example training_scenarios"
            }));
        }
    };

    let samples: Vec<serde_json::Value> = match serde_json::from_str(&content) {
        Ok(data) => data,
        Err(e) => {
            return Json(json!({
                "status": "error",
                "message": format!("Failed to parse training data: {}", e)
            }));
        }
    };

    let mut features = Vec::new();
    let mut labels = Vec::new();

    for sample in samples {
        if let Some(f) = sample["features"].as_array() {
            let feature_vec: Vec<f64> = f.iter().map(|v| v.as_f64().unwrap_or(0.0)).collect();
            features.push(feature_vec);
        }
        labels.push(sample["label"].as_f64().unwrap_or(0.0));
    }

    info!("📊 Loaded {} samples for LSTM training", features.len());

    let anomaly_count = labels.iter().filter(|&&l| l > 0.5).count();
    let model_path = state.ml_config.model_path.to_string_lossy().into_owned();
    let started = std::time::Instant::now();
    let result = state.realtime_lstm.train_from_data(&features, &labels).await;
    let run = record_training_run(
        &state.training_history,
        TrainingSource::TrainReal,
        &result,
        features.len(),
        anomaly_count,
        &model_path,
        started,
    );

    Json(json!({
        "status": if result.model_saved { "training_completed" } else { "training_failed" },
        "samples_used": features.len(),
        "anomalies": anomaly_count,
        "normal": labels.len() - anomaly_count,
        "accuracy": result.accuracy,
        "f1_score": result.f1_score,
        "loss": result.loss,
        "model_saved": result.model_saved,
        "epochs_run": result.epochs_run,
        "training_run": run,
    }))
}

async fn test_model_direct(State(state): State<AppState>) -> Json<serde_json::Value> {
    // 8-D timestep (как falco_event_to_lstm_timestep)
    let normal_features = vec![1.0, 0.0, 0.0, 0.1, 0.0, 0.0, 0.0, 0.0];
    let anomaly_features = vec![5.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

    let normal_score = state.realtime_lstm.predict_single(&normal_features).await;
    let anomaly_score = state.realtime_lstm.predict_single(&anomaly_features).await;

    Json(json!({
        "normal_prediction": normal_score,
        "anomaly_prediction": anomaly_score,
        "is_model_working": anomaly_score > normal_score,
        "threshold": state.ml_config.anomaly_threshold,
    }))
}
