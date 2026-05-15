// Интеграция с Guardd - Runtime Security для Kubernetes
// https://github.com/benny-e/guardd

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

/// Guardd событие безопасности
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuarddEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: GuarddEventType,
    pub pod_name: String,
    pub namespace: String,
    pub container_name: String,
    pub severity: GuarddSeverity,
    pub details: GuarddDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuarddEventType {
    FileAccess,
    NetworkConnection,
    ProcessExecution,
    CapabilityUsage,
    SyscallAnomaly,
    ConfigChange,
}

impl std::fmt::Display for GuarddEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuarddEventType::FileAccess => write!(f, "FileAccess"),
            GuarddEventType::NetworkConnection => write!(f, "NetworkConnection"),
            GuarddEventType::ProcessExecution => write!(f, "ProcessExecution"),
            GuarddEventType::CapabilityUsage => write!(f, "CapabilityUsage"),
            GuarddEventType::SyscallAnomaly => write!(f, "SyscallAnomaly"),
            GuarddEventType::ConfigChange => write!(f, "ConfigChange"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GuarddSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuarddDetails {
    pub description: String,
    pub process_name: Option<String>,
    pub file_path: Option<String>,
    pub network_dest: Option<String>,
    pub syscall: Option<String>,
    pub capabilities: Option<Vec<String>>,
}

/// Интеграция с Guardd
pub struct GuarddIntegration {
    events: Arc<RwLock<Vec<GuarddEvent>>>,
    response_engine: Arc<crate::automated_response::AutomatedResponseEngine>,
}

impl GuarddIntegration {
    pub async fn new(
        response_engine: Arc<crate::automated_response::AutomatedResponseEngine>,
    ) -> Result<Self> {
        info!("🛡️ Инициализация Guardd интеграции");

        let integration = Self {
            events: Arc::new(RwLock::new(Vec::new())),
            response_engine,
        };

        // Запускаем webhook сервер для Guardd
        integration.start_webhook_server().await?;

        info!("✅ Guardd интеграция готова");
        Ok(integration)
    }

    async fn start_webhook_server(&self) -> Result<()> {
        let events = Arc::clone(&self.events);
        let response_engine = Arc::clone(&self.response_engine);

        tokio::spawn(async move {
            let app = axum::Router::new()
                .route("/guardd-events", axum::routing::post({
                    let events = events.clone();
                    let engine = response_engine.clone();
                    move |body| {
                        let events = events.clone();
                        let engine = engine.clone();
                        async move { handle_guardd_event(body, events, engine).await }
                    }
                }));

            let listener = match tokio::net::TcpListener::bind("0.0.0.0:8081").await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind Guardd webhook on :8081: {}", e);
                    return;
                }
            };

            info!("🛡️ Guardd webhook сервер запущен на :8081");
            
            if let Err(e) = axum::serve(listener, app).await {
                error!("Guardd webhook server error: {}", e);
            }
        });

        Ok(())
    }

    pub async fn get_events(&self) -> Vec<GuarddEvent> {
        self.events.read().await.clone()
    }

    pub async fn get_critical_events(&self) -> Vec<GuarddEvent> {
        let events = self.events.read().await;
        events
            .iter()
            .filter(|e| e.severity == GuarddSeverity::Critical)
            .cloned()
            .collect()
    }
}

async fn handle_guardd_event(
    body: String,
    events: Arc<RwLock<Vec<GuarddEvent>>>,
    response_engine: Arc<crate::automated_response::AutomatedResponseEngine>,
) -> axum::response::Response {
    match serde_json::from_str::<GuarddEvent>(&body) {
        Ok(event) => {
            info!(
                "🛡️ Guardd событие: {:?} в {}/{}",
                event.event_type, event.namespace, event.pod_name
            );

            // Сохраняем событие
            {
                let mut events_guard = events.write().await;
                events_guard.push(event.clone());
                
                // Ограничиваем размер буфера
                if events_guard.len() > 10000 {
                    events_guard.drain(0..1000);
                }
            }

            // Обрабатываем критические события
            if event.severity == GuarddSeverity::Critical {
                warn!(
                    "🚨 CRITICAL Guardd событие: {} - {}",
                    event.event_type, event.details.description
                );

                // Автоматическое реагирование
                handle_critical_guardd_event(&event, response_engine).await;
            }

            axum::response::Response::builder()
                .status(200)
                .body(axum::body::Body::from("OK"))
                .unwrap()
        }
        Err(e) => {
            error!("Ошибка парсинга Guardd события: {}", e);
            axum::response::Response::builder()
                .status(400)
                .body(axum::body::Body::from(format!("Error: {}", e)))
                .unwrap()
        }
    }
}

async fn handle_critical_guardd_event(
    event: &GuarddEvent,
    _response_engine: Arc<crate::automated_response::AutomatedResponseEngine>,
) {
    match event.event_type {
        GuarddEventType::FileAccess => {
            if let Some(ref path) = event.details.file_path {
                if path.contains("/etc/shadow") || path.contains("/etc/passwd") {
                    error!(
                        "🚨 Попытка доступа к критическому файлу: {} в pod {}",
                        path, event.pod_name
                    );
                    
                    // Изолируем pod
                    if let Err(e) = isolate_pod(&event.namespace, &event.pod_name).await {
                        error!("❌ Не удалось изолировать pod {}: {}", event.pod_name, e);
                    } else {
                        info!("✅ Pod {} изолирован", event.pod_name);
                    }
                }
            }
        }
        GuarddEventType::NetworkConnection => {
            if let Some(ref dest) = event.details.network_dest {
                warn!(
                    "🌐 Подозрительное сетевое соединение: {} -> {}",
                    event.pod_name, dest
                );
                
                // Проверяем в threat intelligence (упрощенная версия)
                if is_suspicious_destination(dest) {
                    error!("🚨 Обнаружено соединение с подозрительным адресом: {}", dest);
                    
                    // Изолируем pod
                    if let Err(e) = isolate_pod(&event.namespace, &event.pod_name).await {
                        error!("❌ Не удалось изолировать pod {}: {}", event.pod_name, e);
                    }
                }
            }
        }
        GuarddEventType::ProcessExecution => {
            if let Some(ref proc) = event.details.process_name {
                if proc.contains("nc") || proc.contains("ncat") || proc.contains("/bin/sh") {
                    error!(
                        "🚨 Подозрительный процесс: {} в pod {}",
                        proc, event.pod_name
                    );
                    
                    // Логируем для ручного реагирования
                    warn!("⚠️ Требуется ручное вмешательство для pod {}", event.pod_name);
                    
                    // В production здесь можно убить процесс через kubectl exec
                    // kill_process_in_pod(&event.namespace, &event.pod_name, &event.container_name, pid).await
                }
            }
        }
        GuarddEventType::CapabilityUsage => {
            if let Some(ref caps) = event.details.capabilities {
                if caps.contains(&"CAP_SYS_ADMIN".to_string()) {
                    error!(
                        "🚨 Использование CAP_SYS_ADMIN в pod {}",
                        event.pod_name
                    );
                    
                    // Проверяем легитимность (упрощенная версия)
                    if !is_privileged_pod(&event.namespace, &event.pod_name).await {
                        warn!("⚠️ Неавторизованное использование CAP_SYS_ADMIN в pod {}", event.pod_name);
                    }
                }
            }
        }
        GuarddEventType::SyscallAnomaly => {
            warn!(
                "⚠️ Аномальный syscall в pod {}: {}",
                event.pod_name, event.details.description
            );
        }
        GuarddEventType::ConfigChange => {
            warn!(
                "⚠️ Изменение конфигурации в pod {}: {}",
                event.pod_name, event.details.description
            );
        }
    }
}

/// Изолирует pod с помощью Kubernetes API
async fn isolate_pod(namespace: &str, pod_name: &str) -> Result<()> {
    use kube::{Api, Client};
    use k8s_openapi::api::core::v1::Pod;
    use kube::api::{Patch, PatchParams};
    
    info!("🔒 Изоляция pod {}/{}", namespace, pod_name);
    
    // Подключаемся к Kubernetes API
    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            error!("❌ Не удалось подключиться к Kubernetes API: {}", e);
            return Err(anyhow::anyhow!("Kubernetes API connection failed: {}", e));
        }
    };
    
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    
    // Добавляем label для карантина
    let patch = serde_json::json!({
        "metadata": {
            "labels": {
                "security.quarantine": "true",
                "security.threat": "critical",
                "security.isolated-at": chrono::Utc::now().to_rfc3339()
            }
        }
    });
    
    match pods.patch(pod_name, &PatchParams::default(), &Patch::Merge(&patch)).await {
        Ok(_) => {
            info!("✅ Pod {} помечен для изоляции", pod_name);
            
            // В production здесь нужно создать NetworkPolicy
            // Для демонстрации просто логируем
            info!("📋 NetworkPolicy для изоляции pod {} должна быть создана", pod_name);
            
            Ok(())
        }
        Err(e) => {
            error!("❌ Не удалось изолировать pod {}: {}", pod_name, e);
            Err(anyhow::anyhow!("Failed to isolate pod: {}", e))
        }
    }
}

/// Проверяет, является ли destination подозрительным (упрощенная версия)
fn is_suspicious_destination(dest: &str) -> bool {
    // Список известных вредоносных IP/доменов (для демонстрации)
    let suspicious_patterns = vec![
        "malware.com",
        "evil.net",
        "192.0.2.", // TEST-NET-1 (для тестирования)
    ];
    
    suspicious_patterns.iter().any(|pattern| dest.contains(pattern))
}

/// Проверяет, является ли pod привилегированным (упрощенная версия)
async fn is_privileged_pod(namespace: &str, pod_name: &str) -> bool {
    // Whitelist привилегированных приложений
    let privileged_apps = vec![
        "kube-system",
        "monitoring",
        "security-stack",
    ];
    
    // Проверяем namespace
    if privileged_apps.contains(&namespace) {
        return true;
    }
    
    // Проверяем имя pod
    if pod_name.starts_with("privileged-") || pod_name.starts_with("system-") {
        return true;
    }
    
    false
}
