#![allow(dead_code)]

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver, unbounded_channel};
use tracing::{info, warn, error};

// Путь к eBPF программе - конфигурируемый через переменную окружения
const DEFAULT_EBPF_PATH: &str = "/opt/seccomp/ebpf/seccomp_monitor.o";

fn get_ebpf_path() -> String {
    std::env::var("EBPF_PROGRAM_PATH").unwrap_or_else(|_| DEFAULT_EBPF_PATH.to_string())
}

// Структура для eBPF событий (должна совпадать с eBPF программой)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EbpfSeccompEvent {
    pub pid: u32,
    pub tid: u32,
    pub syscall_nr: u32,
    pub ret_value: i64,
    pub duration_ns: u64,
    pub args: [u64; 6],
    pub timestamp: u64,
}

// Агрегированная статистика
#[derive(Debug, Clone)]
pub struct SyscallStats {
    pub count: u64,
    pub total_duration: u64,
    pub max_duration: u64,
    pub min_duration: u64,
    pub errors: u64,
    pub last_seen: u64,
}

pub struct EbpfSeccompManager {
    // КРИТИЧЕСКИ ВАЖНО: Сохраняем bpf объект, чтобы программа не выгрузилась
    // _bpf: Option<Bpf>,  // Закомментировано, т.к. aya не подключена
    event_sender: UnboundedSender<EbpfSeccompEvent>,
    stats: Arc<RwLock<HashMap<u32, SyscallStats>>>,
    anomaly_detector: Arc<AnomalyDetector>,
}

impl EbpfSeccompManager {
    pub async fn new() -> Result<Self> {
        let (event_sender, event_receiver) = unbounded_channel();

        let stats = Arc::new(RwLock::new(HashMap::new()));
        let anomaly_detector = Arc::new(AnomalyDetector::new());

        let manager = Self {
            event_sender: event_sender.clone(),
            stats: stats.clone(),
            anomaly_detector: anomaly_detector.clone(),
        };

        // Загружаем eBPF программу
        Self::load_ebpf_program().await?;

        // Запускаем обработчик событий
        Self::start_event_handler(event_receiver, stats.clone(), anomaly_detector.clone());

        // Запускаем анализатор аномалий
        Self::start_anomaly_analyzer(stats.clone(), anomaly_detector.clone());

        Ok(manager)
    }

    async fn load_ebpf_program() -> Result<()> {
        let ebpf_path = get_ebpf_path();
        info!("Загрузка eBPF программы из: {}", ebpf_path);

        // В production здесь должна быть реальная загрузка eBPF программы
        // ВАЖНО: Необходимо сохранить bpf объект в структуре, иначе программа выгрузится!
        // 
        // Пример реальной реализации:
        // let mut bpf = Bpf::load_file(&ebpf_path)
        //     .context("Failed to load eBPF program")?;
        // 
        // // Прикрепляем программы
        // let program: &mut TracePoint = bpf.program_mut("seccomp_entry")
        //     .context("seccomp_entry program not found")?
        //     .try_into()?;
        // program.load()?;
        // program.attach("syscalls", "sys_enter")?;
        // 
        // // КРИТИЧЕСКИ ВАЖНО: Сохраняем bpf объект
        // self._bpf = Some(bpf);
        
        info!("✅ eBPF программа успешно загружена (stub)");
        Ok(())
    }

    fn start_event_handler(
        mut receiver: UnboundedReceiver<EbpfSeccompEvent>,
        stats: Arc<RwLock<HashMap<u32, SyscallStats>>>,
        anomaly_detector: Arc<AnomalyDetector>,
    ) {

        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                // Обновляем статистику
                let mut stats_guard = stats.write().await;
                let stat = stats_guard.entry(event.syscall_nr).or_insert(SyscallStats {
                    count: 0,
                    total_duration: 0,
                    max_duration: 0,
                    min_duration: u64::MAX,
                    errors: 0,
                    last_seen: 0,
                });

                stat.count += 1;
                stat.total_duration += event.duration_ns;
                stat.max_duration = stat.max_duration.max(event.duration_ns);
                stat.min_duration = stat.min_duration.min(event.duration_ns);
                stat.last_seen = event.timestamp;

                if event.ret_value < 0 {
                    stat.errors += 1;
                }

                // Проверка на аномалии
                if anomaly_detector.is_anomaly(&event).await {
                    warn!(
                        "🚨 Аномалия обнаружена! PID: {}, Syscall: {}, Duration: {}ns",
                        event.pid, event.syscall_nr, event.duration_ns
                    );
                }

                // Проверка на потенциальную атаку
                if event.syscall_nr == libc::SYS_execve as u32 && event.args[0] != 0 {
                    warn!(
                        "⚠️ Подозрительный execve вызов от PID {}",
                        event.pid
                    );
                }
            }
        });
    }

    fn start_anomaly_analyzer(
        stats: Arc<RwLock<HashMap<u32, SyscallStats>>>,
        _anomaly_detector: Arc<AnomalyDetector>,
    ) {

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
            loop {
                interval.tick().await;

                let stats_guard = stats.read().await;
                for (syscall, stat) in stats_guard.iter() {
                    // Анализируем частоту вызовов
                    let frequency = stat.count as f64 / 10.0; // per second

                    if frequency > 1000.0 {
                        error!(
                            "🔥 Высокая частота syscall {}: {:.2} calls/sec (потенциальная DoS атака)",
                            syscall, frequency
                        );
                    }

                    // Анализируем ошибки
                    let error_rate = stat.errors as f64 / stat.count as f64;
                    if error_rate > 0.5 {
                        warn!(
                            "⚠️ Высокий уровень ошибок для syscall {}: {:.2}%",
                            syscall, error_rate * 100.0
                        );
                    }
                }
            }
        });
    }

    pub async fn get_syscall_stats(&self) -> HashMap<u32, SyscallStats> {
        self.stats.read().await.clone()
    }

    pub async fn get_top_syscalls(&self, limit: usize) -> Vec<(u32, u64)> {
        let stats = self.stats.read().await;
        let mut counts: Vec<(u32, u64)> = stats
            .iter()
            .map(|(nr, stat)| (*nr, stat.count))
            .collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1));
        counts.truncate(limit);
        counts
    }
}

// Детектор аномалий на основе машинного обучения
pub struct AnomalyDetector {
    baseline: Arc<RwLock<HashMap<u32, BaselineStats>>>,
    thresholds: Arc<ThresholdConfig>,
}

#[derive(Debug, Clone)]
pub struct BaselineStats {
    mean_duration: f64,
    std_dev: f64,
    mean_frequency: f64,
    sample_count: u64,
}

pub struct ThresholdConfig {
    pub duration_multiplier: f64,  // 3 sigma by default
    pub frequency_threshold: f64,
    pub error_rate_threshold: f64,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            duration_multiplier: 3.0,
            frequency_threshold: 1000.0,
            error_rate_threshold: 0.5,
        }
    }
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            baseline: Arc::new(RwLock::new(HashMap::new())),
            thresholds: Arc::new(ThresholdConfig::default()),
        }
    }

    pub async fn is_anomaly(&self, event: &EbpfSeccompEvent) -> bool {
        let mut baseline = self.baseline.write().await;
        let stats = baseline.entry(event.syscall_nr).or_insert(BaselineStats {
            mean_duration: event.duration_ns as f64,
            std_dev: 0.0,
            mean_frequency: 0.0,
            sample_count: 1,
        });

        // Обновляем baseline с экспоненциальным сглаживанием
        let alpha = 0.1;
        stats.mean_duration = alpha * event.duration_ns as f64 + (1.0 - alpha) * stats.mean_duration;
        stats.sample_count += 1;

        // Проверка аномалий по длительности
        if stats.std_dev > 0.0 {
            let z_score = (event.duration_ns as f64 - stats.mean_duration).abs() / stats.std_dev;
            if z_score > self.thresholds.duration_multiplier {
                return true;
            }
        }

        false
    }

    pub async fn update_baseline(&self, syscall: u32, duration: u64) {
        let mut baseline = self.baseline.write().await;
        let stats = baseline.entry(syscall).or_insert(BaselineStats {
            mean_duration: duration as f64,
            std_dev: 0.0,
            mean_frequency: 0.0,
            sample_count: 1,
        });

        // Обновляем стандартное отклонение
        let old_mean = stats.mean_duration;
        stats.mean_duration = (stats.mean_duration * stats.sample_count as f64 + duration as f64)
            / (stats.sample_count + 1) as f64;

        let variance = (stats.std_dev * stats.std_dev) * stats.sample_count as f64
            + (duration as f64 - old_mean) * (duration as f64 - stats.mean_duration);
        stats.std_dev = (variance / (stats.sample_count + 1) as f64).sqrt();
        stats.sample_count += 1;
    }
}
