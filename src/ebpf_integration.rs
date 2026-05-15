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
    zscore_detector: Arc<crate::ebpf_zscore_detector::SyscallDurationZScoreDetector>,
}

impl EbpfSeccompManager {
    pub async fn new() -> Result<Self> {
        let (event_sender, event_receiver) = unbounded_channel();

        let stats = Arc::new(RwLock::new(HashMap::new()));
        let zscore_detector =
            Arc::new(crate::ebpf_zscore_detector::SyscallDurationZScoreDetector::new());

        let manager = Self {
            event_sender: event_sender.clone(),
            stats: stats.clone(),
            zscore_detector: zscore_detector.clone(),
        };

        // Загружаем eBPF программу
        Self::load_ebpf_program().await?;

        // Запускаем обработчик событий
        Self::start_event_handler(event_receiver, stats.clone(), zscore_detector.clone());

        Self::start_anomaly_analyzer(stats.clone(), zscore_detector.clone());

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
        zscore_detector: Arc<crate::ebpf_zscore_detector::SyscallDurationZScoreDetector>,
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
                if zscore_detector
                    .is_anomaly(event.syscall_nr, event.duration_ns)
                    .await
                {
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
        _zscore_detector: Arc<crate::ebpf_zscore_detector::SyscallDurationZScoreDetector>,
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
