use std::collections::BTreeMap;
use anyhow::Result;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp,
    SeccompCondition, SeccompFilter, SeccompRule, TargetArch,
};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
    Paranoid,
}

pub struct TempBlockRule {
    pub syscalls: HashSet<String>,
    pub expires_at: Instant,
    pub priority: String,
}

pub struct TempRuleInfo {
    pub syscalls: HashSet<String>,
    pub expires_in: u64,
    pub priority: String,
}

pub struct DynamicSeccompManager {
    current_level: Arc<RwLock<SecurityLevel>>,
    temp_rules: Arc<RwLock<Vec<TempBlockRule>>>,
    is_filter_active: Arc<RwLock<bool>>,
}

impl DynamicSeccompManager {
    // Создает менеджер без применения фильтра
        pub async fn new_without_filter() -> Result<Self> {
            Ok(Self {
                current_level: Arc::new(RwLock::new(SecurityLevel::High)),
                temp_rules: Arc::new(RwLock::new(Vec::new())),
                is_filter_active: Arc::new(RwLock::new(false)),
            })
        }

    pub async fn new() -> Result<Self> {
        let manager = Self {
            current_level: Arc::new(RwLock::new(SecurityLevel::High)),
            temp_rules: Arc::new(RwLock::new(Vec::new())),
            is_filter_active: Arc::new(RwLock::new(false)),
        };

        manager.apply_current_config().await?;
        manager.start_cleanup_task();

        Ok(manager)
    }

    fn get_current_arch() -> TargetArch {
        #[cfg(target_arch = "x86_64")]
        return TargetArch::x86_64;
        #[cfg(target_arch = "aarch64")]
        return TargetArch::aarch64;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        panic!("Unsupported architecture");
    }

    async fn build_allowed_syscalls(&self) -> HashSet<String> {
        let level = *self.current_level.read().await;
        let temp_rules = self.temp_rules.read().await;

        let mut allowed = self.get_level_syscalls(level);

        for rule in temp_rules.iter() {
            for syscall in &rule.syscalls {
                allowed.remove(syscall);
            }
        }

        allowed
    }

    fn get_level_syscalls(&self, level: SecurityLevel) -> HashSet<String> {
        let mut set = HashSet::new();

        // Базовые syscall'ы, всегда необходимые
        let always_needed = vec![
            "read", "write", "close", "exit", "exit_group",
            "getpid", "gettid", "brk", "mmap", "munmap",
            "mprotect", "rt_sigaction", "rt_sigprocmask",
            "rt_sigreturn", "futex", "clone", "nanosleep",
            "clock_gettime", "prctl", "sigaltstack",
            "socket", "bind", "listen", "accept", "accept4",
            "recvfrom", "sendto", "getsockname", "getpeername",
            "getsockopt", "setsockopt", "shutdown", "fcntl",
            "epoll_create", "epoll_ctl", "epoll_wait", "eventfd2",
        ];

        for s in always_needed {
            set.insert(s.to_string());
        }

        match level {
            SecurityLevel::Low => {
                for s in &["openat", "fstat", "lseek"] {
                    set.insert(s.to_string());
                }
            }
            SecurityLevel::Medium => {
                for s in &["openat", "fstat", "lseek", "stat"] {
                    set.insert(s.to_string());
                }
            }
            SecurityLevel::High => {
                for s in &["openat", "fstat", "lseek", "stat"] {
                    set.insert(s.to_string());
                }
            }
            SecurityLevel::Paranoid => {
                // В paranoid режиме только БАЗОВЫЕ syscall'ы
                // (уже добавлены в always_needed)
                // Ничего дополнительно не добавляем
            }
        }

        set
    }

    fn syscall_name_to_nr(name: &str) -> Option<i64> {
        match name {
            "read" => Some(libc::SYS_read),
            "write" => Some(libc::SYS_write),
            "close" => Some(libc::SYS_close),
            "exit" => Some(libc::SYS_exit),
            "exit_group" => Some(libc::SYS_exit_group),
            "getpid" => Some(libc::SYS_getpid),
            "gettid" => Some(libc::SYS_gettid),
            "brk" => Some(libc::SYS_brk),
            "mmap" => Some(libc::SYS_mmap),
            "munmap" => Some(libc::SYS_munmap),
            "mprotect" => Some(libc::SYS_mprotect),
            "rt_sigaction" => Some(libc::SYS_rt_sigaction),
            "rt_sigprocmask" => Some(libc::SYS_rt_sigprocmask),
            "rt_sigreturn" => Some(libc::SYS_rt_sigreturn),
            "futex" => Some(libc::SYS_futex),
            "clone" => Some(libc::SYS_clone),
            "nanosleep" => Some(libc::SYS_nanosleep),
            "clock_gettime" => Some(libc::SYS_clock_gettime),
            "prctl" => Some(libc::SYS_prctl),
            "sigreturn" => Some(libc::SYS_rt_sigreturn),
            "sigaltstack" => Some(libc::SYS_sigaltstack),
            "openat" => Some(libc::SYS_openat),
            "fstat" => Some(libc::SYS_fstat),
            "lseek" => Some(libc::SYS_lseek),
            "stat" => Some(libc::SYS_stat),
            "socket" => Some(libc::SYS_socket),
            "connect" => Some(libc::SYS_connect),
            "accept" => Some(libc::SYS_accept),
            "bind" => Some(libc::SYS_bind),
            "listen" => Some(libc::SYS_listen),
            "recvfrom" => Some(libc::SYS_recvfrom),
            "sendto" => Some(libc::SYS_sendto),
            "getsockopt" => Some(libc::SYS_getsockopt),
            "setsockopt" => Some(libc::SYS_setsockopt),
            "execve" => Some(libc::SYS_execve),
            "fork" => Some(libc::SYS_fork),
            "accept4" => Some(libc::SYS_accept4),
            "recvmsg" => Some(libc::SYS_recvmsg),
            "sendmsg" => Some(libc::SYS_sendmsg),
            "getsockname" => Some(libc::SYS_getsockname),
            "getpeername" => Some(libc::SYS_getpeername),
            "shutdown" => Some(libc::SYS_shutdown),
            "epoll_create" => Some(libc::SYS_epoll_create),
            "epoll_ctl" => Some(libc::SYS_epoll_ctl),
            "epoll_wait" => Some(libc::SYS_epoll_wait),
            "eventfd2" => Some(libc::SYS_eventfd2),
            "fcntl" => Some(libc::SYS_fcntl),
            _ => None,
        }
    }

    pub async fn apply_current_config(&self) -> Result<()> {
        let allowed = self.build_allowed_syscalls().await;

        info!("Applying seccomp filter with {} allowed syscalls", allowed.len());

        let mut rules = BTreeMap::new();

        for syscall_name in allowed {
            if let Some(syscall_nr) = Self::syscall_name_to_nr(&syscall_name) {
                let always_true = SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Ge,
                    0_u64,
                )?;
                let rule = SeccompRule::new(vec![always_true])?;
                rules.insert(syscall_nr, vec![rule]);
            }
        }

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Errno(1),
            SeccompAction::Allow,
            Self::get_current_arch(),
        )?;

        let bpf_program: BpfProgram = filter.try_into()?;
        seccompiler::apply_filter(&bpf_program)?;

        *self.is_filter_active.write().await = true;
        info!("✅ Seccomp filter applied successfully");

        Ok(())
    }

    pub async fn apply_threat_response(&self, threat_type: &str, _score: Option<f64>) -> Result<()> {
        info!("Applying threat response for: {}", threat_type);
        self.escalate_security_level(SecurityLevel::Paranoid).await?;

        let mut rules = self.temp_rules.write().await;

        match threat_type {
            "reverse_shell" | "crypto_miner" => {
                rules.push(TempBlockRule {
                    syscalls: vec!["execve".to_string(), "fork".to_string(), "clone".to_string()].into_iter().collect(),
                    expires_at: Instant::now() + Duration::from_secs(600),
                    priority: "critical".to_string(),
                });
            }
            "ml_anomaly" => {
                rules.push(TempBlockRule {
                    syscalls: vec!["execve".to_string(), "clone".to_string()].into_iter().collect(),
                    expires_at: Instant::now() + Duration::from_secs(300),
                    priority: "high".to_string(),
                });
            }
            _ => {}
        }

        drop(rules);
        self.apply_current_config().await?;

        Ok(())
    }

    pub async fn escalate_security_level(&self, new_level: SecurityLevel) -> Result<()> {
        let mut level = self.current_level.write().await;
        if *level != new_level {
            info!("Escalating from {:?} to {:?}", *level, new_level);
            *level = new_level;
            drop(level);
            // self.apply_current_config().await?;
        }
        Ok(())
    }

    pub async fn get_current_level(&self) -> SecurityLevel {
        *self.current_level.read().await
    }

    pub async fn get_temp_rules(&self) -> Vec<TempRuleInfo> {
        let rules = self.temp_rules.read().await;
        rules.iter().map(|rule| TempRuleInfo {
            syscalls: rule.syscalls.clone(),
            expires_in: rule.expires_at.saturating_duration_since(Instant::now()).as_secs(),
            priority: rule.priority.clone(),
        }).collect()
    }

    pub async fn add_temp_rule(&self, rule: TempBlockRule) -> Result<()> {
        let mut rules = self.temp_rules.write().await;
        rules.push(rule);
        drop(rules);
        self.apply_current_config().await?;
        Ok(())
    }

    fn start_cleanup_task(&self) {
        let temp_rules = self.temp_rules.clone();
        let _self = self.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let mut rules = temp_rules.write().await;
                let before = rules.len();
                rules.retain(|rule| rule.expires_at > Instant::now());
                if before != rules.len() {
                    info!("Cleaned up {} expired rules", before - rules.len());
                    drop(rules);
                    let _ = _self.apply_current_config().await;
                }
            }
        });
    }
}

impl Clone for DynamicSeccompManager {
    fn clone(&self) -> Self {
        Self {
            current_level: self.current_level.clone(),
            temp_rules: self.temp_rules.clone(),
            is_filter_active: self.is_filter_active.clone(),
        }
    }
}

// pub async fn apply_to_process(&self, pid: libc::pid_t) -> Result<()> {
//     let allowed = self.build_allowed_syscalls().await;
//     let bpf = self.build_bpf_filter(&allowed)?;

//     // Применяем к целевому процессу через prctl
//     unsafe {
//         let ret = libc::prctl(libc::PR_SET_SECCOMP, 2, &bpf.as_ptr(), 0, 0);
//         if ret != 0 {
//             anyhow::bail!("Failed to apply seccomp to process {}: errno {}", pid, *libc::__errno_location());
//         }
//     }

//     Ok(())
// }

// fn build_bpf_filter(&self, allowed: &HashSet<String>) -> Result<BpfProgram> {
//     let mut rules = BTreeMap::new();

//     for syscall_name in allowed {
//         if let Some(syscall_nr) = Self::syscall_name_to_nr(syscall_name) {
//             let always_true = SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ge, 0_u64)?;
//             let rule = SeccompRule::new(vec![always_true])?;
//             rules.insert(syscall_nr, vec![rule]);
//         }
//     }

//     let filter = SeccompFilter::new(rules, SeccompAction::Errno(1), SeccompAction::Allow, Self::get_current_arch())?;
//     let bpf: BpfProgram = filter.try_into()?;

//     Ok(bpf)
// }
