#![allow(dead_code)]

use anyhow::Result;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompFilter,
    SeccompRule,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
    Paranoid,
}

pub struct EnhancedSecuritySystem {
    security_level: Arc<RwLock<SecurityLevel>>,
    active_filters: Arc<RwLock<HashMap<String, SeccompFilter>>>,
    syscall_whitelist: Arc<RwLock<Vec<i64>>>,
    syscall_blacklist: Arc<RwLock<Vec<i64>>>,
}

impl EnhancedSecuritySystem {
    pub async fn new(level: SecurityLevel) -> Result<Self> {
        let system = Self {
            security_level: Arc::new(RwLock::new(level)),
            active_filters: Arc::new(RwLock::new(HashMap::new())),
            syscall_whitelist: Arc::new(RwLock::new(Vec::new())),
            syscall_blacklist: Arc::new(RwLock::new(Vec::new())),
        };

        system.initialize_filters(level).await?;
        
        Ok(system)
    }

    async fn initialize_filters(&self, level: SecurityLevel) -> Result<()> {
        info!("🔧 Инициализация seccomp фильтров для уровня: {:?}", level);

        let mut filters = HashMap::new();

        // Создаем фильтры в зависимости от уровня безопасности
        match level {
            SecurityLevel::Low => {
                info!("✅ Low security level - минимальные ограничения");
                match self.create_low_security_filter() {
                    Ok(filter) => {
                        filters.insert("low_security".to_string(), filter);
                        info!("  📋 Фильтр: low_security (блокирует ptrace, process_vm_*)");
                    }
                    Err(e) => {
                        warn!("⚠️ Не удалось создать low_security фильтр: {}", e);
                    }
                }
            }
            SecurityLevel::Medium => {
                info!("✅ Medium security level - стандартные ограничения");
                match self.create_medium_security_filter() {
                    Ok(filter) => {
                        filters.insert("medium_security".to_string(), filter);
                        info!("  📋 Фильтр: medium_security (блокирует опасные операции)");
                    }
                    Err(e) => {
                        warn!("⚠️ Не удалось создать medium_security фильтр: {}", e);
                    }
                }
            }
            SecurityLevel::High => {
                info!("✅ High security level - строгие ограничения");
                match self.create_high_security_filter() {
                    Ok(filter) => {
                        filters.insert("high_security".to_string(), filter);
                        info!("  📋 Фильтр: high_security (whitelist подход)");
                    }
                    Err(e) => {
                        warn!("⚠️ Не удалось создать high_security фильтр: {}", e);
                    }
                }
            }
            SecurityLevel::Paranoid => {
                info!("✅ Paranoid security level - максимальные ограничения");
                match self.create_paranoid_filter() {
                    Ok(filter) => {
                        filters.insert("paranoid".to_string(), filter);
                        info!("  📋 Фильтр: paranoid (минимальный набор syscalls)");
                    }
                    Err(e) => {
                        warn!("⚠️ Не удалось создать paranoid фильтр: {}", e);
                    }
                }
            }
        }

        // Создаем дополнительные специализированные фильтры
        match self.create_network_filter() {
            Ok(filter) => {
                filters.insert("network_only".to_string(), filter);
                info!("  📋 Фильтр: network_only (только сетевые операции)");
            }
            Err(e) => {
                warn!("⚠️ Не удалось создать network_only фильтр: {}", e);
            }
        }

        match self.create_filesystem_filter() {
            Ok(filter) => {
                filters.insert("filesystem_only".to_string(), filter);
                info!("  📋 Фильтр: filesystem_only (только файловые операции)");
            }
            Err(e) => {
                warn!("⚠️ Не удалось создать filesystem_only фильтр: {}", e);
            }
        }

        let filter_count = filters.len();
        let mut active = self.active_filters.write().await;
        *active = filters;

        info!("✅ Инициализировано {} seccomp фильтров", filter_count);
        Ok(())
    }

    fn create_low_security_filter(&self) -> Result<SeccompFilter> {
        // Базовый фильтр - блокируем только самые опасные syscalls
        let blocked_syscalls = vec![
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
        ];

        let mut filter_map = std::collections::BTreeMap::new();
        
        // Для заблокированных syscalls используем пустой Vec правил
        // Это означает "всегда применять match_action для этого syscall"
        for syscall in blocked_syscalls {
            filter_map.insert(syscall, vec![]);
        }

        // match_action = Errno (блокируем syscalls из списка)
        // mismatch_action = Allow (разрешаем все остальные)
        Ok(SeccompFilter::new(
            filter_map,
            SeccompAction::Allow,  // mismatch_action
            SeccompAction::Errno(libc::EPERM as u32),  // match_action
            std::env::consts::ARCH.try_into()?,
        )?)
    }

    fn create_medium_security_filter(&self) -> Result<SeccompFilter> {
        // Средний уровень - блокируем опасные операции
        let blocked_syscalls = vec![
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_kexec_load,
            libc::SYS_kexec_file_load,
            libc::SYS_reboot,
            libc::SYS_swapon,
            libc::SYS_swapoff,
            libc::SYS_mount,
            libc::SYS_umount2,
        ];

        let mut filter_map = std::collections::BTreeMap::new();
        
        for syscall in blocked_syscalls {
            filter_map.insert(syscall, vec![]);
        }

        Ok(SeccompFilter::new(
            filter_map,
            SeccompAction::Allow,  // mismatch_action - разрешаем все остальные
            SeccompAction::Errno(libc::EPERM as u32),  // match_action - блокируем из списка
            std::env::consts::ARCH.try_into()?,
        )?)
    }

    fn create_high_security_filter(&self) -> Result<SeccompFilter> {
        // Высокий уровень - whitelist подход
        // Эти syscalls будут РАЗРЕШЕНЫ, все остальные - заблокированы
        let allowed_syscalls = vec![
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_open,
            libc::SYS_close,
            libc::SYS_stat,
            libc::SYS_fstat,
            libc::SYS_lstat,
            libc::SYS_poll,
            libc::SYS_lseek,
            libc::SYS_mmap,
            libc::SYS_mprotect,
            libc::SYS_munmap,
            libc::SYS_brk,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_ioctl,
            libc::SYS_pread64,
            libc::SYS_pwrite64,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_access,
            libc::SYS_pipe,
            libc::SYS_select,
            libc::SYS_sched_yield,
            libc::SYS_mremap,
            libc::SYS_msync,
            libc::SYS_mincore,
            libc::SYS_madvise,
            libc::SYS_dup,
            libc::SYS_dup2,
            libc::SYS_nanosleep,
            libc::SYS_getpid,
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_accept,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_setsockopt,
            libc::SYS_getsockopt,
            libc::SYS_clone,
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_execve,
            libc::SYS_exit,
            libc::SYS_wait4,
            libc::SYS_kill,
            libc::SYS_uname,
            libc::SYS_fcntl,
            libc::SYS_flock,
            libc::SYS_fsync,
            libc::SYS_fdatasync,
            libc::SYS_getcwd,
            libc::SYS_chdir,
            libc::SYS_rename,
            libc::SYS_mkdir,
            libc::SYS_rmdir,
            libc::SYS_creat,
            libc::SYS_link,
            libc::SYS_unlink,
            libc::SYS_readlink,
            libc::SYS_chmod,
            libc::SYS_fchmod,
            libc::SYS_chown,
            libc::SYS_fchown,
            libc::SYS_getuid,
            libc::SYS_getgid,
            libc::SYS_geteuid,
            libc::SYS_getegid,
            libc::SYS_getppid,
            libc::SYS_getpgrp,
            libc::SYS_setsid,
            libc::SYS_getgroups,
            libc::SYS_setgroups,
            libc::SYS_getresuid,
            libc::SYS_getresgid,
            libc::SYS_getpgid,
            libc::SYS_getsid,
            libc::SYS_capget,
            libc::SYS_capset,
            libc::SYS_rt_sigpending,
            libc::SYS_rt_sigtimedwait,
            libc::SYS_rt_sigqueueinfo,
            libc::SYS_rt_sigsuspend,
            libc::SYS_sigaltstack,
            libc::SYS_utime,
            libc::SYS_mknod,
            libc::SYS_personality,
            libc::SYS_statfs,
            libc::SYS_fstatfs,
            libc::SYS_getpriority,
            libc::SYS_setpriority,
            libc::SYS_sched_setparam,
            libc::SYS_sched_getparam,
            libc::SYS_sched_setscheduler,
            libc::SYS_sched_getscheduler,
            libc::SYS_sched_get_priority_max,
            libc::SYS_sched_get_priority_min,
            libc::SYS_sched_rr_get_interval,
            libc::SYS_prctl,
            libc::SYS_arch_prctl,
            libc::SYS_setrlimit,
            libc::SYS_sync,
            libc::SYS_gettid,
            libc::SYS_time,
            libc::SYS_futex,
            libc::SYS_sched_setaffinity,
            libc::SYS_sched_getaffinity,
            libc::SYS_set_thread_area,
            libc::SYS_get_thread_area,
            libc::SYS_epoll_create,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_wait,
            libc::SYS_set_tid_address,
            libc::SYS_clock_gettime,
            libc::SYS_clock_getres,
            libc::SYS_clock_nanosleep,
            libc::SYS_exit_group,
            libc::SYS_epoll_pwait,
            libc::SYS_openat,
            libc::SYS_mkdirat,
            libc::SYS_newfstatat,
            libc::SYS_unlinkat,
            libc::SYS_renameat,
            libc::SYS_linkat,
            libc::SYS_symlinkat,
            libc::SYS_readlinkat,
            libc::SYS_fchmodat,
            libc::SYS_faccessat,
            libc::SYS_pselect6,
            libc::SYS_ppoll,
            libc::SYS_set_robust_list,
            libc::SYS_get_robust_list,
            libc::SYS_epoll_pwait,
            libc::SYS_accept4,
            libc::SYS_dup3,
            libc::SYS_pipe2,
            libc::SYS_preadv,
            libc::SYS_pwritev,
            libc::SYS_prlimit64,
            libc::SYS_getrandom,
        ];

        let mut filter_map = std::collections::BTreeMap::new();
        
        // Для разрешенных syscalls создаем правила
        for syscall in allowed_syscalls {
            filter_map.insert(syscall, vec![]);
        }

        // match_action = Allow (разрешаем syscalls из списка)
        // mismatch_action = Errno (блокируем все остальные)
        Ok(SeccompFilter::new(
            filter_map,
            SeccompAction::Errno(libc::EPERM as u32),  // mismatch_action
            SeccompAction::Allow,  // match_action
            std::env::consts::ARCH.try_into()?,
        )?)
    }

    fn create_paranoid_filter(&self) -> Result<SeccompFilter> {
        // Параноидальный режим - минимальный набор syscalls
        let allowed_syscalls = vec![
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_close,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_rt_sigreturn,
        ];

        let mut filter_map = std::collections::BTreeMap::new();
        
        for syscall in allowed_syscalls {
            filter_map.insert(syscall, vec![]);
        }

        Ok(SeccompFilter::new(
            filter_map,
            SeccompAction::Errno(libc::EPERM as u32),  // mismatch_action - блокируем все остальные
            SeccompAction::Allow,  // match_action - разрешаем из списка
            std::env::consts::ARCH.try_into()?,
        )?)
    }

    fn create_network_filter(&self) -> Result<SeccompFilter> {
        // Фильтр для сетевых операций - разрешаем только сетевые syscalls
        let network_syscalls = vec![
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
            libc::SYS_shutdown,
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_setsockopt,
            libc::SYS_getsockopt,
        ];

        let mut filter_map = std::collections::BTreeMap::new();
        
        for syscall in network_syscalls {
            filter_map.insert(syscall, vec![]);
        }

        Ok(SeccompFilter::new(
            filter_map,
            SeccompAction::Errno(libc::EPERM as u32),  // mismatch_action
            SeccompAction::Allow,  // match_action
            std::env::consts::ARCH.try_into()?,
        )?)
    }

    fn create_filesystem_filter(&self) -> Result<SeccompFilter> {
        // Фильтр для файловых операций - разрешаем только файловые syscalls
        let fs_syscalls = vec![
            libc::SYS_open,
            libc::SYS_openat,
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_close,
            libc::SYS_stat,
            libc::SYS_fstat,
            libc::SYS_lstat,
            libc::SYS_access,
            libc::SYS_faccessat,
        ];

        let mut filter_map = std::collections::BTreeMap::new();
        
        for syscall in fs_syscalls {
            filter_map.insert(syscall, vec![]);
        }

        Ok(SeccompFilter::new(
            filter_map,
            SeccompAction::Errno(libc::EPERM as u32),  // mismatch_action
            SeccompAction::Allow,  // match_action
            std::env::consts::ARCH.try_into()?,
        )?)
    }

    fn build_filter(
        &self,
        rules: Vec<(i64, Vec<SeccompRule>)>,
        mismatch_action: SeccompAction,
    ) -> Result<SeccompFilter> {
        let mut filter_map = std::collections::BTreeMap::new();

        for (syscall, rule_vec) in rules {
            filter_map.insert(syscall, rule_vec);
        }

        // match_action - что делать когда syscall совпадает с правилом
        // mismatch_action - что делать когда syscall НЕ совпадает с правилом
        let match_action = SeccompAction::Allow;

        Ok(SeccompFilter::new(
            filter_map,
            mismatch_action,
            match_action,
            std::env::consts::ARCH.try_into()?,
        )?)
    }

    pub async fn apply_filter(&self, filter_name: &str) -> Result<()> {
        let filters = self.active_filters.read().await;
        
        if let Some(filter) = filters.get(filter_name) {
            info!("🔒 Применение seccomp фильтра: {}", filter_name);
            
            // Клонируем фильтр для компиляции (SeccompFilter не реализует Copy)
            // Компилируем фильтр в BPF программу используя into_bpf_program()
            let bpf_program: BpfProgram = match filter.clone().try_into() {
                Ok(prog) => prog,
                Err(e) => {
                    warn!("⚠️ Не удалось скомпилировать фильтр {}: {}", filter_name, e);
                    return Ok(()); // Не фейлим
                }
            };
            
            // ВАЖНО: В контейнере применение seccomp может требовать специальных прав
            // Для production нужно применять через SecurityContext в Kubernetes
            match seccompiler::apply_filter(&bpf_program) {
                Ok(_) => {
                    info!("✅ Seccomp фильтр применен: {}", filter_name);
                }
                Err(e) => {
                    warn!(
                        "⚠️ Не удалось применить seccomp фильтр {} (требуются права): {}",
                        filter_name, e
                    );
                    warn!("💡 Для применения seccomp в production используйте SecurityContext в Kubernetes");
                }
            }
            
            Ok(())
        } else {
            warn!("⚠️ Фильтр {} не найден", filter_name);
            Ok(())
        }
    }

    pub async fn set_security_level(&self, level: SecurityLevel) -> Result<()> {
        info!("🔄 Изменение уровня безопасности на: {:?}", level);
        
        let mut current_level = self.security_level.write().await;
        *current_level = level;
        
        // Переинициализируем фильтры
        drop(current_level);
        self.initialize_filters(level).await?;
        
        Ok(())
    }

    pub async fn get_security_level(&self) -> SecurityLevel {
        *self.security_level.read().await
    }

    pub async fn dynamic_security_adjustment(&self) -> Result<()> {
        let current_level = self.get_security_level().await;
        
        let new_level = match current_level {
            SecurityLevel::Low => SecurityLevel::Medium,
            SecurityLevel::Medium => SecurityLevel::High,
            SecurityLevel::High => SecurityLevel::Paranoid,
            SecurityLevel::Paranoid => SecurityLevel::Paranoid,
        };
        
        if new_level != current_level {
            warn!("⚠️ Автоматическое повышение уровня безопасности: {:?} -> {:?}", 
                  current_level, new_level);
            self.set_security_level(new_level).await?;
        }
        
        Ok(())
    }

    pub async fn add_syscall_to_whitelist(&self, syscall: i64) {
        let mut whitelist = self.syscall_whitelist.write().await;
        if !whitelist.contains(&syscall) {
            whitelist.push(syscall);
            info!("✅ Syscall {} добавлен в whitelist", syscall);
        }
    }

    pub async fn add_syscall_to_blacklist(&self, syscall: i64) {
        let mut blacklist = self.syscall_blacklist.write().await;
        if !blacklist.contains(&syscall) {
            blacklist.push(syscall);
            info!("🚫 Syscall {} добавлен в blacklist", syscall);
        }
    }
    
    pub async fn get_active_filters(&self) -> Vec<String> {
        let filters = self.active_filters.read().await;
        filters.keys().cloned().collect()
    }
    
    pub async fn get_filter_count(&self) -> usize {
        let filters = self.active_filters.read().await;
        filters.len()
    }
}
