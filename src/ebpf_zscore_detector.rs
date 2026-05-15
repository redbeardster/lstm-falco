//! Z-score anomaly detection on eBPF syscall duration baselines.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
struct BaselineStats {
    mean_duration: f64,
    std_dev: f64,
    mean_frequency: f64,
    sample_count: u64,
}

#[derive(Debug, Clone)]
pub struct SyscallDurationThresholds {
    pub duration_multiplier: f64,
    pub frequency_threshold: f64,
    pub error_rate_threshold: f64,
}

impl Default for SyscallDurationThresholds {
    fn default() -> Self {
        Self {
            duration_multiplier: 3.0,
            frequency_threshold: 1000.0,
            error_rate_threshold: 0.5,
        }
    }
}

/// Online z-score detector for syscall duration relative to per-syscall baselines.
pub struct SyscallDurationZScoreDetector {
    baseline: Arc<RwLock<HashMap<u32, BaselineStats>>>,
    thresholds: SyscallDurationThresholds,
}

impl SyscallDurationZScoreDetector {
    pub fn new() -> Self {
        Self {
            baseline: Arc::new(RwLock::new(HashMap::new())),
            thresholds: SyscallDurationThresholds::default(),
        }
    }

    pub async fn is_anomaly(&self, syscall_nr: u32, duration_ns: u64) -> bool {
        let mut baseline = self.baseline.write().await;
        let stats = baseline.entry(syscall_nr).or_insert(BaselineStats {
            mean_duration: duration_ns as f64,
            std_dev: 0.0,
            mean_frequency: 0.0,
            sample_count: 1,
        });

        let alpha = 0.1;
        stats.mean_duration =
            alpha * duration_ns as f64 + (1.0 - alpha) * stats.mean_duration;
        stats.sample_count += 1;

        if stats.std_dev > 0.0 {
            let z_score = (duration_ns as f64 - stats.mean_duration).abs() / stats.std_dev;
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

        let old_mean = stats.mean_duration;
        stats.mean_duration = (stats.mean_duration * stats.sample_count as f64 + duration as f64)
            / (stats.sample_count + 1) as f64;

        let variance = (stats.std_dev * stats.std_dev) * stats.sample_count as f64
            + (duration as f64 - old_mean) * (duration as f64 - stats.mean_duration);
        stats.std_dev = (variance / (stats.sample_count + 1) as f64).sqrt();
        stats.sample_count += 1;
    }
}

impl Default for SyscallDurationZScoreDetector {
    fn default() -> Self {
        Self::new()
    }
}
