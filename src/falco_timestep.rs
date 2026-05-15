//! Shared 8-D feature vector extraction for Falco events (LSTM input).

use crate::falco_integration::FalcoEvent;

pub const LSTM_TIMESTEP_SIZE: usize = 8;

pub fn falco_event_to_lstm_timestep(event: &FalcoEvent) -> Vec<f64> {
    let mut features = vec![0.0; LSTM_TIMESTEP_SIZE];

    features[0] = match event.priority.as_str() {
        "Emergency" => 5.0,
        "Alert" => 4.0,
        "Critical" => 4.0,
        "Error" => 3.0,
        "Warning" => 2.0,
        "Informational" => 1.0,
        _ => 1.0,
    };

    features[1] = if event.container_id.is_some() { 1.0 } else { 0.0 };
    features[2] = if event.process_pid.is_some() { 1.0 } else { 0.0 };

    features[3] = match event.syscall.as_deref() {
        Some("execve") => 1.0,
        Some("fork") => 0.8,
        Some("clone") => 0.7,
        Some("connect") => 0.6,
        Some("socket") => 0.5,
        Some("open") => 0.3,
        Some("read") => 0.2,
        Some("write") => 0.2,
        _ => 0.0,
    };

    features[4] = (event.output.len() as f64 / 200.0).min(1.0);
    features[5] = if event.tags.is_some() { 1.0 } else { 0.0 };
    features[6] = if event.source.is_some() { 1.0 } else { 0.0 };
    features[7] = if event.output_fields.is_some() { 1.0 } else { 0.0 };

    features
}
