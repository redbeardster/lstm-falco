// Generates synthetic Falco webhook traffic and writes unified 8-D training_data.json.

use serde::{Deserialize, Serialize};
use serde_json::json;

/// Mirrors `FalcoEvent` / `falco_event_to_lstm_timestep` in the main binary (keep in sync).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FalcoEvent {
    time: chrono::DateTime<chrono::Utc>,
    rule: String,
    priority: String,
    output: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    output_fields: Option<serde_json::Value>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    container_id: Option<String>,
    #[serde(default)]
    process_pid: Option<u32>,
    #[serde(default)]
    syscall: Option<String>,
}

fn falco_event_to_lstm_timestep(event: &FalcoEvent) -> Vec<f64> {
    let mut features = vec![0.0; 8];

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

fn make_event(
    rule: &str,
    priority: &str,
    output: &str,
    syscall: &str,
    tags: Vec<&str>,
) -> FalcoEvent {
    FalcoEvent {
        time: chrono::Utc::now(),
        rule: rule.to_string(),
        priority: priority.to_string(),
        output: output.to_string(),
        source: Some("syscall".to_string()),
        tags: Some(tags.into_iter().map(|t| t.to_string()).collect()),
        output_fields: Some(serde_json::json!({})),
        hostname: Some("localhost".to_string()),
        container_id: None,
        process_pid: Some(1234),
        syscall: Some(syscall.to_string()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let webhook_url = "http://localhost:8080/falco-events";
    let client = reqwest::Client::new();
    let mut training_rows = Vec::new();

    println!("Training Scenarios Generator (8-D LSTM timesteps)\n");

    println!("Sending normal workload...");
    for i in 0..1000 {
        let event = make_event(
            &format!("Normal Operation {}", i),
            "Informational",
            "Normal system operation",
            "read",
            vec!["normal"],
        );

        let _ = client
            .post(webhook_url)
            .json(&event)
            .send()
            .await;

        training_rows.push(json!({
            "timestep": falco_event_to_lstm_timestep(&event),
            "label": 0.0,
            "source": "synthetic",
            "rule": event.rule,
        }));

        if i % 100 == 0 {
            println!("  Sent {}/1000 events", i);
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    println!("\nSending attack scenarios...");
    let attacks = [
        ("Reverse Shell", "Critical", "execve", vec!["attack", "shell"]),
        ("Cryptominer", "Critical", "execve", vec!["attack", "miner"]),
        ("Data Exfiltration", "Critical", "connect", vec!["attack", "exfil"]),
        (
            "Privilege Escalation",
            "Error",
            "execve",
            vec!["attack", "privilege"],
        ),
    ];

    for _ in 0..2 {
        for (rule, priority, syscall, tags) in &attacks {
            let event = make_event(
                rule,
                priority,
                &format!("{rule} detected!"),
                syscall,
                tags.iter().copied().collect(),
            );

            let _ = client.post(webhook_url).json(&event).send().await;

            training_rows.push(json!({
                "timestep": falco_event_to_lstm_timestep(&event),
                "label": 1.0,
                "source": "synthetic",
                "rule": rule,
            }));

            println!("  Sent attack: {}", rule);
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    std::fs::create_dir_all("data")?;
    let json_data = serde_json::to_string_pretty(&training_rows)?;
    std::fs::write("data/training_data.json", json_data)?;

    let anomalies = training_rows
        .iter()
        .filter(|r| r["label"].as_f64().unwrap_or(0.0) > 0.5)
        .count();

    println!("\nTraining data saved: {} samples", training_rows.len());
    println!("  Normal: {}", training_rows.len() - anomalies);
    println!("  Anomalies: {}", anomalies);
    println!("  Format: 8-D timestep + label + source + rule");

    Ok(())
}
