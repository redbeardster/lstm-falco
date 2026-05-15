// examples/training_scenarios.rs

use std::fs::OpenOptions;
use std::io::Write;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let webhook_url = "http://localhost:8080/falco-events";
    let client = reqwest::Client::new();
    let mut collected_features = Vec::new();
    let mut collected_labels = Vec::new();

    println!("🚀 Training Scenarios Generator\n");

    // 1. Сценарий: Нормальная нагрузка (1000 событий)
    println!("📊 Sending normal workload...");
    for i in 0..1000 {
        let features = vec![1.0, 0.0, 0.0, 0.1, 0.0];
        let label = 0.0;

        let event = json!({
            "time": chrono::Utc::now().to_rfc3339(),
            "rule": format!("Normal Operation {}", i),
            "priority": "Info",
            "output": "Normal system operation",
            "source": "syscall",
            "tags": ["normal"],
            "output_fields": {},
            "hostname": "localhost",
            "syscall": "read"
        });

        let _ = client.post(webhook_url).json(&event).send().await;
        collected_features.push(features);
        collected_labels.push(label);

        if i % 100 == 0 {
            println!("  Sent {}/1000 events", i);
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    // 2. Сценарий: Атаки (8 событий)
    println!("\n🚨 Sending attack scenarios...");
    let attacks = vec![
        (vec![5.0, 1.0, 1.0, 1.0, 1.0], "Reverse Shell"),
        (vec![4.0, 1.0, 0.0, 0.9, 1.0], "Cryptominer"),
        (vec![4.0, 0.0, 0.0, 0.8, 1.0], "Data Exfiltration"),
        (vec![3.0, 1.0, 1.0, 0.7, 0.0], "Privilege Escalation"),
    ];

    for _ in 0..2 {
        for (features, attack_type) in &attacks {
            let event = json!({
                "time": chrono::Utc::now().to_rfc3339(),
                "rule": attack_type,
                "priority": "Critical",
                "output": format!("{} detected!", attack_type),
                "source": "syscall",
                "tags": ["attack", attack_type],
                "output_fields": {},
                "hostname": "localhost",
                "syscall": "execve"
            });

            let _ = client.post(webhook_url).json(&event).send().await;
            collected_features.push(features.clone());
            collected_labels.push(1.0);

            println!("  Sent attack: {}", attack_type);
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    // 3. Сохраняем данные для обучения
    println!("\n💾 Saving training data...");

    let training_data: Vec<serde_json::Value> = collected_features.iter()
        .zip(collected_labels.iter())
        .map(|(f, &l)| json!({
            "features": f,
            "label": l
        }))
        .collect();

    let json_data = serde_json::to_string_pretty(&training_data)?;
    std::fs::write("data/training_data.json", json_data)?;

    println!("✅ Training data saved: {} samples", training_data.len());
    println!("   Normal: {} (label=0)", collected_labels.iter().filter(|&&l| l == 0.0).count());
    println!("   Anomalies: {} (label=1)", collected_labels.iter().filter(|&&l| l == 1.0).count());

    Ok(())
}
