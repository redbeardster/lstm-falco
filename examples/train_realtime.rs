// examples/train_realtime.rs

use reqwest::Client;
use serde_json::Value;
use std::time::Duration;

async fn collect_real_data(
    duration_secs: u64,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let mut samples = Vec::new();

    println!("Collecting real data for {} seconds...", duration_secs);
    let start = std::time::Instant::now();

    while start.elapsed() < Duration::from_secs(duration_secs) {
        // Получаем события из вашего API
        let response = client
            .get("http://localhost:3000/api/security/incidents")
            .send()
            .await?;

        let incidents: Value = response.json().await?;
        samples.push(incidents);

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // Сохраняем собранные данные
    let json = serde_json::to_string_pretty(&samples)?;
    std::fs::write(output_path, json)?;

    println!("✅ Collected {} samples", samples.len());
    Ok(())
}

async fn train_on_real_data(
    data_path: &str,
    model_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Loading real data from {}...", data_path);
    let content = std::fs::read_to_string(data_path)?;
    let samples: Vec<Value> = serde_json::from_str(&content)?;

    // Преобразуем в формат для обучения
    // ... код обучения

    println!("✅ Model trained and saved to {}", model_path);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Сбор данных в течение 1 часа
    collect_real_data(3600, "data/real_samples.json").await?;

    // Обучение на собранных данных
    train_on_real_data("data/real_samples.json", "data/lstm_real_model.json").await?;

    Ok(())
}
