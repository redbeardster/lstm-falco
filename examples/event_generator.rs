// examples/event_generator.rs

use chrono::Utc;
use rand::Rng;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone)]
struct EventTemplate {
    rule: String,
    priority: String,
    output: String,
    tags: Vec<String>,
    is_anomaly: bool,
}

impl EventTemplate {
    fn normal() -> Vec<Self> {
        vec![
            Self {
                rule: "File Read".to_string(),
                priority: "Info".to_string(),
                output: "Process read file".to_string(),
                tags: vec!["file".to_string(), "read".to_string()],
                is_anomaly: false,
            },
            Self {
                rule: "Network Connection".to_string(),
                priority: "Info".to_string(),
                output: "Established network connection".to_string(),
                tags: vec!["network".to_string()],
                is_anomaly: false,
            },
            Self {
                rule: "Process Execution".to_string(),
                priority: "Info".to_string(),
                output: "New process executed".to_string(),
                tags: vec!["process".to_string()],
                is_anomaly: false,
            },
        ]
    }

    fn anomaly() -> Vec<Self> {
        vec![
            Self {
                rule: "Reverse Shell Detected".to_string(),
                priority: "Critical".to_string(),
                output: "Reverse shell connection attempt".to_string(),
                tags: vec![
                    "shell".to_string(),
                    "reverse".to_string(),
                    "attack".to_string(),
                ],
                is_anomaly: true,
            },
            Self {
                rule: "Cryptominer Detected".to_string(),
                priority: "Critical".to_string(),
                output: "Cryptocurrency miner process detected".to_string(),
                tags: vec![
                    "crypto".to_string(),
                    "miner".to_string(),
                    "attack".to_string(),
                ],
                is_anomaly: true,
            },
            Self {
                rule: "Privilege Escalation".to_string(),
                priority: "Error".to_string(),
                output: "Suspicious privilege escalation attempt".to_string(),
                tags: vec!["privilege".to_string(), "escalation".to_string()],
                is_anomaly: true,
            },
            Self {
                rule: "Lateral Movement".to_string(),
                priority: "Warning".to_string(),
                output: "SSH connection from container".to_string(),
                tags: vec!["lateral".to_string(), "movement".to_string()],
                is_anomaly: true,
            },
            Self {
                rule: "Data Exfiltration".to_string(),
                priority: "Critical".to_string(),
                output: "Large outbound data transfer".to_string(),
                tags: vec!["exfiltration".to_string(), "data".to_string()],
                is_anomaly: true,
            },
        ]
    }
}

struct EventGenerator {
    client: Client,
    webhook_url: String,
    normal_events: Vec<EventTemplate>,
    anomaly_events: Vec<EventTemplate>,
    anomaly_ratio: f64, // Процент аномалий (0.0 - 1.0)
    rng: rand::rngs::ThreadRng,
}

impl EventGenerator {
    fn new(webhook_url: &str, anomaly_ratio: f64) -> Self {
        Self {
            client: Client::new(),
            webhook_url: webhook_url.to_string(),
            normal_events: EventTemplate::normal(),
            anomaly_events: EventTemplate::anomaly(),
            anomaly_ratio,
            rng: rand::thread_rng(),
        }
    }

    fn generate_event(&mut self) -> EventTemplate {
        let is_anomaly = self.rng.gen_bool(self.anomaly_ratio);
        let events = if is_anomaly {
            &self.anomaly_events
        } else {
            &self.normal_events
        };
        let idx = self.rng.gen_range(0..events.len());
        events[idx].clone()
    }

    fn generate_falco_json(&mut self) -> serde_json::Value {
        let template = self.generate_event();
        let pid = self.rng.gen_range(1000..9999);

        json!({
            "time": Utc::now().to_rfc3339(),
            "rule": template.rule,
            "priority": template.priority,
            "output": format!("{} (proc=process_{} user=root)", template.output, pid),
            "source": "syscall",
            "tags": template.tags,
            "output_fields": {
                "proc.pid": pid,
                "proc.name": format!("process_{}", pid),
                "user.name": "root"
            },
            "hostname": "generated-host",
            "container_id": if self.rng.gen_bool(0.3) { Some("container-123") } else { None },
            "process_pid": pid,
            "syscall": match template.rule.as_str() {
                "File Read" => Some("open"),
                "Network Connection" => Some("connect"),
                "Process Execution" => Some("execve"),
                "Reverse Shell Detected" => Some("execve"),
                "Cryptominer Detected" => Some("execve"),
                _ => Some("unknown"),
            }
        })
    }

    async fn send_event(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let event = self.generate_falco_json();
        let response = self
            .client
            .post(&self.webhook_url)
            .json(&event)
            .send()
            .await?;

        if response.status().is_success() {
            let is_anomaly = event["priority"].as_str().unwrap_or("") == "Critical";
            println!(
                "✅ Event sent: {} [{}] {}",
                event["rule"],
                event["priority"],
                if is_anomaly { "⚠️ ANOMALY" } else { "" }
            );
        } else {
            println!("❌ Failed to send event: {}", response.status());
        }
        Ok(())
    }

    async fn run(&mut self, events_per_second: u64, duration_secs: Option<u64>) {
        let interval = Duration::from_secs_f64(1.0 / events_per_second as f64);
        let start = tokio::time::Instant::now();
        let mut event_count = 0;

        println!("🚀 Starting event generator");
        println!("   Webhook: {}", self.webhook_url);
        println!("   Rate: {} events/sec", events_per_second);
        println!("   Anomaly ratio: {}%", self.anomaly_ratio * 100.0);
        println!();

        loop {
            if let Some(duration) = duration_secs {
                if start.elapsed() >= Duration::from_secs(duration) {
                    break;
                }
            }

            if let Err(e) = self.send_event().await {
                eprintln!("Error: {}", e);
            }

            event_count += 1;
            if event_count % 100 == 0 {
                println!("📊 Generated {} events so far", event_count);
            }

            sleep(interval).await;
        }

        println!("\n✅ Generation complete! Total events: {}", event_count);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let webhook_url = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("http://localhost:8080/falco-events");

    let anomaly_ratio = args
        .get(2)
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.1); // 10% аномалий по умолчанию

    let rate = args.get(3).and_then(|s| s.parse::<u64>().ok()).unwrap_or(5); // 5 событий в секунду

    let duration = args.get(4).and_then(|s| s.parse::<u64>().ok());

    println!("🎯 Falco Event Generator");
    println!("========================\n");

    let mut generator = EventGenerator::new(webhook_url, anomaly_ratio);
    generator.run(rate, duration).await;

    Ok(())
}
