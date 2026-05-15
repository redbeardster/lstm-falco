#!/bin/bash

# Скрипт для тестирования обнаружения и реагирования на угрозы

set -e

API_URL="http://localhost:3000"
FALCO_WEBHOOK="http://localhost:8080/falco-events"

echo "🧪 Тестирование Enterprise Security Stack"
echo "=========================================="
echo ""

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Функция для отправки Falco события
send_falco_event() {
    local rule=$1
    local priority=$2
    local output=$3
    local tags=$4
    
    echo -e "${YELLOW}📤 Отправка Falco события: $rule${NC}"
    
    curl -s -X POST "$FALCO_WEBHOOK" \
        -H "Content-Type: application/json" \
        -d "{
            \"time\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
            \"rule\": \"$rule\",
            \"priority\": \"$priority\",
            \"output\": \"$output\",
            \"source\": \"syscall\",
            \"tags\": $tags,
            \"output_fields\": {
                \"fd.sip\": \"192.168.1.100\",
                \"proc.name\": \"suspicious_process\",
                \"container.id\": \"test-container-123\"
            },
            \"hostname\": \"test-node-01\",
            \"container_id\": \"test-container-123\",
            \"process_pid\": 12345,
            \"syscall\": \"execve\"
        }" > /dev/null
    
    echo -e "${GREEN}✅ Событие отправлено${NC}"
    sleep 1
}

# Проверка доступности API
echo "1️⃣  Проверка доступности API..."
if curl -s "$API_URL/health" > /dev/null; then
    echo -e "${GREEN}✅ API доступен${NC}"
else
    echo -e "${RED}❌ API недоступен. Запустите приложение: sudo ./target/release/enterprise-security-stack${NC}"
    exit 1
fi
echo ""

# Получение начального статуса
echo "2️⃣  Получение начального статуса безопасности..."
INITIAL_STATUS=$(curl -s "$API_URL/api/security/status")
echo "$INITIAL_STATUS" | jq '.'
echo ""

# Тест 1: Bruteforce атака
echo "3️⃣  Тест 1: Симуляция Bruteforce атаки"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
send_falco_event \
    "Multiple Failed Login Attempts" \
    "Critical" \
    "Detected 15 failed login attempts from IP 192.168.1.100 in 60 seconds" \
    "[\"bruteforce\", \"authentication\"]"

echo "Ожидаемые действия:"
echo "  - Включение rate limiting"
echo "  - Блокировка IP 192.168.1.100"
echo "  - Уведомление администратора"
echo ""
sleep 2

# Тест 2: Lateral Movement
echo "4️⃣  Тест 2: Симуляция Lateral Movement"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
send_falco_event \
    "Suspicious Process Spawning Across Multiple Hosts" \
    "Alert" \
    "Process suspicious_process spawned on 4 different hosts in 5 minutes" \
    "[\"lateral_movement\", \"privilege_escalation\"]"

echo "Ожидаемые действия:"
echo "  - Изоляция скомпрометированных подов"
echo "  - Создание снапшотов для форензики"
echo "  - Усиление мониторинга"
echo ""
sleep 2

# Тест 3: Data Exfiltration
echo "5️⃣  Тест 3: Симуляция Data Exfiltration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
send_falco_event \
    "Large Outbound Data Transfer" \
    "Emergency" \
    "Detected 500MB outbound transfer to unknown IP 203.0.113.42" \
    "[\"data_exfiltration\", \"network_anomaly\"]"

echo "Ожидаемые действия:"
echo "  - Блокировка исходящего трафика"
echo "  - Изоляция контейнера test-container-123"
echo "  - Создание снапшота"
echo "  - Немедленное уведомление"
echo ""
sleep 2

# Тест 4: Подозрительный execve
echo "6️⃣  Тест 4: Симуляция подозрительного execve"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
send_falco_event \
    "Shell Spawned in Container" \
    "Warning" \
    "Shell /bin/bash spawned in container test-container-123" \
    "[\"command_execution\", \"container_escape\"]"

echo "Ожидаемые действия:"
echo "  - Логирование подозрительной активности"
echo "  - Анализ контекста выполнения"
echo ""
sleep 2

# Тест 5: Множественные события для AI предсказания
echo "7️⃣  Тест 5: Генерация множественных событий для AI анализа"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
for i in {1..10}; do
    send_falco_event \
        "Failed Login Attempt $i" \
        "Warning" \
        "Failed login attempt #$i from 192.168.1.100" \
        "[\"authentication\"]"
done
echo ""

# Проверка предсказаний угроз
echo "8️⃣  Получение предсказаний угроз от AI..."
PREDICTIONS=$(curl -s "$API_URL/api/security/predictions")
echo "$PREDICTIONS" | jq '.'
echo ""

# Проверка истории инцидентов
echo "9️⃣  Получение истории инцидентов..."
INCIDENTS=$(curl -s "$API_URL/api/security/incidents")
echo "$INCIDENTS" | jq '.'
echo ""

# Получение финального статуса
echo "🔟 Получение финального статуса безопасности..."
FINAL_STATUS=$(curl -s "$API_URL/api/security/status")
echo "$FINAL_STATUS" | jq '.'
echo ""

# Сравнение статусов
echo "📊 Сравнение статусов:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
INITIAL_THREATS=$(echo "$INITIAL_STATUS" | jq -r '.active_threats')
FINAL_THREATS=$(echo "$FINAL_STATUS" | jq -r '.active_threats')
INITIAL_RISK=$(echo "$INITIAL_STATUS" | jq -r '.risk_score')
FINAL_RISK=$(echo "$FINAL_STATUS" | jq -r '.risk_score')

echo "Активные угрозы: $INITIAL_THREATS → $FINAL_THREATS"
echo "Risk Score: $INITIAL_RISK → $FINAL_RISK"
echo ""

# Тест ручного реагирования
echo "1️⃣1️⃣  Тест ручного реагирования..."
MANUAL_RESPONSE=$(curl -s -X POST "$API_URL/api/security/respond" \
    -H "Content-Type: application/json" \
    -d '{
        "threat_type": "bruteforce",
        "target": "test-pod-manual"
    }')
echo "$MANUAL_RESPONSE" | jq '.'
echo ""

# Итоги
echo "✅ Тестирование завершено!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📝 Резюме:"
echo "  - Отправлено Falco событий: 14"
echo "  - Типы угроз: Bruteforce, Lateral Movement, Data Exfiltration"
echo "  - Финальный risk score: $FINAL_RISK"
echo "  - Активные угрозы: $FINAL_THREATS"
echo ""
echo "💡 Проверьте логи приложения для деталей обработки:"
echo "   sudo journalctl -u enterprise-security-stack -f"
echo ""
echo "🔍 Для просмотра всех инцидентов:"
echo "   curl http://localhost:3000/api/security/incidents | jq"
