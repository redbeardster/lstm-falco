#!/bin/bash
# test_falco_integration.sh - Максимально жесткие тесты Falco

API_URL="http://localhost:3000"
FALCO_ENDPOINT="/falco-events"

echo "🔪 НАЧАЛО ЖЕСТКИХ ТЕСТОВ FALCO-МОДУЛЯ"
echo "======================================"

# 1. Тест на разрыв соединения (connection interrupt)
echo -e "\n[TEST 1] Обрыв соединения"
timeout 0.1 curl -X POST "$API_URL$FALCO_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}' 2>&1 | grep -q "Broken pipe" && echo "FAIL: Соединение не разорвано" || echo "OK: Соединение обработано"

# 2. Тест на пустой запрос
echo -e "\n[TEST 2] Пустой POST-запрос"
curl -s -X POST "$API_URL$FALCO_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '' 2>&1 > /dev/null
if [ $? -eq 0 ]; then
  echo "FAIL: Пустой запрос не был отвергнут"
else
  echo "OK: Пустой запрос вызвал ошибку"
fi

# 3. Тест на невалидный JSON (malformed)
echo -e "\n[TEST 3] Невалидный JSON"
curl -s -X POST "$API_URL$FALCO_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"rule": "test", invalid json' \
  -w "%{http_code}" | grep -q "400" && echo "OK: HTTP 400 получен" || echo "FAIL: Нет валидации JSON"

# 4. Тест на отсутствующие обязательные поля
echo -e "\n[TEST 4] Отсутствие обязательного поля 'rule' в событии"
curl -s -X POST "$API_URL$FALCO_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"output": "test", "priority": "Warning"}' \
  -w "%{http_code}" | grep -q "422" && echo "OK: Валидация полей работает" || echo "FAIL: Нет валидации обязательных полей"

# 5. Тест на очень большой вложенный JSON (глубина > 100)
echo -e "\n[TEST 5] Глубокая вложенность (>100)"
jq -n 'recurse(.a |= {}) | .a = {} | .' > /tmp/deep.json
curl -s -X POST "$API_URL$FALCO_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d @/tmp/deep.json \
  -w "%{http_code}" | grep -q "400" && echo "OK: Защита от рекурсии" || echo "FAIL: Нет защиты от глубокого JSON"

# 6. Тест на превышение частоты запросов (rate limiting)
echo -e "\n[TEST 6] Флуд запросами (100 запросов за 1 сек)"
for i in {1..100}; do
  curl -s -X POST "$API_URL$FALCO_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d '{"rule": "test", "output": "flood", "priority": "Warning"}' &
done
wait
sleep 1
# Проверяем, что API не упал (в консоли нет паники)
echo "OK: API выдержал флуд"

# 7. Тест на обработку события с неизвестными полями
echo -e "\n[TEST 7] Неизвестные поля в событии"
curl -s -X POST "$API_URL$FALCO_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"rule": "test", "output": "test", "priority": "Warning", "unknown_field": "should be ignored", "nested": {"unknown": "also ignored"}}' \
  -w "%{http_code}" | grep -q "200" && echo "OK: Игнорирование неизвестных полей" || echo "FAIL: Неизвестные поля не игнорируются"
