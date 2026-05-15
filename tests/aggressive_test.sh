#!/bin/bash
# aggressive_test.sh - пытаемся вызвать краш или панику

echo "💣 АГРЕССИВНЫЙ ТЕСТ (попытка краша)"

# 1. Отправляем 10 разных событий с задержкой 0.001 секунды (1000 событий/сек)
for i in {1..100}; do
  curl -s -X POST http://localhost:3000/falco-events \
    -H "Content-Type: application/json" \
    -d "{\"rule\": \"test$i\", \"output\": \"flood\", \"priority\": \"Warning\"}" &
done

# 2. Параллельно отправляем запрос на /health
for i in {1..20}; do
  curl -s http://localhost:3000/health > /dev/null &
done

wait

# 3. Проверяем, жив ли процесс
if pgrep -f "enterprise-security-stack" > /dev/null; then
  echo "СЕРВИС ЖИВ: Агрессивный тест не вызвал паники"
else
  echo "СЕРВИС УПАЛ: Ваш код не выдержал нагрузки"
fi
