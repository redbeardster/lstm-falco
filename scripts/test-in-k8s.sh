#!/bin/bash

# Быстрый тест Enterprise Security Stack в существующем кластере

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🧪 Быстрый тест Enterprise Security Stack${NC}"
echo "=========================================="
echo ""

# Проверка кластера
echo -e "${YELLOW}1️⃣  Проверка кластера...${NC}"
kubectl cluster-info | head -1
kubectl get nodes
echo ""

# Проверка существующих подов
echo -e "${YELLOW}2️⃣  Существующие поды в кластере:${NC}"
kubectl get pods --all-namespaces
echo ""

# Создание тестового пода с нашим приложением
echo -e "${YELLOW}3️⃣  Создание тестового пода...${NC}"

# Сначала соберем образ если его нет
if ! docker images | grep -q "enterprise-security-stack"; then
    echo -e "${YELLOW}Сборка Docker образа...${NC}"
    cargo build --release
    docker build -t enterprise-security-stack:latest .
fi

# Создаем namespace если его нет
kubectl create namespace security-test --dry-run=client -o yaml | kubectl apply -f -

# Создаем тестовый под
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: security-stack-test
  namespace: security-test
  labels:
    app: security-stack-test
spec:
  hostNetwork: true
  hostPID: true
  containers:
    - name: security-stack
      image: enterprise-security-stack:latest
      imagePullPolicy: Never
      securityContext:
        privileged: true
      env:
        - name: RUST_LOG
          value: "enterprise_security=info"
      ports:
        - containerPort: 3000
          name: api
        - containerPort: 8080
          name: falco
        - containerPort: 8081
          name: guardd
      command: ["./enterprise-security-stack"]
EOF

echo -e "${GREEN}✅ Тестовый под создан${NC}"
echo ""

# Ожидание запуска
echo -e "${YELLOW}4️⃣  Ожидание запуска пода (30 секунд)...${NC}"
sleep 5

# Проверка статуса
for i in {1..6}; do
    STATUS=$(kubectl get pod security-stack-test -n security-test -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
    echo -e "   Попытка $i/6: Статус = ${YELLOW}$STATUS${NC}"
    
    if [ "$STATUS" = "Running" ]; then
        echo -e "${GREEN}✅ Под запущен!${NC}"
        break
    fi
    
    if [ $i -eq 6 ]; then
        echo -e "${RED}❌ Под не запустился${NC}"
        echo -e "${YELLOW}Описание пода:${NC}"
        kubectl describe pod security-stack-test -n security-test
        echo ""
        echo -e "${YELLOW}Логи пода:${NC}"
        kubectl logs security-stack-test -n security-test 2>/dev/null || echo "Логи недоступны"
        exit 1
    fi
    
    sleep 5
done
echo ""

# Показываем логи
echo -e "${YELLOW}5️⃣  Логи приложения:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
kubectl logs security-stack-test -n security-test --tail=20
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Port-forward для тестирования
echo -e "${YELLOW}6️⃣  Настройка port-forward для тестирования...${NC}"
kubectl port-forward -n security-test security-stack-test 3000:3000 8080:8080 8081:8081 &
PF_PID=$!

# Ждем пока port-forward установится
sleep 3

# Проверка health
echo -e "${YELLOW}7️⃣  Проверка health endpoint...${NC}"
if curl -s http://localhost:3000/health | jq . 2>/dev/null; then
    echo -e "${GREEN}✅ Health check успешен${NC}"
else
    echo -e "${RED}❌ Health check не прошел${NC}"
fi
echo ""

# Тестирование Guardd webhook
echo -e "${YELLOW}8️⃣  Тестирование Guardd webhook...${NC}"
curl -s -X POST http://localhost:8081/guardd-events \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "event_type": "file_access",
    "pod_name": "test-pod",
    "namespace": "default",
    "container_name": "test",
    "severity": "critical",
    "details": {
      "description": "Test event from K8s",
      "process_name": "test",
      "file_path": "/etc/shadow"
    }
  }' && echo -e "\n${GREEN}✅ Событие отправлено${NC}" || echo -e "\n${RED}❌ Ошибка отправки${NC}"
echo ""

# Проверка событий
echo -e "${YELLOW}9️⃣  Проверка полученных событий...${NC}"
sleep 2
curl -s http://localhost:3000/api/guardd/events | jq '.total' && echo -e "${GREEN}✅ События получены${NC}"
echo ""

# Показываем логи после теста
echo -e "${YELLOW}🔟 Логи после теста:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
kubectl logs security-stack-test -n security-test --tail=10
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Останавливаем port-forward
kill $PF_PID 2>/dev/null || true

# Итоги
echo -e "${GREEN}✅ Тестирование завершено!${NC}"
echo "=========================================="
echo ""
echo -e "${BLUE}📝 Полезные команды:${NC}"
echo ""
echo -e "${YELLOW}Просмотр логов:${NC}"
echo "  kubectl logs -n security-test security-stack-test -f"
echo ""
echo -e "${YELLOW}Подключение к поду:${NC}"
echo "  kubectl exec -it -n security-test security-stack-test -- /bin/bash"
echo ""
echo -e "${YELLOW}Port-forward для доступа:${NC}"
echo "  kubectl port-forward -n security-test security-stack-test 3000:3000 8080:8080 8081:8081"
echo ""
echo -e "${YELLOW}Удаление тестового пода:${NC}"
echo "  kubectl delete pod security-stack-test -n security-test"
echo "  kubectl delete namespace security-test"
echo ""
echo -e "${YELLOW}Полное развертывание:${NC}"
echo "  ./scripts/deploy-to-k8s.sh"
echo ""
