#!/bin/bash

# Быстрый тест в Kubernetes без privileged режима

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🚀 Быстрый тест Enterprise Security Stack в K8s${NC}"
echo "=================================================="
echo ""

# 1. Проверка кластера
echo -e "${YELLOW}1. Проверка кластера...${NC}"
kubectl cluster-info | head -1
echo ""

# 2. Сборка образа
echo -e "${YELLOW}2. Проверка Docker образа...${NC}"
if ! docker images | grep -q "enterprise-security-stack.*latest"; then
    echo -e "${YELLOW}   Образ не найден, выполняю сборку...${NC}"
    cargo build --release
    docker build -t enterprise-security-stack:latest .
    echo -e "${GREEN}   ✅ Образ создан${NC}"
else
    echo -e "${GREEN}   ✅ Образ уже существует${NC}"
fi
echo ""

# 3. Загрузка образа в кластер (для minikube/kind)
echo -e "${YELLOW}3. Загрузка образа в кластер...${NC}"
if command -v minikube &> /dev/null && minikube status &> /dev/null 2>&1; then
    echo -e "${YELLOW}   Обнаружен Minikube...${NC}"
    minikube image load enterprise-security-stack:latest
    echo -e "${GREEN}   ✅ Образ загружен в Minikube${NC}"
elif command -v kind &> /dev/null && kind get clusters 2>/dev/null | grep -q .; then
    CLUSTER_NAME=$(kind get clusters | head -1)
    echo -e "${YELLOW}   Обнаружен Kind (кластер: $CLUSTER_NAME)...${NC}"
    kind load docker-image enterprise-security-stack:latest --name "$CLUSTER_NAME"
    echo -e "${GREEN}   ✅ Образ загружен в Kind${NC}"
else
    echo -e "${YELLOW}   ⚠️  Стандартный кластер, образ должен быть доступен локально${NC}"
fi
echo ""

# 4. Развертывание
echo -e "${YELLOW}4. Развертывание тестового пода...${NC}"
kubectl apply -f k8s/simple-test-pod.yaml
echo -e "${GREEN}   ✅ Манифесты применены${NC}"
echo ""

# 5. Ожидание готовности
echo -e "${YELLOW}5. Ожидание готовности пода...${NC}"
echo -e "${YELLOW}   Это может занять до 60 секунд...${NC}"

for i in {1..12}; do
    STATUS=$(kubectl get pod security-stack-test -n security-test -o jsonpath='{.status.phase}' 2>/dev/null || echo "Pending")
    READY=$(kubectl get pod security-stack-test -n security-test -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "False")
    
    echo -e "   Попытка $i/12: Статус=${YELLOW}$STATUS${NC}, Ready=${YELLOW}$READY${NC}"
    
    if [ "$STATUS" = "Running" ] && [ "$READY" = "True" ]; then
        echo -e "${GREEN}   ✅ Под готов!${NC}"
        break
    fi
    
    if [ $i -eq 12 ]; then
        echo -e "${RED}   ❌ Под не стал готовым за 60 секунд${NC}"
        echo ""
        echo -e "${YELLOW}   Описание пода:${NC}"
        kubectl describe pod security-stack-test -n security-test
        echo ""
        echo -e "${YELLOW}   Логи пода:${NC}"
        kubectl logs security-stack-test -n security-test 2>/dev/null || echo "   Логи недоступны"
        echo ""
        echo -e "${RED}   Для удаления: kubectl delete -f k8s/simple-test-pod.yaml${NC}"
        exit 1
    fi
    
    sleep 5
done
echo ""

# 6. Показываем информацию
echo -e "${YELLOW}6. Информация о развертывании:${NC}"
echo ""
kubectl get pods -n security-test -o wide
echo ""
kubectl get svc -n security-test
echo ""

# 7. Логи
echo -e "${YELLOW}7. Логи приложения (последние 15 строк):${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
kubectl logs security-stack-test -n security-test --tail=15 2>/dev/null || echo "Логи недоступны"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 8. Получаем NodePort
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
API_PORT=$(kubectl get svc security-stack-test -n security-test -o jsonpath='{.spec.ports[?(@.name=="api")].nodePort}')
GUARDD_PORT=$(kubectl get svc security-stack-test -n security-test -o jsonpath='{.spec.ports[?(@.name=="guardd")].nodePort}')

echo -e "${GREEN}✅ Развертывание завершено!${NC}"
echo "=================================================="
echo ""
echo -e "${BLUE}📝 Доступ к сервисам:${NC}"
echo ""
echo -e "${YELLOW}API Endpoint:${NC}"
echo "  http://${NODE_IP}:${API_PORT}"
echo ""
echo -e "${YELLOW}Guardd Webhook:${NC}"
echo "  http://${NODE_IP}:${GUARDD_PORT}"
echo ""

# 9. Тестирование
echo -e "${YELLOW}8. Тестирование API...${NC}"
echo ""

# Health check
echo -e "${BLUE}Health Check:${NC}"
if curl -s "http://${NODE_IP}:${API_PORT}/health" | jq . 2>/dev/null; then
    echo -e "${GREEN}✅ Health check успешен${NC}"
else
    echo -e "${RED}❌ Health check не прошел${NC}"
    echo -e "${YELLOW}Попробуйте через port-forward:${NC}"
    echo "  kubectl port-forward -n security-test svc/security-stack-test 3000:3000"
fi
echo ""

# Отправка тестового события
echo -e "${BLUE}Отправка тестового Guardd события:${NC}"
curl -s -X POST "http://${NODE_IP}:${GUARDD_PORT}/guardd-events" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "event_type": "file_access",
    "pod_name": "test-pod-k8s",
    "namespace": "default",
    "container_name": "test",
    "severity": "critical",
    "details": {
      "description": "Test from K8s cluster",
      "process_name": "cat",
      "file_path": "/etc/shadow"
    }
  }' && echo -e "\n${GREEN}✅ Событие отправлено${NC}" || echo -e "\n${RED}❌ Ошибка отправки${NC}"
echo ""

sleep 2

# Проверка событий
echo -e "${BLUE}Проверка полученных событий:${NC}"
EVENTS=$(curl -s "http://${NODE_IP}:${API_PORT}/api/guardd/events" | jq -r '.total' 2>/dev/null || echo "0")
echo -e "Всего событий: ${GREEN}${EVENTS}${NC}"
echo ""

# Логи после теста
echo -e "${YELLOW}9. Логи после теста:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
kubectl logs security-stack-test -n security-test --tail=10 2>/dev/null | grep -E "(Guardd|событие|event)" || kubectl logs security-stack-test -n security-test --tail=10
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Итоги
echo -e "${GREEN}✅ Тестирование завершено!${NC}"
echo "=================================================="
echo ""
echo -e "${BLUE}📝 Полезные команды:${NC}"
echo ""
echo -e "${YELLOW}Просмотр всех логов:${NC}"
echo "  kubectl logs -n security-test security-stack-test -f"
echo ""
echo -e "${YELLOW}Port-forward для локального доступа:${NC}"
echo "  kubectl port-forward -n security-test svc/security-stack-test 3000:3000 8080:8080 8081:8081"
echo ""
echo -e "${YELLOW}Проверка API (через NodePort):${NC}"
echo "  curl http://${NODE_IP}:${API_PORT}/health | jq"
echo "  curl http://${NODE_IP}:${API_PORT}/api/guardd/events | jq"
echo "  curl http://${NODE_IP}:${API_PORT}/api/security/status | jq"
echo ""
echo -e "${YELLOW}Отправка тестового события:${NC}"
echo "  curl -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events -H 'Content-Type: application/json' -d '{...}'"
echo ""
echo -e "${YELLOW}Удаление тестового развертывания:${NC}"
echo "  kubectl delete -f k8s/simple-test-pod.yaml"
echo ""
echo -e "${YELLOW}Полное развертывание с DaemonSet:${NC}"
echo "  ./scripts/deploy-to-k8s.sh"
echo ""
