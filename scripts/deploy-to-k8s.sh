#!/bin/bash

# Скрипт для развертывания Enterprise Security Stack в Kubernetes

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🚀 Развертывание Enterprise Security Stack в Kubernetes${NC}"
echo "================================================================"
echo ""

# Проверка доступности kubectl
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}❌ kubectl не найден. Установите kubectl.${NC}"
    exit 1
fi

# Проверка доступности кластера
echo -e "${YELLOW}1️⃣  Проверка доступности кластера...${NC}"
if ! kubectl cluster-info &> /dev/null; then
    echo -e "${RED}❌ Kubernetes кластер недоступен${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Кластер доступен${NC}"
kubectl cluster-info | head -1
echo ""

# Сборка Docker образа
echo -e "${YELLOW}2️⃣  Сборка Docker образа...${NC}"
if [ ! -f "target/release/enterprise-security-stack" ]; then
    echo -e "${YELLOW}Бинарник не найден, выполняю сборку...${NC}"
    cargo build --release
fi

echo -e "${YELLOW}Создание Docker образа...${NC}"
docker build -t enterprise-security-stack:latest . || {
    echo -e "${RED}❌ Ошибка сборки Docker образа${NC}"
    exit 1
}
echo -e "${GREEN}✅ Docker образ создан${NC}"
echo ""

# Загрузка образа в кластер (для minikube/kind)
echo -e "${YELLOW}3️⃣  Проверка типа кластера...${NC}"
if command -v minikube &> /dev/null && minikube status &> /dev/null; then
    echo -e "${YELLOW}Обнаружен Minikube, загружаю образ...${NC}"
    minikube image load enterprise-security-stack:latest
    echo -e "${GREEN}✅ Образ загружен в Minikube${NC}"
elif command -v kind &> /dev/null && kind get clusters 2>/dev/null | grep -q .; then
    CLUSTER_NAME=$(kind get clusters | head -1)
    echo -e "${YELLOW}Обнаружен Kind (кластер: $CLUSTER_NAME), загружаю образ...${NC}"
    kind load docker-image enterprise-security-stack:latest --name "$CLUSTER_NAME"
    echo -e "${GREEN}✅ Образ загружен в Kind${NC}"
else
    echo -e "${YELLOW}⚠️  Стандартный кластер, убедитесь что образ доступен${NC}"
fi
echo ""

# Создание namespace
echo -e "${YELLOW}4️⃣  Создание namespace security-system...${NC}"
kubectl apply -f k8s/namespace.yaml
echo -e "${GREEN}✅ Namespace создан${NC}"
echo ""

# Развертывание Security Stack
echo -e "${YELLOW}5️⃣  Развертывание Security Stack...${NC}"
kubectl apply -f k8s/security-stack-deployment.yaml
echo -e "${GREEN}✅ Security Stack развернут${NC}"
echo ""

# Ожидание готовности
echo -e "${YELLOW}6️⃣  Ожидание готовности подов...${NC}"
kubectl wait --for=condition=ready pod \
    -l app=security-stack \
    -n security-system \
    --timeout=120s || {
    echo -e "${RED}❌ Под не стал готовым за 120 секунд${NC}"
    echo -e "${YELLOW}Логи пода:${NC}"
    kubectl logs -n security-system -l app=security-stack --tail=50
    exit 1
}
echo -e "${GREEN}✅ Поды готовы${NC}"
echo ""

# Развертывание Guardd DaemonSet (опционально)
echo -e "${YELLOW}7️⃣  Развертывание Guardd DaemonSet (опционально)...${NC}"
read -p "Развернуть Guardd DaemonSet? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    kubectl apply -f k8s/guardd-daemonset.yaml
    echo -e "${GREEN}✅ Guardd DaemonSet развернут${NC}"
else
    echo -e "${YELLOW}⏭️  Пропущено${NC}"
fi
echo ""

# Проверка статуса
echo -e "${YELLOW}8️⃣  Проверка статуса развертывания...${NC}"
echo ""
echo -e "${BLUE}Поды:${NC}"
kubectl get pods -n security-system -o wide
echo ""
echo -e "${BLUE}Сервисы:${NC}"
kubectl get svc -n security-system
echo ""

# Получение информации для доступа
echo -e "${GREEN}✅ Развертывание завершено!${NC}"
echo "================================================================"
echo ""
echo -e "${BLUE}📝 Информация для доступа:${NC}"
echo ""
echo -e "${YELLOW}1. Проверка логов:${NC}"
echo "   kubectl logs -n security-system -l app=security-stack -f"
echo ""
echo -e "${YELLOW}2. Port-forward для доступа к API:${NC}"
echo "   kubectl port-forward -n security-system svc/security-stack 3000:3000 8080:8080 8081:8081"
echo ""
echo -e "${YELLOW}3. Проверка health:${NC}"
echo "   # После port-forward:"
echo "   curl http://localhost:3000/health"
echo ""
echo -e "${YELLOW}4. Тестирование Guardd:${NC}"
echo "   # После port-forward:"
echo "   ./scripts/test-guardd-integration.sh"
echo ""
echo -e "${YELLOW}5. Просмотр событий:${NC}"
echo "   curl http://localhost:3000/api/guardd/events | jq"
echo "   curl http://localhost:3000/api/security/status | jq"
echo ""
echo -e "${YELLOW}6. Удаление развертывания:${NC}"
echo "   kubectl delete namespace security-system"
echo ""

# Автоматический port-forward (опционально)
echo -e "${YELLOW}Запустить port-forward сейчас? (y/N):${NC} "
read -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}Запуск port-forward...${NC}"
    echo -e "${YELLOW}Нажмите CTRL+C для остановки${NC}"
    kubectl port-forward -n security-system svc/security-stack 3000:3000 8080:8080 8081:8081
fi
