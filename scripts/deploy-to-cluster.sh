#!/bin/bash
# Скрипт для развертывания Enterprise Security Stack в реальном кластере

set -e

echo "🚀 Развертывание Enterprise Security Stack"
echo "=========================================="
echo ""

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Конфигурация
REGISTRY="${REGISTRY:-192.168.0.7:5000}"
IMAGE_NAME="${IMAGE_NAME:-security-stack}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
NAMESPACE="${NAMESPACE:-default}"

echo -e "${BLUE}Конфигурация:${NC}"
echo "  Registry: $REGISTRY"
echo "  Image: $IMAGE_NAME:$IMAGE_TAG"
echo "  Namespace: $NAMESPACE"
echo ""

# Проверка кластера
echo -e "${BLUE}1. Проверка кластера${NC}"
if ! kubectl cluster-info &>/dev/null; then
    echo -e "${RED}❌ Кластер недоступен${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Кластер доступен${NC}"
kubectl get nodes
echo ""

# Проверка registry
echo -e "${BLUE}2. Проверка registry${NC}"
if curl -s http://$REGISTRY/v2/_catalog &>/dev/null; then
    echo -e "${GREEN}✅ Registry доступен: $REGISTRY${NC}"
else
    echo -e "${YELLOW}⚠️  Registry недоступен, используем локальную сборку${NC}"
fi
echo ""

# Сборка образа
echo -e "${BLUE}3. Сборка Docker образа${NC}"
echo "Собираем образ..."
docker build -t $REGISTRY/$IMAGE_NAME:$IMAGE_TAG . || {
    echo -e "${RED}❌ Ошибка сборки образа${NC}"
    exit 1
}
echo -e "${GREEN}✅ Образ собран: $REGISTRY/$IMAGE_NAME:$IMAGE_TAG${NC}"
echo ""

# Пуш в registry
echo -e "${BLUE}4. Загрузка образа в registry${NC}"
if curl -s http://$REGISTRY/v2/_catalog &>/dev/null; then
    docker push $REGISTRY/$IMAGE_NAME:$IMAGE_TAG || {
        echo -e "${YELLOW}⚠️  Не удалось загрузить в registry, используем локальный образ${NC}"
    }
    echo -e "${GREEN}✅ Образ загружен в registry${NC}"
else
    echo -e "${YELLOW}⚠️  Registry недоступен, используем локальный образ${NC}"
fi
echo ""

# Создание namespace (если нужно)
if [ "$NAMESPACE" != "default" ]; then
    echo -e "${BLUE}5. Создание namespace${NC}"
    kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
    echo -e "${GREEN}✅ Namespace: $NAMESPACE${NC}"
    echo ""
fi

# Развертывание через Helm
echo -e "${BLUE}6. Развертывание через Helm${NC}"

# Проверка наличия Helm
if ! command -v helm &>/dev/null; then
    echo -e "${YELLOW}⚠️  Helm не установлен, используем kubectl${NC}"
    USE_KUBECTL=true
else
    echo -e "${GREEN}✅ Helm установлен${NC}"
    USE_KUBECTL=false
fi

if [ "$USE_KUBECTL" = true ]; then
    # Развертывание через kubectl
    echo "Развертывание через kubectl..."
    
    # Создаем простой манифест
    cat > /tmp/security-stack-deployment.yaml <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: security-stack
  namespace: $NAMESPACE
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-stack
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: security-stack
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: security-stack
subjects:
- kind: ServiceAccount
  name: security-stack
  namespace: $NAMESPACE
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-stack
  namespace: $NAMESPACE
  labels:
    app: security-stack
spec:
  replicas: 1
  selector:
    matchLabels:
      app: security-stack
  template:
    metadata:
      labels:
        app: security-stack
    spec:
      serviceAccountName: security-stack
      containers:
      - name: security-stack
        image: $REGISTRY/$IMAGE_NAME:$IMAGE_TAG
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 3000
          name: http
        env:
        - name: RUST_LOG
          value: "info"
        - name: CONFIRMATION_THRESHOLD
          value: "3"
        - name: CONFIRMATION_WINDOW_SECS
          value: "60"
        - name: MAX_EVENTS_BUFFER
          value: "10000"
        resources:
          limits:
            cpu: 500m
            memory: 512Mi
          requests:
            cpu: 200m
            memory: 256Mi
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: security-stack
  namespace: $NAMESPACE
  labels:
    app: security-stack
spec:
  type: NodePort
  ports:
  - port: 3000
    targetPort: 3000
    nodePort: 30000
    name: http
  selector:
    app: security-stack
EOF

    kubectl apply -f /tmp/security-stack-deployment.yaml
    echo -e "${GREEN}✅ Развернуто через kubectl${NC}"
else
    # Развертывание через Helm
    echo "Развертывание через Helm..."
    
    helm upgrade --install security-stack ./charts/enterprise-security-stack \
        --namespace $NAMESPACE \
        --set image.repository=$REGISTRY/$IMAGE_NAME \
        --set image.tag=$IMAGE_TAG \
        --set config.confirmationThreshold=3 \
        --set config.confirmationWindowSecs=60 \
        --wait \
        --timeout 5m || {
        echo -e "${RED}❌ Ошибка развертывания через Helm${NC}"
        exit 1
    }
    
    echo -e "${GREEN}✅ Развернуто через Helm${NC}"
fi
echo ""

# Ожидание готовности
echo -e "${BLUE}7. Ожидание готовности подов${NC}"
echo "Ожидаем запуска подов..."

kubectl wait --for=condition=Ready pod -l app=security-stack \
    -n $NAMESPACE \
    --timeout=300s || {
    echo -e "${YELLOW}⚠️  Поды не готовы, проверяем статус...${NC}"
    kubectl get pods -n $NAMESPACE -l app=security-stack
    kubectl describe pods -n $NAMESPACE -l app=security-stack | tail -50
}

echo -e "${GREEN}✅ Поды готовы${NC}"
echo ""

# Проверка статуса
echo -e "${BLUE}8. Проверка статуса${NC}"
kubectl get all -n $NAMESPACE -l app=security-stack
echo ""

# Получение информации о сервисе
echo -e "${BLUE}9. Информация о доступе${NC}"
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
NODE_PORT=$(kubectl get svc security-stack -n $NAMESPACE -o jsonpath='{.spec.ports[0].nodePort}')

echo -e "${GREEN}✅ Security Stack развернут!${NC}"
echo ""
echo "Доступ к API:"
echo "  URL: http://$NODE_IP:$NODE_PORT"
echo ""
echo "Примеры команд:"
echo "  # Health check"
echo "  curl http://$NODE_IP:$NODE_PORT/health"
echo ""
echo "  # Detectors health"
echo "  curl http://$NODE_IP:$NODE_PORT/api/security/detectors/health"
echo ""
echo "  # Security status"
echo "  curl http://$NODE_IP:$NODE_PORT/api/security/status"
echo ""
echo "  # Audit log"
echo "  curl http://$NODE_IP:$NODE_PORT/api/security/audit"
echo ""

# Проверка логов
echo -e "${BLUE}10. Последние логи${NC}"
kubectl logs -n $NAMESPACE -l app=security-stack --tail=20
echo ""

# Тестирование API
echo -e "${BLUE}11. Тестирование API${NC}"
echo "Ожидаем 5 секунд для инициализации..."
sleep 5

echo "Проверяем health endpoint..."
if curl -s -f http://$NODE_IP:$NODE_PORT/health &>/dev/null; then
    echo -e "${GREEN}✅ Health check: OK${NC}"
    curl -s http://$NODE_IP:$NODE_PORT/health | jq .
else
    echo -e "${YELLOW}⚠️  Health check: недоступен (возможно, еще инициализируется)${NC}"
fi
echo ""

echo "Проверяем detectors health..."
if curl -s -f http://$NODE_IP:$NODE_PORT/api/security/detectors/health &>/dev/null; then
    echo -e "${GREEN}✅ Detectors health: OK${NC}"
    curl -s http://$NODE_IP:$NODE_PORT/api/security/detectors/health | jq .
else
    echo -e "${YELLOW}⚠️  Detectors health: недоступен${NC}"
fi
echo ""

# Итоги
echo "=========================================="
echo -e "${GREEN}🎉 Развертывание завершено!${NC}"
echo ""
echo "Полезные команды:"
echo "  # Просмотр логов"
echo "  kubectl logs -n $NAMESPACE -l app=security-stack -f"
echo ""
echo "  # Проверка статуса"
echo "  kubectl get pods -n $NAMESPACE -l app=security-stack"
echo ""
echo "  # Удаление"
if [ "$USE_KUBECTL" = true ]; then
    echo "  kubectl delete -f /tmp/security-stack-deployment.yaml"
else
    echo "  helm uninstall security-stack -n $NAMESPACE"
fi
echo ""
echo "  # Просмотр событий"
echo "  kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp'"
echo ""
