#!/bin/bash

# Скрипт для настройки локального Docker registry и развертывания в K8s

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

REGISTRY_HOST="192.168.0.7"
REGISTRY_PORT="5000"
REGISTRY_URL="${REGISTRY_HOST}:${REGISTRY_PORT}"
IMAGE_NAME="enterprise-security-stack"
IMAGE_TAG="latest"

echo -e "${BLUE}🚀 Настройка локального registry и развертывание в K8s${NC}"
echo "============================================================"
echo ""

# 1. Запуск локального registry (если не запущен)
echo -e "${YELLOW}1. Проверка локального registry...${NC}"
if docker ps | grep -q "registry:2"; then
    echo -e "${GREEN}   ✅ Registry уже запущен${NC}"
else
    echo -e "${YELLOW}   Запуск registry на ${REGISTRY_URL}...${NC}"
    docker run -d -p ${REGISTRY_PORT}:5000 --restart=always --name registry registry:2
    sleep 3
    echo -e "${GREEN}   ✅ Registry запущен${NC}"
fi
echo ""

# 2. Проверка доступности registry
echo -e "${YELLOW}2. Проверка доступности registry...${NC}"
if curl -s http://${REGISTRY_URL}/v2/_catalog > /dev/null; then
    echo -e "${GREEN}   ✅ Registry доступен на http://${REGISTRY_URL}${NC}"
else
    echo -e "${RED}   ❌ Registry недоступен${NC}"
    exit 1
fi
echo ""

# 3. Тегирование образа для registry
echo -e "${YELLOW}3. Тегирование образа для registry...${NC}"
docker tag ${IMAGE_NAME}:${IMAGE_TAG} ${REGISTRY_URL}/${IMAGE_NAME}:${IMAGE_TAG}
echo -e "${GREEN}   ✅ Образ тегирован: ${REGISTRY_URL}/${IMAGE_NAME}:${IMAGE_TAG}${NC}"
echo ""

# 4. Push образа в registry
echo -e "${YELLOW}4. Push образа в registry...${NC}"
docker push ${REGISTRY_URL}/${IMAGE_NAME}:${IMAGE_TAG}
echo -e "${GREEN}   ✅ Образ загружен в registry${NC}"
echo ""

# 5. Проверка образа в registry
echo -e "${YELLOW}5. Проверка образа в registry...${NC}"
if curl -s http://${REGISTRY_URL}/v2/${IMAGE_NAME}/tags/list | grep -q "${IMAGE_TAG}"; then
    echo -e "${GREEN}   ✅ Образ доступен в registry${NC}"
    curl -s http://${REGISTRY_URL}/v2/${IMAGE_NAME}/tags/list | jq .
else
    echo -e "${RED}   ❌ Образ не найден в registry${NC}"
    exit 1
fi
echo ""

# 6. Настройка containerd для insecure registry (если нужно)
echo -e "${YELLOW}6. Проверка настройки containerd...${NC}"
CONTAINERD_CONFIG="/etc/containerd/config.toml"
if sudo grep -q "${REGISTRY_URL}" ${CONTAINERD_CONFIG} 2>/dev/null; then
    echo -e "${GREEN}   ✅ Registry уже настроен в containerd${NC}"
else
    echo -e "${YELLOW}   ⚠️  Registry не настроен в containerd${NC}"
    echo -e "${YELLOW}   Для использования insecure registry добавьте в ${CONTAINERD_CONFIG}:${NC}"
    echo ""
    echo "   [plugins.\"io.containerd.grpc.v1.cri\".registry.mirrors.\"${REGISTRY_URL}\"]"
    echo "     endpoint = [\"http://${REGISTRY_URL}\"]"
    echo ""
    echo "   [plugins.\"io.containerd.grpc.v1.cri\".registry.configs.\"${REGISTRY_URL}\".tls]"
    echo "     insecure_skip_verify = true"
    echo ""
    echo -e "${YELLOW}   После изменений перезапустите containerd: sudo systemctl restart containerd${NC}"
fi
echo ""

# 7. Создание манифеста для K8s с registry
echo -e "${YELLOW}7. Создание манифеста для K8s...${NC}"
cat > k8s/registry-test-pod.yaml <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: security-test
---
apiVersion: v1
kind: Pod
metadata:
  name: security-stack-test
  namespace: security-test
  labels:
    app: security-stack-test
spec:
  containers:
    - name: security-stack
      image: ${REGISTRY_URL}/${IMAGE_NAME}:${IMAGE_TAG}
      imagePullPolicy: Always
      env:
        - name: RUST_LOG
          value: "enterprise_security=info,guardd=info"
        - name: EBPF_PROGRAM_PATH
          value: "/opt/seccomp/ebpf/seccomp_monitor.o"
      ports:
        - containerPort: 3000
          name: api
          protocol: TCP
        - containerPort: 8080
          name: falco
          protocol: TCP
        - containerPort: 8081
          name: guardd
          protocol: TCP
      livenessProbe:
        httpGet:
          path: /health
          port: 3000
        initialDelaySeconds: 10
        periodSeconds: 30
      readinessProbe:
        httpGet:
          path: /health
          port: 3000
        initialDelaySeconds: 5
        periodSeconds: 10
  restartPolicy: Always
---
apiVersion: v1
kind: Service
metadata:
  name: security-stack-test
  namespace: security-test
spec:
  type: NodePort
  selector:
    app: security-stack-test
  ports:
    - name: api
      port: 3000
      targetPort: 3000
      nodePort: 30000
    - name: falco
      port: 8080
      targetPort: 8080
      nodePort: 30080
    - name: guardd
      port: 8081
      targetPort: 8081
      nodePort: 30081
EOF
echo -e "${GREEN}   ✅ Манифест создан: k8s/registry-test-pod.yaml${NC}"
echo ""

# 8. Развертывание в K8s
echo -e "${YELLOW}8. Развертывание в K8s...${NC}"
kubectl delete -f k8s/registry-test-pod.yaml 2>/dev/null || true
sleep 2
kubectl apply -f k8s/registry-test-pod.yaml
echo -e "${GREEN}   ✅ Манифест применен${NC}"
echo ""

# 9. Ожидание готовности
echo -e "${YELLOW}9. Ожидание готовности пода (до 60 секунд)...${NC}"
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
        kubectl describe pod security-stack-test -n security-test | tail -30
        echo ""
        echo -e "${YELLOW}   Логи пода:${NC}"
        kubectl logs security-stack-test -n security-test 2>/dev/null || echo "   Логи недоступны"
        exit 1
    fi
    
    sleep 5
done
echo ""

# 10. Информация о развертывании
echo -e "${YELLOW}10. Информация о развертывании:${NC}"
echo ""
kubectl get pods -n security-test -o wide
echo ""
kubectl get svc -n security-test
echo ""

# 11. Логи
echo -e "${YELLOW}11. Логи приложения (последние 15 строк):${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
kubectl logs security-stack-test -n security-test --tail=15 2>/dev/null || echo "Логи недоступны"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 12. Получаем NodePort
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
API_PORT=$(kubectl get svc security-stack-test -n security-test -o jsonpath='{.spec.ports[?(@.name=="api")].nodePort}')
GUARDD_PORT=$(kubectl get svc security-stack-test -n security-test -o jsonpath='{.spec.ports[?(@.name=="guardd")].nodePort}')

echo -e "${GREEN}✅ Развертывание завершено!${NC}"
echo "============================================================"
echo ""
echo -e "${BLUE}📝 Доступ к сервисам:${NC}"
echo ""
echo -e "${YELLOW}Registry:${NC}"
echo "  http://${REGISTRY_URL}"
echo "  Образы: curl http://${REGISTRY_URL}/v2/_catalog"
echo ""
echo -e "${YELLOW}API Endpoint:${NC}"
echo "  http://${NODE_IP}:${API_PORT}"
echo ""
echo -e "${YELLOW}Guardd Webhook:${NC}"
echo "  http://${NODE_IP}:${GUARDD_PORT}"
echo ""

# 13. Тестирование
echo -e "${YELLOW}12. Тестирование API...${NC}"
echo ""

# Health check
echo -e "${BLUE}Health Check:${NC}"
if curl -s "http://${NODE_IP}:${API_PORT}/health" | jq . 2>/dev/null; then
    echo -e "${GREEN}✅ Health check успешен${NC}"
else
    echo -e "${RED}❌ Health check не прошел${NC}"
fi
echo ""

# Отправка тестового события
echo -e "${BLUE}Отправка тестового Guardd события:${NC}"
curl -s -X POST "http://${NODE_IP}:${GUARDD_PORT}/guardd-events" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "event_type": "file_access",
    "pod_name": "test-pod-registry",
    "namespace": "default",
    "container_name": "test",
    "severity": "critical",
    "details": {
      "description": "Test from K8s with registry",
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
echo -e "${YELLOW}13. Логи после теста:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
kubectl logs security-stack-test -n security-test --tail=10 2>/dev/null | grep -E "(Guardd|событие|event)" || kubectl logs security-stack-test -n security-test --tail=10
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Итоги
echo -e "${GREEN}✅ Тестирование завершено!${NC}"
echo "============================================================"
echo ""
echo -e "${BLUE}📝 Полезные команды:${NC}"
echo ""
echo -e "${YELLOW}Просмотр логов:${NC}"
echo "  kubectl logs -n security-test security-stack-test -f"
echo ""
echo -e "${YELLOW}Проверка API:${NC}"
echo "  curl http://${NODE_IP}:${API_PORT}/health | jq"
echo "  curl http://${NODE_IP}:${API_PORT}/api/guardd/events | jq"
echo "  curl http://${NODE_IP}:${API_PORT}/api/security/status | jq"
echo ""
echo -e "${YELLOW}Проверка registry:${NC}"
echo "  curl http://${REGISTRY_URL}/v2/_catalog"
echo "  curl http://${REGISTRY_URL}/v2/${IMAGE_NAME}/tags/list"
echo ""
echo -e "${YELLOW}Удаление:${NC}"
echo "  kubectl delete -f k8s/registry-test-pod.yaml"
echo "  docker stop registry && docker rm registry"
echo ""
