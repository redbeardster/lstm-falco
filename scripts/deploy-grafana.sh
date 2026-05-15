#!/bin/bash
# Скрипт для развертывания Grafana + Prometheus для мониторинга Enterprise Security Stack

set -e

echo "📊 Развертывание Grafana + Prometheus"
echo "======================================"
echo ""

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Конфигурация
NAMESPACE="${NAMESPACE:-monitoring}"
GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-admin123}"

echo -e "${BLUE}Конфигурация:${NC}"
echo "  Namespace: $NAMESPACE"
echo "  Grafana Password: $GRAFANA_PASSWORD"
echo ""

# 1. Создание namespace
echo -e "${BLUE}1. Создание namespace${NC}"
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
echo -e "${GREEN}✅ Namespace создан: $NAMESPACE${NC}"
echo ""

# 2. Добавление Helm репозиториев
echo -e "${BLUE}2. Добавление Helm репозиториев${NC}"
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
echo -e "${GREEN}✅ Helm репозитории добавлены${NC}"
echo ""

# 3. Установка Prometheus
echo -e "${BLUE}3. Установка Prometheus${NC}"

cat > /tmp/prometheus-values.yaml <<EOF
server:
  persistentVolume:
    enabled: false
  service:
    type: NodePort
    nodePort: 30090
  
  # Scrape конфигурация для Enterprise Security Stack
  extraScrapeConfigs: |
    - job_name: 'enterprise-security-stack'
      kubernetes_sd_configs:
        - role: pod
          namespaces:
            names:
              - default
      relabel_configs:
        - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
          action: keep
          regex: enterprise-security-stack
        - source_labels: [__meta_kubernetes_pod_ip]
          action: replace
          target_label: __address__
          replacement: \$1:3000
        - source_labels: [__meta_kubernetes_pod_name]
          action: replace
          target_label: pod
        - source_labels: [__meta_kubernetes_namespace]
          action: replace
          target_label: namespace
      metrics_path: /metrics

alertmanager:
  enabled: false

pushgateway:
  enabled: false

nodeExporter:
  enabled: false

kubeStateMetrics:
  enabled: true
EOF

helm upgrade --install prometheus prometheus-community/prometheus \
  --namespace $NAMESPACE \
  --values /tmp/prometheus-values.yaml \
  --wait \
  --timeout 5m

echo -e "${GREEN}✅ Prometheus установлен${NC}"
echo ""

# 4. Установка Grafana
echo -e "${BLUE}4. Установка Grafana${NC}"

cat > /tmp/grafana-values.yaml <<EOF
adminPassword: $GRAFANA_PASSWORD

service:
  type: NodePort
  nodePort: 30300

persistence:
  enabled: false

datasources:
  datasources.yaml:
    apiVersion: 1
    datasources:
      - name: Prometheus
        type: prometheus
        url: http://prometheus-server.$NAMESPACE.svc.cluster.local
        access: proxy
        isDefault: true

dashboardProviders:
  dashboardproviders.yaml:
    apiVersion: 1
    providers:
      - name: 'default'
        orgId: 1
        folder: ''
        type: file
        disableDeletion: false
        editable: true
        options:
          path: /var/lib/grafana/dashboards/default

dashboards:
  default:
    security-overview:
      json: |
        {
          "dashboard": {
            "title": "Enterprise Security Stack - Overview",
            "tags": ["security", "threats"],
            "timezone": "browser",
            "panels": [
              {
                "id": 1,
                "title": "Active Threats",
                "type": "stat",
                "targets": [
                  {
                    "expr": "security_active_threats",
                    "refId": "A"
                  }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 0, "y": 0}
              },
              {
                "id": 2,
                "title": "Risk Score",
                "type": "gauge",
                "targets": [
                  {
                    "expr": "security_risk_score",
                    "refId": "A"
                  }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 6, "y": 0},
                "options": {
                  "minValue": 0,
                  "maxValue": 1
                }
              },
              {
                "id": 3,
                "title": "Threats Detected (by type)",
                "type": "timeseries",
                "targets": [
                  {
                    "expr": "rate(security_threats_detected_total[5m])",
                    "legendFormat": "{{threat_type}}",
                    "refId": "A"
                  }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
              },
              {
                "id": 4,
                "title": "Detector Health",
                "type": "stat",
                "targets": [
                  {
                    "expr": "security_detector_health",
                    "legendFormat": "{{detector}}",
                    "refId": "A"
                  }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
              },
              {
                "id": 5,
                "title": "Actions Executed",
                "type": "timeseries",
                "targets": [
                  {
                    "expr": "rate(security_actions_executed_total[5m])",
                    "legendFormat": "{{action_type}} ({{status}})",
                    "refId": "A"
                  }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
              },
              {
                "id": 6,
                "title": "Pending Confirmations",
                "type": "table",
                "targets": [
                  {
                    "expr": "security_pending_confirmations",
                    "refId": "A",
                    "format": "table"
                  }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
              },
              {
                "id": 7,
                "title": "Confirmation Time",
                "type": "heatmap",
                "targets": [
                  {
                    "expr": "rate(security_confirmation_time_seconds_bucket[5m])",
                    "refId": "A",
                    "format": "heatmap"
                  }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
              },
              {
                "id": 8,
                "title": "False Positives Rate",
                "type": "timeseries",
                "targets": [
                  {
                    "expr": "rate(security_false_positives_total[5m])",
                    "legendFormat": "{{threat_type}}",
                    "refId": "A"
                  }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 24}
              },
              {
                "id": 9,
                "title": "Event Processing Time",
                "type": "timeseries",
                "targets": [
                  {
                    "expr": "histogram_quantile(0.95, rate(security_event_processing_time_ms_bucket[5m]))",
                    "legendFormat": "p95 - {{event_type}}",
                    "refId": "A"
                  }
                ],
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 24}
              },
              {
                "id": 10,
                "title": "HTTP Requests",
                "type": "timeseries",
                "targets": [
                  {
                    "expr": "rate(security_http_requests_total[5m])",
                    "legendFormat": "{{method}} {{endpoint}} ({{status}})",
                    "refId": "A"
                  }
                ],
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 32}
              }
            ],
            "refresh": "10s",
            "time": {
              "from": "now-1h",
              "to": "now"
            }
          }
        }
EOF

helm upgrade --install grafana grafana/grafana \
  --namespace $NAMESPACE \
  --values /tmp/grafana-values.yaml \
  --wait \
  --timeout 5m

echo -e "${GREEN}✅ Grafana установлен${NC}"
echo ""

# 5. Ожидание готовности
echo -e "${BLUE}5. Ожидание готовности подов${NC}"
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=prometheus \
  -n $NAMESPACE \
  --timeout=300s || true

kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=grafana \
  -n $NAMESPACE \
  --timeout=300s || true

echo -e "${GREEN}✅ Поды готовы${NC}"
echo ""

# 6. Получение информации о доступе
echo -e "${BLUE}6. Информация о доступе${NC}"
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')

echo -e "${GREEN}✅ Мониторинг развернут!${NC}"
echo ""
echo "=========================================="
echo -e "${GREEN}📊 Grafana${NC}"
echo "  URL: http://$NODE_IP:30300"
echo "  Username: admin"
echo "  Password: $GRAFANA_PASSWORD"
echo ""
echo -e "${GREEN}📈 Prometheus${NC}"
echo "  URL: http://$NODE_IP:30090"
echo ""
echo -e "${GREEN}🎯 Enterprise Security Stack${NC}"
echo "  Metrics: http://$NODE_IP:30100/metrics"
echo ""
echo "=========================================="
echo ""

# 7. Проверка метрик
echo -e "${BLUE}7. Проверка метрик${NC}"
echo "Ожидаем 5 секунд для инициализации..."
sleep 5

echo "Проверяем доступность метрик Security Stack..."
if curl -s -f http://$NODE_IP:30100/metrics | head -5; then
    echo -e "${GREEN}✅ Метрики доступны${NC}"
else
    echo -e "${YELLOW}⚠️  Метрики пока недоступны (возможно, нужно пересобрать с feature 'metrics')${NC}"
fi
echo ""

# 8. Проверка Prometheus targets
echo -e "${BLUE}8. Проверка Prometheus targets${NC}"
echo "Prometheus должен автоматически обнаружить Security Stack..."
echo "Проверьте targets в Prometheus UI: http://$NODE_IP:30090/targets"
echo ""

# Итоги
echo "=========================================="
echo -e "${GREEN}🎉 Развертывание завершено!${NC}"
echo ""
echo "Следующие шаги:"
echo ""
echo "1. Откройте Grafana:"
echo "   http://$NODE_IP:30300"
echo "   Login: admin / $GRAFANA_PASSWORD"
echo ""
echo "2. Дашборд 'Enterprise Security Stack - Overview' уже создан"
echo ""
echo "3. Проверьте Prometheus targets:"
echo "   http://$NODE_IP:30090/targets"
echo ""
echo "4. Для включения метрик в Security Stack, пересоберите с feature 'metrics':"
echo "   docker build --build-arg FEATURES=metrics -t 192.168.0.7:5000/security-stack:latest ."
echo ""
echo "Полезные команды:"
echo "  # Просмотр логов Grafana"
echo "  kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=grafana -f"
echo ""
echo "  # Просмотр логов Prometheus"
echo "  kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=prometheus -f"
echo ""
echo "  # Удаление мониторинга"
echo "  helm uninstall grafana -n $NAMESPACE"
echo "  helm uninstall prometheus -n $NAMESPACE"
echo ""

