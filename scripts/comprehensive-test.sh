#!/bin/bash

# Комплексный тест Enterprise Security Stack

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
API_PORT="30000"
GUARDD_PORT="30081"
FALCO_PORT="30080"

PASSED=0
FAILED=0
TOTAL=0

test_case() {
    local name="$1"
    local command="$2"
    local expected_result="${3:-0}"  # 0 = success, 1 = should fail
    
    ((TOTAL++))
    echo -e "\n${BLUE}[$TOTAL] Testing: $name${NC}"
    
    if eval "$command" > /dev/null 2>&1; then
        result=0
    else
        result=1
    fi
    
    if [ $result -eq $expected_result ]; then
        echo -e "${GREEN}✅ PASSED${NC}"
        ((PASSED++))
    else
        echo -e "${RED}❌ FAILED${NC}"
        ((FAILED++))
    fi
}

echo -e "${BLUE}🔥 Comprehensive Security Testing${NC}"
echo "=========================================="
echo "Target: $NODE_IP"
echo "API Port: $API_PORT"
echo "Guardd Port: $GUARDD_PORT"
echo "=========================================="

# ============================================
# 1. BASIC FUNCTIONALITY TESTS
# ============================================
echo -e "\n${YELLOW}=== 1. Basic Functionality Tests ===${NC}"

test_case "Health Check" \
    "curl -sf http://${NODE_IP}:${API_PORT}/health"

test_case "API Status Endpoint" \
    "curl -sf http://${NODE_IP}:${API_PORT}/api/security/status"

test_case "Guardd Events Endpoint" \
    "curl -sf http://${NODE_IP}:${API_PORT}/api/guardd/events"

test_case "Valid Guardd Event Submission" \
    "curl -sf -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events \
    -H 'Content-Type: application/json' \
    -d '{
      \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"event_type\": \"file_access\",
      \"pod_name\": \"test-basic\",
      \"namespace\": \"default\",
      \"container_name\": \"test\",
      \"severity\": \"low\",
      \"details\": {
        \"description\": \"Basic test\",
        \"file_path\": \"/tmp/test\"
      }
    }'"

# ============================================
# 2. INJECTION ATTACK TESTS
# ============================================
echo -e "\n${YELLOW}=== 2. Injection Attack Tests ===${NC}"

test_case "SQL Injection in pod_name" \
    "curl -sf -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events \
    -H 'Content-Type: application/json' \
    -d '{
      \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"event_type\": \"file_access\",
      \"pod_name\": \"test'; DROP TABLE events; --\",
      \"namespace\": \"default\",
      \"container_name\": \"test\",
      \"severity\": \"critical\",
      \"details\": {
        \"description\": \"SQL injection test\"
      }
    }'"

test_case "XSS in description" \
    "curl -sf -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events \
    -H 'Content-Type: application/json' \
    -d '{
      \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"event_type\": \"file_access\",
      \"pod_name\": \"test-xss\",
      \"namespace\": \"default\",
      \"container_name\": \"test\",
      \"severity\": \"critical\",
      \"details\": {
        \"description\": \"<script>alert(1)</script>\"
      }
    }'"

test_case "Command Injection in process_name" \
    "curl -sf -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events \
    -H 'Content-Type: application/json' \
    -d '{
      \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"event_type\": \"process_execution\",
      \"pod_name\": \"test-cmd\",
      \"namespace\": \"default\",
      \"container_name\": \"test\",
      \"severity\": \"critical\",
      \"details\": {
        \"description\": \"Command injection test\",
        \"process_name\": \"cat /etc/passwd; rm -rf /\"
      }
    }'"

test_case "Path Traversal in file_path" \
    "curl -sf -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events \
    -H 'Content-Type: application/json' \
    -d '{
      \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"event_type\": \"file_access\",
      \"pod_name\": \"test-path\",
      \"namespace\": \"default\",
      \"container_name\": \"test\",
      \"severity\": \"critical\",
      \"details\": {
        \"description\": \"Path traversal test\",
        \"file_path\": \"../../../../etc/shadow\"
      }
    }'"

# ============================================
# 3. INVALID INPUT TESTS
# ============================================
echo -e "\n${YELLOW}=== 3. Invalid Input Tests ===${NC}"

test_case "Invalid JSON (should fail)" \
    "curl -sf -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events \
    -H 'Content-Type: application/json' \
    -d '{invalid json here'" \
    1

test_case "Empty Body (should fail)" \
    "curl -sf -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events \
    -H 'Content-Type: application/json' \
    -d ''" \
    1

test_case "Missing Required Fields (should fail)" \
    "curl -sf -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events \
    -H 'Content-Type: application/json' \
    -d '{\"pod_name\": \"test\"}'" \
    1

test_case "Wrong Content-Type" \
    "curl -sf -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events \
    -H 'Content-Type: text/plain' \
    -d 'not json at all'" \
    1

# ============================================
# 4. LOAD TESTS
# ============================================
echo -e "\n${YELLOW}=== 4. Load Tests ===${NC}"

test_case "100 Sequential Requests" \
    "for i in {1..100}; do
      curl -sf -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events \
        -H 'Content-Type: application/json' \
        -d '{
          \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
          \"event_type\": \"file_access\",
          \"pod_name\": \"load-test-\$i\",
          \"namespace\": \"default\",
          \"container_name\": \"test\",
          \"severity\": \"low\",
          \"details\": {\"description\": \"Load test \$i\"}
        }' || exit 1
    done"

test_case "50 Concurrent Requests" \
    "seq 1 50 | xargs -P 10 -I {} curl -sf -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events \
    -H 'Content-Type: application/json' \
    -d '{
      \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"event_type\": \"file_access\",
      \"pod_name\": \"concurrent-test-{}\",
      \"namespace\": \"default\",
      \"container_name\": \"test\",
      \"severity\": \"low\",
      \"details\": {\"description\": \"Concurrent test {}\"}
    }'"

# ============================================
# 5. RESOURCE TESTS
# ============================================
echo -e "\n${YELLOW}=== 5. Resource Tests ===${NC}"

test_case "Pod Still Running" \
    "kubectl get pod security-stack-test -n security-test -o jsonpath='{.status.phase}' | grep -q Running"

test_case "Pod Ready" \
    "kubectl get pod security-stack-test -n security-test -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' | grep -q True"

test_case "No Restarts" \
    "[ \$(kubectl get pod security-stack-test -n security-test -o jsonpath='{.status.containerStatuses[0].restartCount}') -eq 0 ]"

test_case "Memory Usage Reasonable" \
    "kubectl top pod security-stack-test -n security-test --no-headers | awk '{print \$3}' | sed 's/Mi//' | awk '{exit !(\$1 < 500)}'"

# ============================================
# 6. SECURITY TESTS
# ============================================
echo -e "\n${YELLOW}=== 6. Security Tests ===${NC}"

test_case "No Secrets in Logs" \
    "! kubectl logs security-stack-test -n security-test | grep -iE '(password|secret|token|key).*=.*[a-zA-Z0-9]{8,}'"

test_case "Running as Non-Root User" \
    "kubectl exec -n security-test security-stack-test -- id -u | grep -q 1000"

test_case "No Privileged Escalation" \
    "! kubectl exec -n security-test security-stack-test -- sudo -l 2>/dev/null"

# ============================================
# 7. ALL EVENT TYPES TEST
# ============================================
echo -e "\n${YELLOW}=== 7. All Event Types Test ===${NC}"

for event_type in "file_access" "network_connection" "process_execution" "capability_usage" "syscall_anomaly" "config_change"; do
    test_case "Event Type: $event_type" \
        "curl -sf -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events \
        -H 'Content-Type: application/json' \
        -d '{
          \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
          \"event_type\": \"$event_type\",
          \"pod_name\": \"test-$event_type\",
          \"namespace\": \"default\",
          \"container_name\": \"test\",
          \"severity\": \"medium\",
          \"details\": {\"description\": \"Test $event_type\"}
        }'"
done

# ============================================
# 8. STRESS TEST (OPTIONAL)
# ============================================
if [ "${RUN_STRESS_TEST:-0}" = "1" ]; then
    echo -e "\n${YELLOW}=== 8. Stress Test (1000 requests) ===${NC}"
    
    test_case "1000 Rapid Requests" \
        "for i in {1..1000}; do
          curl -sf -X POST http://${NODE_IP}:${GUARDD_PORT}/guardd-events \
            -H 'Content-Type: application/json' \
            -d '{
              \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
              \"event_type\": \"file_access\",
              \"pod_name\": \"stress-test-\$i\",
              \"namespace\": \"default\",
              \"container_name\": \"test\",
              \"severity\": \"low\",
              \"details\": {\"description\": \"Stress test \$i\"}
            }' &
          if [ \$((i % 100)) -eq 0 ]; then
            wait
            sleep 0.5
          fi
        done
        wait"
    
    # Проверяем что под не упал
    test_case "Pod Survived Stress Test" \
        "kubectl get pod security-stack-test -n security-test -o jsonpath='{.status.phase}' | grep -q Running"
fi

# ============================================
# SUMMARY
# ============================================
echo ""
echo "=========================================="
echo -e "${BLUE}Test Summary${NC}"
echo "=========================================="
echo -e "Total Tests:  $TOTAL"
echo -e "${GREEN}Passed:       $PASSED${NC}"
echo -e "${RED}Failed:       $FAILED${NC}"
echo "=========================================="

# Дополнительная информация
echo -e "\n${BLUE}System Status:${NC}"
kubectl get pods -n security-test
echo ""
kubectl top pod security-stack-test -n security-test 2>/dev/null || echo "Metrics not available"

echo -e "\n${BLUE}Event Statistics:${NC}"
TOTAL_EVENTS=$(curl -s http://${NODE_IP}:${API_PORT}/api/guardd/events | jq -r '.total' 2>/dev/null || echo "N/A")
CRITICAL_EVENTS=$(curl -s http://${NODE_IP}:${API_PORT}/api/guardd/critical | jq -r '.total' 2>/dev/null || echo "N/A")
echo "Total Events: $TOTAL_EVENTS"
echo "Critical Events: $CRITICAL_EVENTS"

# Финальный результат
echo ""
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed!${NC}"
    echo -e "${GREEN}System is functioning correctly.${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed!${NC}"
    echo -e "${YELLOW}Check the logs for details:${NC}"
    echo "  kubectl logs -n security-test security-stack-test --tail=50"
    exit 1
fi
