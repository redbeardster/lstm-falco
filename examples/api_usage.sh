#!/bin/bash

# Примеры использования API Enterprise Security Stack

BASE_URL="http://localhost:3000"

echo "=== Enterprise Security Stack API Examples ==="
echo ""

# 1. Health check
echo "1. Health Check:"
curl -s "${BASE_URL}/health" | jq .
echo ""
echo ""

# 2. Security Status
echo "2. Security Status:"
curl -s "${BASE_URL}/api/security/status" | jq .
echo ""
echo ""

# 3. Threat Predictions
echo "3. Threat Predictions:"
curl -s "${BASE_URL}/api/security/predictions" | jq .
echo ""
echo ""

# 4. Incidents History
echo "4. Incidents History:"
curl -s "${BASE_URL}/api/security/incidents" | jq .
echo ""
echo ""

# 5. Manual Response
echo "5. Manual Response (POST):"
curl -s -X POST "${BASE_URL}/api/security/respond" \
  -H "Content-Type: application/json" \
  -d '{
    "threat_type": "bruteforce",
    "target": "test-pod"
  }' | jq .
echo ""
echo ""

echo "=== Done ==="
