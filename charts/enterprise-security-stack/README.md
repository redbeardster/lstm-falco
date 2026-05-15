# Enterprise Security Stack Helm Chart

Enterprise-grade Kubernetes security monitoring with eBPF, Falco, and AI-powered threat detection.

## Features

- 🔍 **Real-time threat detection** - eBPF, Falco, and Guardd integration
- 🤖 **AI-powered analysis** - ML-based threat prediction
- 🛡️ **Automated response** - Automatic pod isolation and threat mitigation
- 📊 **Comprehensive monitoring** - Security events, incidents, and audit logs
- ✅ **False positive protection** - Confirmation mechanism before critical actions
- 📝 **Immutable audit log** - Complete audit trail for compliance

## Prerequisites

- Kubernetes 1.25+
- Helm 3.0+
- Falco installed (optional, can use existing installation)

## Installation

### Quick Start

```bash
# Add the repository (if published)
helm repo add enterprise-security https://charts.example.com
helm repo update

# Install with default values
helm install security-stack enterprise-security/enterprise-security-stack

# Or install from local chart
helm install security-stack ./charts/enterprise-security-stack
```

### Custom Installation

```bash
# Install with custom values
helm install security-stack ./charts/enterprise-security-stack \
  --set image.repository=your-registry/security-stack \
  --set image.tag=1.3.0 \
  --set config.confirmationThreshold=5 \
  --set persistence.enabled=true
```

### Install in specific namespace

```bash
# Create namespace
kubectl create namespace security

# Install
helm install security-stack ./charts/enterprise-security-stack \
  --namespace security \
  --create-namespace
```

## Configuration

### Key Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Image repository | `192.168.0.7:5000/security-stack` |
| `image.tag` | Image tag | `latest` |
| `replicaCount` | Number of replicas | `1` |
| `config.confirmationThreshold` | Confirmations before action | `3` |
| `config.confirmationWindowSecs` | Time window for confirmations | `60` |
| `config.falcoUrl` | Falco service URL | `http://falco.falco:8765` |
| `persistence.enabled` | Enable audit log persistence | `false` |
| `persistence.size` | PVC size for audit logs | `10Gi` |

### Full Configuration

See [values.yaml](values.yaml) for all available options.

### Example: Production Configuration

```yaml
# production-values.yaml
replicaCount: 2

image:
  repository: your-registry/security-stack
  tag: "1.3.0"
  pullPolicy: Always

resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 500m
    memory: 512Mi

config:
  confirmationThreshold: 5  # More confirmations for production
  confirmationWindowSecs: 120  # Longer window
  logLevel: "info"

persistence:
  enabled: true
  storageClass: "fast-ssd"
  size: 50Gi

metrics:
  enabled: true
  serviceMonitor:
    enabled: true

ingress:
  enabled: true
  className: "nginx"
  hosts:
    - host: security.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: security-tls
      hosts:
        - security.example.com
```

Install with production values:

```bash
helm install security-stack ./charts/enterprise-security-stack \
  --namespace security \
  --values production-values.yaml
```

## Upgrading

```bash
# Upgrade to new version
helm upgrade security-stack ./charts/enterprise-security-stack

# Upgrade with new values
helm upgrade security-stack ./charts/enterprise-security-stack \
  --values new-values.yaml

# Rollback if needed
helm rollback security-stack
```

## Uninstallation

```bash
# Uninstall the release
helm uninstall security-stack

# Uninstall from specific namespace
helm uninstall security-stack --namespace security
```

## Verification

### Check Installation

```bash
# Check release status
helm status security-stack

# Check pods
kubectl get pods -l app.kubernetes.io/name=enterprise-security-stack

# Check logs
kubectl logs -l app.kubernetes.io/name=enterprise-security-stack
```

### Test Endpoints

```bash
# Port-forward for local testing
kubectl port-forward svc/security-stack-enterprise-security-stack 3000:3000

# Health check
curl http://localhost:3000/health

# Detectors health
curl http://localhost:3000/api/security/detectors/health

# Audit log
curl http://localhost:3000/api/security/audit
```

## Configuration Examples

### 1. High Security Mode

```yaml
config:
  confirmationThreshold: 10  # Very strict
  confirmationWindowSecs: 300  # 5 minutes
  logLevel: "debug"

resources:
  limits:
    cpu: 2000m
    memory: 2Gi
```

### 2. Development Mode

```yaml
config:
  confirmationThreshold: 1  # Quick response
  confirmationWindowSecs: 10  # Short window
  logLevel: "debug"

persistence:
  enabled: false  # No persistence needed
```

### 3. With Existing Falco

```yaml
config:
  falcoUrl: "http://my-falco.monitoring:8765"

falco:
  enabled: false
  existingInstallation: true
```

### 4. With Persistence and Metrics

```yaml
persistence:
  enabled: true
  storageClass: "standard"
  size: 20Gi

metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 30s
```

## Troubleshooting

### Pods not starting

```bash
# Check pod status
kubectl describe pod -l app.kubernetes.io/name=enterprise-security-stack

# Check logs
kubectl logs -l app.kubernetes.io/name=enterprise-security-stack --tail=100
```

### RBAC issues

```bash
# Check service account
kubectl get serviceaccount security-stack-enterprise-security-stack

# Check cluster role binding
kubectl get clusterrolebinding security-stack-enterprise-security-stack
```

### Falco connection issues

```bash
# Test Falco connectivity
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://falco.falco:8765/healthz
```

## Advanced Usage

### Custom RBAC

```yaml
rbac:
  create: true
  # Add custom rules in values.yaml
```

### Network Policies

```yaml
networkPolicy:
  enabled: true
  ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            name: monitoring
  egress:
    - to:
      - namespaceSelector:
          matchLabels:
            name: falco
```

### Multiple Instances

```bash
# Install in different namespaces
helm install security-prod ./charts/enterprise-security-stack \
  --namespace production

helm install security-dev ./charts/enterprise-security-stack \
  --namespace development \
  --set config.confirmationThreshold=1
```

## Monitoring

### Prometheus Integration

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 30s
    scrapeTimeout: 10s
```

### Grafana Dashboard

Import dashboard from `dashboards/security-stack.json` (coming soon).

## Security Considerations

1. **RBAC**: Chart creates minimal required permissions
2. **Security Context**: Runs as non-root by default
3. **Network Policies**: Optional, can be enabled
4. **Audit Logs**: Immutable audit trail for compliance
5. **Confirmation Mechanism**: Protects against false positives

## Support

- **Documentation**: See [docs/](../../docs/)
- **Issues**: GitHub Issues
- **Slack**: #security-stack

## License

See [LICENSE](../../LICENSE)

## Version History

- **1.3.0** - Added confirmation mechanism and audit logging
- **1.2.0** - Added trait-based detectors
- **1.1.0** - Initial Helm chart release
