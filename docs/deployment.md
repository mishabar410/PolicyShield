# PolicyShield Deployment Guide

## Quick Start (Docker)

```bash
# Build and run
docker compose up -d

# Verify
curl http://localhost:8100/api/v1/health
```

## Docker

### Build

```bash
docker build -t policyshield:latest .
```

### Run

```bash
docker run -d \
  -p 8100:8100 \
  -v ./policies:/app/policies:ro \
  -e POLICYSHIELD_TOKEN=your-secret-token \
  -e POLICYSHIELD_FAIL_MODE=closed \
  policyshield:latest
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POLICYSHIELD_MODE` | `enforce` | Operating mode: `enforce`, `audit`, `disabled` |
| `POLICYSHIELD_PORT` | `8100` | Server port |
| `POLICYSHIELD_HOST` | `0.0.0.0` | Bind address |
| `POLICYSHIELD_FAIL_MODE` | `closed` | `open` (allow on error) or `closed` (block on error) |
| `POLICYSHIELD_TOKEN` | _(empty)_ | Bearer token for API auth |
| `POLICYSHIELD_TRACE_DIR` | `./traces` | Audit trail directory |
| `POLICYSHIELD_ENGINE_TIMEOUT` | `5.0` | Max seconds per check |
| `POLICYSHIELD_TELEGRAM_TOKEN` | _(empty)_ | Telegram bot token for approvals |
| `POLICYSHIELD_TELEGRAM_CHAT_ID` | _(empty)_ | Telegram chat ID for approvals |
| `OPENAI_API_KEY` | _(empty)_ | For LLM Guard and NL compiler |

## Docker Compose

See `docker-compose.yml` in the project root. Supports:
- Volume mount for rules (read-only)
- Persistent trace storage volume
- Health checks
- Optional Redis for distributed sessions

## Kubernetes

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: policyshield
spec:
  replicas: 2
  selector:
    matchLabels:
      app: policyshield
  template:
    metadata:
      labels:
        app: policyshield
    spec:
      containers:
      - name: policyshield
        image: policyshield:latest
        ports:
        - containerPort: 8100
        env:
        - name: POLICYSHIELD_TOKEN
          valueFrom:
            secretKeyRef:
              name: policyshield-secrets
              key: api-token
        - name: POLICYSHIELD_FAIL_MODE
          value: "closed"
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 8100
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /api/v1/health
            port: 8100
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 256Mi
        volumeMounts:
        - name: policies
          mountPath: /app/policies
          readOnly: true
      volumes:
      - name: policies
        configMap:
          name: policyshield-rules
---
apiVersion: v1
kind: Service
metadata:
  name: policyshield
spec:
  selector:
    app: policyshield
  ports:
  - port: 8100
    targetPort: 8100
  type: ClusterIP
```

### Secret

```bash
kubectl create secret generic policyshield-secrets \
  --from-literal=api-token=your-secret-token
```

### ConfigMap for Rules

```bash
kubectl create configmap policyshield-rules \
  --from-file=policies/
```

## Security Checklist

- [ ] Set `POLICYSHIELD_TOKEN` to a strong, unique value
- [ ] Use `POLICYSHIELD_FAIL_MODE=closed` in production
- [ ] Mount rules as read-only volumes
- [ ] Run as non-root user (default in Dockerfile)
- [ ] Enable TLS via `--tls-cert` and `--tls-key` or reverse proxy
- [ ] Restrict network access to the shield API
- [ ] Enable audit traces (`POLICYSHIELD_TRACE_DIR`)
- [ ] Configure health checks and monitoring
- [ ] Set resource limits (CPU/memory) in K8s

## Monitoring

### Health Endpoint

```bash
curl http://localhost:8100/api/v1/health
# {"status":"ok","shield_name":"...","version":1,"rules_count":5,"mode":"enforce"}
```

### Prometheus Metrics (via trace dashboard)

```bash
policyshield trace dashboard --dir ./traces --prometheus
# Exposes /metrics endpoint for Prometheus scraping
```

## TLS

```bash
policyshield server --rules policies/ \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem
```

Or via environment:
```bash
export POLICYSHIELD_TLS_CERT=/path/to/cert.pem
export POLICYSHIELD_TLS_KEY=/path/to/key.pem
```
