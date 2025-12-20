# Deployment Guide

This guide covers various deployment strategies for the S3 IAM Proxy.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Docker Deployment](#docker-deployment)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Systemd Service](#systemd-service)
5. [Production Checklist](#production-checklist)

## Quick Start

### Prerequisites

- Go 1.21+ (for building from source)
- Access to Hetzner Object Storage or any S3-compatible backend
- Valid S3 credentials with full access

### Build and Run

```bash
# Clone repository
git clone https://github.com/pratikbin/go-s3-rbac-single-bucket.git
cd go-s3-rbac-single-bucket

# Install dependencies
go mod download

# Edit configuration
cp config.yaml config.local.yaml
vim config.local.yaml  # Add your credentials

# Build
go build -o s3-proxy

# Run
./s3-proxy -config config.local.yaml
```

## Docker Deployment

### Using Docker Compose (Recommended)

```bash
# Edit config.yaml with your credentials
vim config.yaml

# Start the service
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

### Manual Docker Build

```bash
# Build image
docker build -t s3-proxy:latest .

# Run container
docker run -d \
  --name s3-proxy \
  -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/s3-proxy/config.yaml:ro \
  --restart unless-stopped \
  s3-proxy:latest
```

### Docker Configuration

Mount your config file:

```yaml
volumes:
  - ./config.yaml:/etc/s3-proxy/config.yaml:ro
```

Or use environment variables (requires code modification):

```yaml
environment:
  - MASTER_ACCESS_KEY=your-key
  - MASTER_SECRET_KEY=your-secret
  - MASTER_ENDPOINT=https://your-endpoint.com
```

## Kubernetes Deployment

### Create ConfigMap

```bash
kubectl create configmap s3-proxy-config --from-file=config.yaml
```

### Deployment Manifest

Create `k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: s3-proxy
  labels:
    app: s3-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: s3-proxy
  template:
    metadata:
      labels:
        app: s3-proxy
    spec:
      containers:
      - name: s3-proxy
        image: s3-proxy:latest
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 8080
          name: http
        volumeMounts:
        - name: config
          mountPath: /etc/s3-proxy
          readOnly: true
        livenessProbe:
          httpGet:
            path: /
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
      volumes:
      - name: config
        configMap:
          name: s3-proxy-config
---
apiVersion: v1
kind: Service
metadata:
  name: s3-proxy
spec:
  type: LoadBalancer
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
    name: http
  selector:
    app: s3-proxy
```

### Deploy

```bash
kubectl apply -f k8s/deployment.yaml

# Check status
kubectl get pods -l app=s3-proxy
kubectl get svc s3-proxy

# View logs
kubectl logs -f -l app=s3-proxy
```

### Ingress (Optional)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: s3-proxy
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - s3.yourdomain.com
    secretName: s3-proxy-tls
  rules:
  - host: s3.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: s3-proxy
            port:
              number: 8080
```

## Systemd Service

### Create Service User

```bash
sudo useradd -r -s /bin/false s3proxy
```

### Install Binary

```bash
# Build binary
go build -o s3-proxy

# Copy to system location
sudo cp s3-proxy /usr/local/bin/
sudo chmod +x /usr/local/bin/s3-proxy

# Copy config
sudo mkdir -p /etc/s3-proxy
sudo cp config.yaml /etc/s3-proxy/
sudo chown -R s3proxy:s3proxy /etc/s3-proxy
sudo chmod 600 /etc/s3-proxy/config.yaml  # Protect secrets
```

### Create Systemd Unit

Create `/etc/systemd/system/s3-proxy.service`:

```ini
[Unit]
Description=S3 IAM Proxy
Documentation=https://github.com/pratikbin/go-s3-rbac-single-bucket
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=s3proxy
Group=s3proxy
ExecStart=/usr/local/bin/s3-proxy -config /etc/s3-proxy/config.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/s3-proxy

# Environment
Environment="GOMAXPROCS=4"

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable on boot
sudo systemctl enable s3-proxy

# Start service
sudo systemctl start s3-proxy

# Check status
sudo systemctl status s3-proxy

# View logs
sudo journalctl -u s3-proxy -f
```

## Production Checklist

### Security

- [ ] Use HTTPS/TLS (put behind Nginx or Traefik)
- [ ] Secure config file permissions (`chmod 600`)
- [ ] Use strong, randomly generated access keys and secrets
- [ ] Enable firewall rules (only allow necessary ports)
- [ ] Run as non-root user
- [ ] Keep Go and dependencies updated
- [ ] Enable audit logging

### Performance

- [ ] Set appropriate `GOMAXPROCS` (equal to CPU cores)
- [ ] Tune kernel parameters:
  ```bash
  # /etc/sysctl.conf
  net.ipv4.tcp_tw_reuse = 1
  net.ipv4.ip_local_port_range = 1024 65535
  net.core.somaxconn = 65535
  ```
- [ ] Increase file descriptor limits (`ulimit -n 65535`)
- [ ] Configure appropriate timeouts in `config.yaml`
- [ ] Monitor memory usage and CPU utilization

### Monitoring

- [ ] Set up health checks
- [ ] Configure log aggregation (ELK, Loki, etc.)
- [ ] Set up metrics collection (Prometheus)
- [ ] Configure alerting (disk space, error rates, latency)
- [ ] Monitor backend (Hetzner) API limits

### Backup and Recovery

- [ ] Document configuration
- [ ] Back up `config.yaml` securely
- [ ] Test restore procedures
- [ ] Plan for credential rotation

### Load Balancing

For high availability, run multiple instances behind a load balancer:

```
                   ┌─────────────┐
                   │   Nginx     │
                   │  (SSL Term) │
                   └──────┬──────┘
                          │
              ┌───────────┼───────────┐
              │           │           │
         ┌────▼───┐  ┌────▼───┐ ┌────▼───┐
         │ Proxy1 │  │ Proxy2 │ │ Proxy3 │
         └────┬───┘  └────┬───┘ └────┬───┘
              └───────────┼───────────┘
                          │
                   ┌──────▼──────┐
                   │   Hetzner   │
                   │   Storage   │
                   └─────────────┘
```

### Nginx Configuration Example

```nginx
upstream s3_proxy {
    least_conn;
    server 127.0.0.1:8080 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:8081 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:8082 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name s3.yourdomain.com;

    ssl_certificate /etc/ssl/certs/s3.crt;
    ssl_certificate_key /etc/ssl/private/s3.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    client_max_body_size 10G;
    proxy_request_buffering off;

    location / {
        proxy_pass http://s3_proxy;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts for large uploads
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_read_timeout 300;
    }
}
```

## Troubleshooting

### Check Logs

```bash
# Docker
docker-compose logs -f

# Systemd
journalctl -u s3-proxy -f

# Kubernetes
kubectl logs -f -l app=s3-proxy
```

### Test Connectivity

```bash
# Test proxy health
curl -v http://localhost:8080/

# Test with AWS CLI
aws s3 ls s3://test-bucket --endpoint-url http://localhost:8080
```

### Debug Mode

Enable debug logging in `config.yaml`:

```yaml
logging:
  level: "debug"
  format: "console"
```

### Common Issues

1. **Signature Mismatch**: Check that client is using correct credentials and clock is synchronized
2. **Connection Timeout**: Increase timeouts in config or Nginx
3. **High Memory**: Ensure clients are using streaming mode
4. **Backend Errors**: Check Hetzner API limits and credentials

## Scaling Recommendations

| Users | Instances | CPU per Instance | Memory per Instance |
|-------|-----------|------------------|---------------------|
| 1-100 | 1 | 2 cores | 512 MB |
| 100-500 | 2-3 | 4 cores | 1 GB |
| 500-2000 | 3-5 | 4 cores | 2 GB |
| 2000+ | 5+ | 8 cores | 4 GB |

## Support

For issues or questions:
- GitHub Issues: https://github.com/pratikbin/go-s3-rbac-single-bucket/issues
- Documentation: See README.md

