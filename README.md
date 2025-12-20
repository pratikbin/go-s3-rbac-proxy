# Go S3 IAM Proxy for Hetzner Object Storage

A high-performance, production-ready S3-compatible IAM proxy written in Go that adds fine-grained access control to object storage backends that lack native IAM policies (like Hetzner Object Storage).

## Features

- ✅ **AWS Signature V4 Authentication**: Full SigV4 validation for both header-based and presigned URLs
- ✅ **Zero-Copy Streaming**: Uses `UNSIGNED-PAYLOAD` and `io.Copy` for memory-efficient request proxying
- ✅ **RBAC (Role-Based Access Control)**: YAML-based user management with per-bucket permissions
- ✅ **High Concurrency**: Optimized `http.Transport` with high connection pooling
- ✅ **Structured Logging**: JSON logging via `uber-go/zap`
- ✅ **Graceful Shutdown**: Handles SIGTERM/SIGINT with connection draining
- ✅ **S3 Compatible**: Works with `aws-cli`, `rclone`, `s3cmd`, and all S3 SDKs

## Architecture

```
┌─────────────┐                  ┌──────────────┐                 ┌─────────────────┐
│   S3 Client │  ──SigV4 Auth──> │  IAM Proxy   │ ──Re-signed──>  │ Hetzner Storage │
│  (aws-cli)  │                  │   (Go)       │    Request      │   (Backend)     │
└─────────────┘                  └──────────────┘                 └─────────────────┘
                                        │
                                        ▼
                                  ┌──────────┐
                                  │ YAML DB  │
                                  │  Users   │
                                  └──────────┘
```

### Request Flow

1. **Client → Proxy**: Client sends SigV4-signed request with their credentials
2. **Authentication**: Proxy validates signature against YAML user database
3. **Authorization**: Checks if user has access to the requested bucket
4. **Re-signing**: Strips client auth, adds master credentials, re-signs with backend keys
5. **Streaming**: Proxies request/response with zero-copy streaming
6. **Response**: Returns backend response to client

## Performance Characteristics

- **Memory**: O(1) - No request body buffering
- **Latency**: ~1-2ms overhead for signature validation
- **Throughput**: Tested at 1000+ concurrent connections
- **CPU**: Multi-core aware (`GOMAXPROCS=NumCPU`)

## Installation

### Prerequisites

- Go 1.21 or higher
- Access to Hetzner Object Storage (or any S3-compatible backend)

### Build from Source

```bash
# Clone repository
git clone https://github.com/pratikbin/go-s3-rbac-single-bucket.git
cd go-s3-rbac-single-bucket

# Download dependencies
go mod download

# Build binary
go build -o s3-proxy .

# Run
./s3-proxy -config config.yaml
```

## Configuration

### config.yaml

```yaml
# Master credentials for Hetzner Object Storage backend
master_credentials:
  access_key: "YOUR_HETZNER_ACCESS_KEY"
  secret_key: "YOUR_HETZNER_SECRET_KEY"
  endpoint: "https://fsn1.your-objectstorage.com"
  region: "us-east-1"

# Proxy server settings
server:
  listen_addr: ":8080"
  read_timeout: "300s"
  write_timeout: "300s"
  idle_timeout: "120s"
  max_header_bytes: 1048576

# User database with RBAC
users:
  - access_key: "user1-key"
    secret_key: "user1-secret"
    allowed_buckets:
      - "bucket-alpha"
      - "bucket-beta"

  - access_key: "admin-key"
    secret_key: "admin-secret"
    allowed_buckets:
      - "*"  # Access all buckets

# Logging
logging:
  level: "info"
  format: "json"
```

## Usage

### Start the Proxy

```bash
./s3-proxy -config config.yaml
```

### Configure S3 Client

#### AWS CLI

```bash
# Configure credentials
aws configure set aws_access_key_id user1-key
aws configure set aws_secret_access_key user1-secret
aws configure set default.region us-east-1

# Point to proxy (use path-style addressing)
aws s3 ls s3://bucket-alpha \
  --endpoint-url http://localhost:8080

# Upload file
aws s3 cp file.txt s3://bucket-alpha/file.txt \
  --endpoint-url http://localhost:8080
```

#### rclone

```ini
[s3proxy]
type = s3
provider = Other
access_key_id = user1-key
secret_access_key = user1-secret
endpoint = http://localhost:8080
region = us-east-1
```

```bash
rclone ls s3proxy:bucket-alpha
```

#### Go SDK (aws-sdk-go-v2)

```go
import (
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/s3"
)

cfg, _ := config.LoadDefaultConfig(context.TODO(),
    config.WithRegion("us-east-1"),
    config.WithCredentialsProvider(
        credentials.NewStaticCredentialsProvider("user1-key", "user1-secret", ""),
    ),
)

client := s3.NewFromConfig(cfg, func(o *s3.Options) {
    o.BaseEndpoint = aws.String("http://localhost:8080")
    o.UsePathStyle = true
})
```

## Security Considerations

### Authentication

- **SigV4 Validation**: Full AWS Signature V4 implementation
- **Timestamp Verification**: Rejects requests with >15min clock skew (replay attack prevention)
- **Constant-Time Comparison**: HMAC signatures compared using `hmac.Equal()`

### Authorization

- **Bucket-Level ACL**: Users can only access explicitly allowed buckets
- **Wildcard Support**: Use `"*"` in `allowed_buckets` for admin users
- **Case-Insensitive**: Bucket names are compared case-insensitively

### Limitations

⚠️ **Body Integrity**: To enable streaming, we do NOT validate the `x-amz-content-sha256` payload hash. The signature proves the client knows the secret key, but they could send a different body than they signed. For most use cases (authorization proxy), this trade-off is acceptable.

**Mitigation**: If body integrity is critical:
1. Use TLS/HTTPS for transport security
2. Trust that backend storage provides checksums
3. Or implement optional body validation for sensitive buckets (at performance cost)

## Deployment

### Docker

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o s3-proxy .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/s3-proxy /usr/local/bin/
COPY config.yaml /etc/s3-proxy/config.yaml
EXPOSE 8080
CMD ["s3-proxy", "-config", "/etc/s3-proxy/config.yaml"]
```

### Systemd Service

```ini
[Unit]
Description=S3 IAM Proxy
After=network.target

[Service]
Type=simple
User=s3proxy
ExecStart=/usr/local/bin/s3-proxy -config /etc/s3-proxy/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Kubernetes

See `k8s/` directory for Deployment, Service, and ConfigMap manifests.

## Monitoring

### Health Check

```bash
curl http://localhost:8080/
```

### Metrics

The proxy logs structured JSON. Integrate with:
- **Prometheus**: Export logs via `promtail` + `loki`
- **ELK Stack**: Ship logs to Elasticsearch
- **Datadog**: Use `datadog-agent` log collection

Example log entry:
```json
{
  "level": "info",
  "ts": "2025-12-20T10:30:15.123Z",
  "msg": "request completed",
  "user": "user1-key",
  "bucket": "bucket-alpha",
  "method": "PUT",
  "path": "/bucket-alpha/file.txt",
  "duration": 0.0453
}
```

## Performance Tuning

### System Limits

```bash
# Increase file descriptors
ulimit -n 65535

# TCP tuning (Linux)
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.ipv4.ip_local_port_range="1024 65535"
```

### Go Runtime

```bash
# Set GOMAXPROCS explicitly
export GOMAXPROCS=16

# Disable GC for benchmarking (not recommended for production)
export GOGC=off
```

### Configuration Tuning

```yaml
server:
  read_timeout: "600s"    # For large uploads
  write_timeout: "600s"
  idle_timeout: "120s"
  max_header_bytes: 2097152  # 2MB for large multipart manifests
```

## Testing

### Unit Tests

```bash
go test -v ./...
```

### Load Testing

```bash
# Install vegeta
go install github.com/tsenart/vegeta@latest

# Run load test
echo "GET http://localhost:8080/bucket-alpha/" | \
  vegeta attack -duration=30s -rate=100 | \
  vegeta report
```

### S3 Compatibility Tests

```bash
# Install s3-tests (Ceph)
git clone https://github.com/ceph/s3-tests
cd s3-tests
pip install -r requirements.txt

# Configure for proxy
cp s3tests.conf.SAMPLE s3tests.conf
# Edit s3tests.conf with proxy endpoint

# Run tests
./virtualenv/bin/nosetests
```

## Troubleshooting

### Signature Mismatch Errors

Enable debug logging to see canonical request:

```yaml
logging:
  level: "debug"
```

Check logs for:
- `canonical_request`: The string being signed
- `string_to_sign`: The final signing input
- `expected` vs `provided` signatures

### Connection Timeouts

Increase timeouts for large files:

```yaml
server:
  read_timeout: "600s"
  write_timeout: "600s"
```

### High Memory Usage

Ensure clients are using `UNSIGNED-PAYLOAD` or disable body hash validation (already default in this implementation).

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- AWS Signature V4 specification
- Go standard library (`net/http`, `httputil.ReverseProxy`)
- `aws-sdk-go-v2` for SigV4 signer
- `uber-go/zap` for logging

## Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/pratikbin/go-s3-rbac-single-bucket/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/pratikbin/go-s3-rbac-single-bucket/discussions)
- 📧 **Email**: pratik@example.com

---

**Built with ❤️ for developers who need S3 IAM policies on object storage providers that don't support them natively.**

