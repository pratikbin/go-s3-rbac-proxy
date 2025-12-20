# Quick Start Guide

Get up and running with the S3 IAM Proxy in 5 minutes.

## Prerequisites

- Go 1.21+ installed
- Hetzner Object Storage credentials (or any S3-compatible backend)

## 1. Clone and Setup

```bash
# Clone repository
git clone https://github.com/pratikbin/go-s3-rbac-single-bucket.git
cd go-s3-rbac-single-bucket

# Install dependencies
go mod download
```

## 2. Configure

Edit `config.yaml`:

```yaml
master_credentials:
  access_key: "YOUR_HETZNER_ACCESS_KEY"    # ← Change this
  secret_key: "YOUR_HETZNER_SECRET_KEY"    # ← Change this
  endpoint: "https://fsn1.your-objectstorage.com"  # ← Change this
  region: "us-east-1"

users:
  - access_key: "alice-key"                 # ← Create your users
    secret_key: "alice-secret"
    allowed_buckets:
      - "my-bucket"                         # ← Bucket names

  - access_key: "bob-key"
    secret_key: "bob-secret"
    allowed_buckets:
      - "another-bucket"
```

## 3. Run

```bash
# Build and run
make run

# Or manually
go build -o s3-proxy
./s3-proxy -config config.yaml
```

You should see:
```
Starting S3 IAM Proxy with GOMAXPROCS=8
{"level":"info","ts":"2025-12-20T10:00:00.000Z","msg":"configuration loaded",...}
{"level":"info","ts":"2025-12-20T10:00:00.001Z","msg":"starting server","addr":":8080"}
```

## 4. Test with AWS CLI

```bash
# Configure credentials
aws configure set aws_access_key_id alice-key
aws configure set aws_secret_access_key alice-secret
aws configure set default.region us-east-1

# Test list operation
aws s3 ls s3://my-bucket/ --endpoint-url http://localhost:8080

# Upload a file
echo "Hello, World!" > test.txt
aws s3 cp test.txt s3://my-bucket/test.txt --endpoint-url http://localhost:8080

# Download the file
aws s3 cp s3://my-bucket/test.txt downloaded.txt --endpoint-url http://localhost:8080

# Verify
cat downloaded.txt  # Should print: Hello, World!
```

## 5. Test Authorization

```bash
# Try accessing a bucket Alice doesn't have permission for
aws s3 ls s3://another-bucket/ --endpoint-url http://localhost:8080

# Should get AccessDenied error:
# An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied
```

## That's it! 🎉

You now have a running S3 IAM Proxy that enforces fine-grained access control.

## Next Steps

- **Production Deployment**: See [DEPLOYMENT.md](DEPLOYMENT.md)
- **More Examples**: See [EXAMPLES.md](EXAMPLES.md)
- **Full Documentation**: See [README.md](README.md)

## Common Commands

```bash
# Build
make build

# Run tests
make test

# View coverage
make coverage

# Run with Docker
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Troubleshooting

### "Signature Does Not Match" Error

**Cause**: Incorrect credentials or clock skew

**Solution**:
1. Verify credentials in `config.yaml`
2. Sync system clock: `sudo ntpdate -s time.nist.gov`
3. Enable debug logging in `config.yaml`:
   ```yaml
   logging:
     level: "debug"
   ```

### "Access Denied" Error

**Cause**: User doesn't have permission for the bucket

**Solution**: Add bucket to user's `allowed_buckets`:
```yaml
users:
  - access_key: "alice-key"
    secret_key: "alice-secret"
    allowed_buckets:
      - "my-bucket"
      - "new-bucket"  # ← Add this
```

### Connection Refused

**Cause**: Proxy not running or wrong port

**Solution**:
1. Check proxy is running: `curl http://localhost:8080/`
2. Check port in `config.yaml` matches `--endpoint-url`

### High Memory Usage

**Cause**: Clients not using streaming

**Solution**: Use `UNSIGNED-PAYLOAD` in client configuration (most modern SDKs do this automatically)

## Architecture Overview

```
┌─────────────┐
│   Client    │  (aws-cli, boto3, etc.)
│  + SigV4    │
└──────┬──────┘
       │ 1. Sign request with user credentials
       ▼
┌─────────────┐
│  IAM Proxy  │  (This application)
│   :8080     │
└──────┬──────┘
       │ 2. Validate signature
       │ 3. Check authorization
       │ 4. Re-sign with master credentials
       ▼
┌─────────────┐
│   Hetzner   │  (Object Storage Backend)
│   Storage   │
└─────────────┘
```

## Key Features

✅ **AWS SigV4 Authentication** - Full signature validation
✅ **Zero-Copy Streaming** - Memory efficient for large files
✅ **Bucket-Level RBAC** - Fine-grained access control
✅ **High Performance** - Handles 1000+ concurrent connections
✅ **S3 Compatible** - Works with all S3 clients/SDKs

## Configuration Quick Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `server.listen_addr` | `:8080` | Server bind address |
| `server.read_timeout` | `300s` | Request read timeout |
| `server.write_timeout` | `300s` | Response write timeout |
| `logging.level` | `info` | Log level (debug, info, warn, error) |
| `logging.format` | `json` | Log format (json, console) |

## Security Notes

⚠️ **For Production**:
1. Use HTTPS (deploy behind Nginx/Traefik with SSL)
2. Secure `config.yaml` permissions: `chmod 600 config.yaml`
3. Use strong random credentials
4. Enable firewall rules
5. Run as non-root user
6. Keep dependencies updated

## Performance Tips

- Use multipart uploads for files > 10 MB
- Enable HTTP/2 with HTTPS
- Increase file descriptors: `ulimit -n 65535`
- Tune `GOMAXPROCS`: `export GOMAXPROCS=<num_cores>`

## Getting Help

- 📖 **Documentation**: [README.md](README.md)
- 🐛 **Issues**: [GitHub Issues](https://github.com/pratikbin/go-s3-rbac-single-bucket/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/pratikbin/go-s3-rbac-single-bucket/discussions)

---

**Ready to deploy?** See [DEPLOYMENT.md](DEPLOYMENT.md) for production setup.

