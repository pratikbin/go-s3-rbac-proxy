# Multi-stage build for minimal image size
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make ca-certificates

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o s3-proxy .

# Final stage - minimal runtime image
FROM alpine:latest

# Install CA certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 s3proxy && \
    adduser -D -u 1000 -G s3proxy s3proxy

# Copy binary from builder
COPY --from=builder /build/s3-proxy /usr/local/bin/s3-proxy

# Create config directory
RUN mkdir -p /etc/s3-proxy && chown s3proxy:s3proxy /etc/s3-proxy

# Switch to non-root user
USER s3proxy

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Run the proxy
ENTRYPOINT ["/usr/local/bin/s3-proxy"]
CMD ["-config", "/etc/s3-proxy/config.yaml"]

