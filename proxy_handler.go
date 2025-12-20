package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Context keys for storing user and bucket information
type contextKey string

const (
	contextKeyUser   contextKey = "user"
	contextKeyBucket contextKey = "bucket"
)

// PERFORMANCE: BufferPool implements httputil.BufferPool for zero-allocation buffer reuse
// Using 64KB buffers (optimal for S3 chunk sizes and network MTU multiples)
const optimalBufferSize = 64 * 1024 // 64KB

// Hetzner Object Store Limits (documented for reference):
//
// Per-bucket limits:
//   - 750 requests/s per bucket
//   - 10 Gbit/s per bucket (read or write)
//   - Up to 50,000,000 objects per bucket
//   - Up to 100 TB per bucket
//
// Per-object limits:
//   - Up to 5 TB per object
//   - Up to 5 GB per object in single PUT
//   - Up to 5 GB per part in multipart upload
//   - Up to 10,000 parts in multipart upload
//   - Up to 8 KB of metadata per object
//
// Per-source-IP limits (shared across all buckets from this proxy):
//   - Up to 256 active parallel TCP sessions per source IP
//   - Up to 750 requests/s per source IP
//
// Transport configuration (derived from Hetzner limits):
const (
	// Allocate 50 connections per bucket to support 5+ buckets under the 256/IP limit
	// This allows parallel multipart uploads while respecting Hetzner's constraints
	transportMaxConnsPerBucket     = 50
	transportMaxIdleConnsPerBucket = 100
)

type BufferPool struct {
	pool sync.Pool
}

// NewBufferPool creates a new buffer pool with fixed-size buffers
func NewBufferPool() *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				// Allocate exactly 64KB buffers
				buf := make([]byte, optimalBufferSize)
				return &buf
			},
		},
	}
}

// Get retrieves a buffer from the pool
func (bp *BufferPool) Get() []byte {
	bufPtr := bp.pool.Get().(*[]byte)
	return *bufPtr
}

// Put returns a buffer to the pool
func (bp *BufferPool) Put(buf []byte) {
	if cap(buf) != optimalBufferSize {
		// Don't pool buffers of wrong size
		return
	}
	// Reset the slice to full capacity before returning to pool
	buf = buf[:cap(buf)]
	bp.pool.Put(&buf)
}

// ProxyHandler handles the reverse proxy logic
type ProxyHandler struct {
	authMiddleware *AuthMiddleware
	masterCreds    MasterCredentials
	backendURL     *url.URL       // Parsed once, reused for every request
	backendSigner  *BackendSigner // Custom SigV4 signer for backend requests
	proxy          *httputil.ReverseProxy
	bufferPool     *BufferPool  // Zero-allocation buffer pool
	transports     sync.Map     // Per-bucket transports: map[string]*http.Transport
	transportMu    sync.RWMutex // Protects transport creation
}

// NewProxyHandler creates a new proxy handler with zero-allocation optimizations
func NewProxyHandler(authMiddleware *AuthMiddleware, masterCreds MasterCredentials) *ProxyHandler {
	// Parse backend URL once during initialization
	backendURL, err := url.Parse(masterCreds.Endpoint)
	if err != nil {
		panic(fmt.Sprintf("invalid backend endpoint: %v", err))
	}

	// Initialize buffer pool for zero-allocation data transfer
	bufferPool := NewBufferPool()

	// Create custom backend signer with full control over path encoding
	backendSigner := NewBackendSigner(
		masterCreds.AccessKey,
		masterCreds.SecretKey,
		masterCreds.Region,
	)

	handler := &ProxyHandler{
		authMiddleware: authMiddleware,
		masterCreds:    masterCreds,
		backendURL:     backendURL,
		backendSigner:  backendSigner,
		bufferPool:     bufferPool,
		// transports is initialized as sync.Map (zero value is ready to use)
	}

	// PERFORMANCE: Create reverse proxy with aggressive streaming optimizations
	// NOTE: Transport is now determined per-request based on target bucket
	handler.proxy = &httputil.ReverseProxy{
		Director:   handler.director,
		Transport:  handler,    // ProxyHandler implements RoundTripper interface
		BufferPool: bufferPool, // Use pooled buffers instead of allocating new ones
		// CRITICAL: FlushInterval -1 = immediate flush after each write
		// This ensures data flows immediately from client → proxy → backend
		// without buffering delays. Essential for high-throughput streaming.
		FlushInterval:  -1 * time.Nanosecond, // Immediate flush
		ModifyResponse: handler.modifyResponse,
		ErrorHandler:   handler.errorHandler,
	}

	Logger.Info("proxy handler initialized with per-bucket transport isolation",
		zap.Int("buffer_size_kb", optimalBufferSize/1024),
		zap.String("flush_mode", "immediate"),
		zap.String("transport_mode", "per-bucket"),
	)

	return handler
}

// ServeHTTP handles incoming requests
func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Log request
	Logger.Info("incoming request",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("remote_addr", r.RemoteAddr),
	)

	// Validate authentication
	user, err := p.authMiddleware.ValidateRequest(r)
	if err != nil {
		Logger.Warn("authentication failed",
			zap.Error(err),
			zap.String("path", r.URL.Path),
		)
		p.writeS3Error(w, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided.", http.StatusForbidden)
		return
	}

	// SECURITY FIX: Intercept ListBuckets (GET /) to prevent exposing all buckets
	if r.URL.Path == "/" && r.Method == "GET" {
		Logger.Debug("intercepting ListBuckets request", zap.String("user", user.AccessKey))
		p.handleListBuckets(w, r, user)
		return
	}

	// Extract bucket name from path
	bucket := extractBucketFromPath(r.URL.Path)
	if bucket == "" {
		// Other service-level operations (not ListBuckets)
		Logger.Debug("service-level operation", zap.String("path", r.URL.Path))
		// Block unknown service-level operations for security
		p.writeS3Error(w, "AccessDenied", "Service-level operation not supported", http.StatusForbidden)
		return
	}

	// Check authorization
	if !user.IsAuthorized(bucket) {
		Logger.Warn("authorization failed",
			zap.String("user", user.AccessKey),
			zap.String("bucket", bucket),
		)
		p.writeS3Error(w, "AccessDenied", "Access Denied", http.StatusForbidden)
		return
	}

	// Store user in context for use in director (using typed keys to avoid collisions)
	ctx := context.WithValue(r.Context(), contextKeyUser, user)
	ctx = context.WithValue(ctx, contextKeyBucket, bucket)
	r = r.WithContext(ctx)

	// Proxy the request
	p.proxy.ServeHTTP(w, r)

	duration := time.Since(startTime)
	Logger.Info("request completed",
		zap.String("user", user.AccessKey),
		zap.String("bucket", bucket),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.Duration("duration", duration),
	)
}

// handleListBuckets handles the ListBuckets (GET /) request
// Returns only buckets the user is authorized to access
func (p *ProxyHandler) handleListBuckets(w http.ResponseWriter, r *http.Request, user *User) {
	// Build list of authorized buckets
	var buckets []string

	if len(user.AllowedBuckets) == 1 && user.AllowedBuckets[0] == "*" {
		// Wildcard user - we still can't list ALL backend buckets for security
		// Instead, return an empty list or require explicit bucket names
		// For security, we return empty list to prevent information disclosure
		Logger.Debug("wildcard user attempted ListBuckets",
			zap.String("user", user.AccessKey),
		)
		buckets = []string{} // Empty list for wildcard users
	} else {
		// Return only explicitly allowed buckets
		buckets = user.AllowedBuckets
	}

	// Build S3 ListAllMyBucketsResult XML response
	buf := getBuffer()
	defer putBuffer(buf)

	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	buf.WriteString(`<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	buf.WriteString(`<Owner>`)
	buf.WriteString(`<ID>`)
	buf.WriteString(user.AccessKey)
	buf.WriteString(`</ID>`)
	buf.WriteString(`<DisplayName>`)
	buf.WriteString(user.AccessKey)
	buf.WriteString(`</DisplayName>`)
	buf.WriteString(`</Owner>`)
	buf.WriteString(`<Buckets>`)

	// Add each authorized bucket
	creationDate := time.Now().UTC().Format(time.RFC3339)
	for _, bucket := range buckets {
		buf.WriteString(`<Bucket>`)
		buf.WriteString(`<Name>`)
		buf.WriteString(bucket)
		buf.WriteString(`</Name>`)
		buf.WriteString(`<CreationDate>`)
		buf.WriteString(creationDate)
		buf.WriteString(`</CreationDate>`)
		buf.WriteString(`</Bucket>`)
	}

	buf.WriteString(`</Buckets>`)
	buf.WriteString(`</ListAllMyBucketsResult>`)

	// Write response
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(buf.Bytes()); err != nil {
		Logger.Error("failed to write ListBuckets response", zap.Error(err))
	}

	Logger.Info("ListBuckets response sent",
		zap.String("user", user.AccessKey),
		zap.Int("bucket_count", len(buckets)),
	)
}

// director modifies the request before sending to backend
func (p *ProxyHandler) director(req *http.Request) {
	// Store original host for logging (only in debug mode)
	var originalHost string
	if Logger.Core().Enabled(zap.DebugLevel) {
		originalHost = req.Host
	}

	// 1. Rewrite Host to backend
	req.URL.Scheme = p.backendURL.Scheme
	req.URL.Host = p.backendURL.Host
	req.Host = p.backendURL.Host

	// 2. CRITICAL: Do NOT remove or modify Content-Length header
	// Hetzner/Ceph Object Storage requires exact Content-Length for multipart uploads
	// httputil.ReverseProxy preserves it automatically, we just ensure we don't touch it

	// 3. Check if this is a streaming/chunked upload (mc uses this)
	originalContentSha256 := req.Header.Get("X-Amz-Content-Sha256")
	isStreamingUpload := strings.Contains(originalContentSha256, "STREAMING")

	// 4. Remove ONLY client's authorization headers (leave Content-Length, Content-Type, etc.)
	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Date")
	req.Header.Del("X-Amz-Security-Token")
	req.Header.Del("X-Amz-Content-Sha256")

	// 5. Sign the request with our custom backend signer
	// CRITICAL: Our custom signer uses S3EncodePath internally, giving us full control
	// over the canonical URI encoding. It will use req.URL.Path and encode it strictly
	// according to S3 rules, ensuring the signature matches what the HTTP client sends.
	// IMPORTANT: AWS SigV4 requires UTC timestamps
	payloadHash := "UNSIGNED-PAYLOAD"
	err := p.backendSigner.SignRequest(req, payloadHash, time.Now().UTC())
	if err != nil {
		Logger.Error("failed to sign backend request", zap.Error(err))
		return
	}

	// 6. Debug logging (only when debug level is enabled)
	if Logger.Core().Enabled(zap.DebugLevel) {
		Logger.Debug("request signed and forwarding to backend",
			zap.String("original_host", originalHost),
			zap.String("backend_host", req.Host),
			zap.String("path", req.URL.Path),
			zap.String("encoded_path", S3EncodePath(req.URL.Path)),
			zap.Bool("streaming", isStreamingUpload),
		)
	}
}

// RoundTrip implements http.RoundTripper interface for per-bucket transport routing
// This allows us to use different transports for different buckets while maintaining
// connection pool isolation to respect Hetzner's per-bucket rate limits
func (p *ProxyHandler) RoundTrip(req *http.Request) (*http.Response, error) {
	// Extract bucket from context (set by ServeHTTP)
	bucket := ""
	if b, ok := req.Context().Value(contextKeyBucket).(string); ok {
		bucket = b
	}

	// Log if bucket is empty (shouldn't happen, but defensive)
	if bucket == "" && Logger.Core().Enabled(zap.DebugLevel) {
		Logger.Debug("RoundTrip called with empty bucket",
			zap.String("method", req.Method),
			zap.String("url", req.URL.String()),
		)
	}

	// Get or create bucket-specific transport
	transport := p.getOrCreateTransport(bucket)

	// Execute request using bucket-specific transport
	return transport.RoundTrip(req)
}

// getOrCreateTransport returns a bucket-specific transport, creating it if necessary
// Hetzner limits: 750 req/s per bucket, 256 parallel TCP sessions per source IP
func (p *ProxyHandler) getOrCreateTransport(bucket string) *http.Transport {
	// Try to load existing transport
	if t, ok := p.transports.Load(bucket); ok {
		return t.(*http.Transport)
	}

	// Need to create new transport - use mutex to prevent duplicate creation
	p.transportMu.Lock()
	defer p.transportMu.Unlock()

	// Double-check after acquiring lock
	if t, ok := p.transports.Load(bucket); ok {
		return t.(*http.Transport)
	}

	// Create new transport for this bucket
	transport := p.createTransport(bucket)
	p.transports.Store(bucket, transport)

	Logger.Info("created new transport for bucket",
		zap.String("bucket", bucket),
		zap.Int("max_conns_per_host", transportMaxConnsPerBucket),
		zap.Int("max_idle_conns", transportMaxIdleConnsPerBucket),
	)

	return transport
}

// createTransport creates a high-performance HTTP transport optimized for Hetzner S3
// Each bucket gets its own transport to isolate connection pools and respect per-bucket limits
func (p *ProxyHandler) createTransport(bucket string) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		// CRITICAL: Disable HTTP/2 for backend connections
		// HTTP/1.1 is faster for 1:1 high-throughput proxying because:
		// - No stream multiplexing overhead
		// - Simpler flow control
		// - Better for large sequential transfers (like S3 uploads)
		ForceAttemptHTTP2: false,
		// HETZNER: Connection pool sizing per bucket
		// With hetznerMaxParallelSessionsPerIP (256) total sessions per source IP,
		// we allocate transportMaxConnsPerBucket (50) per bucket (supports 5+ buckets)
		// This allows parallel multipart uploads while staying under IP limit
		MaxIdleConns:        transportMaxIdleConnsPerBucket, // Per-bucket pool size
		MaxIdleConnsPerHost: transportMaxConnsPerBucket,     // Per-host limit (Hetzner endpoint)
		MaxConnsPerHost:     transportMaxConnsPerBucket,     // Limit concurrent connections
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		// CRITICAL: Increased timeouts for large multipart uploads
		// Hetzner may take time to process 5GB parts, especially under load
		// 5 seconds allows for backend processing without being too aggressive
		ExpectContinueTimeout: 5 * time.Second,
		// For multipart uploads, backend may take time to allocate space/process
		// 60 seconds should handle even slow responses during peak load
		ResponseHeaderTimeout: 60 * time.Second,
		// PERFORMANCE: Disable compression to reduce CPU overhead
		// S3 objects are often pre-compressed (images, videos, archives)
		DisableCompression: true,
		// CRITICAL: Match buffer sizes with our BufferPool (64KB)
		// This ensures buffers are reused efficiently without reallocations
		WriteBufferSize: optimalBufferSize, // 64KB
		ReadBufferSize:  optimalBufferSize, // 64KB
	}
}

// modifyResponse modifies the backend response before sending to client
func (p *ProxyHandler) modifyResponse(resp *http.Response) error {
	// We can add custom headers or modify response here if needed
	// For now, pass through as-is
	return nil
}

// errorHandler handles errors from the backend
func (p *ProxyHandler) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	// Extract bucket for better logging
	bucket := ""
	if b, ok := r.Context().Value(contextKeyBucket).(string); ok {
		bucket = b
	}

	// Check for context cancellation (client closed connection)
	if err == context.Canceled || err.Error() == "context canceled" {
		Logger.Warn("client canceled request",
			zap.Error(err),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("bucket", bucket),
		)
		// Don't write response for canceled contexts - connection is already closed
		return
	}

	// Check for context timeout
	if err == context.DeadlineExceeded {
		Logger.Error("request timeout",
			zap.Error(err),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("bucket", bucket),
		)
		p.writeS3Error(w, "RequestTimeout", "Your socket connection to the server was not read from or written to within the timeout period.", http.StatusRequestTimeout)
		return
	}

	// Check for EOF
	if err == io.EOF {
		Logger.Error("incomplete body",
			zap.Error(err),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("bucket", bucket),
		)
		p.writeS3Error(w, "IncompleteBody", "You did not provide the number of bytes specified by the Content-Length HTTP header", http.StatusBadRequest)
		return
	}

	// Generic error
	Logger.Error("proxy error",
		zap.Error(err),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("bucket", bucket),
	)
	p.writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", http.StatusInternalServerError)
}

// extractBucketFromPath extracts the bucket name from the URL path
func extractBucketFromPath(path string) string {
	// S3 path formats:
	// Virtual-hosted style: not applicable (client sends to proxy)
	// Path style: /{bucket}/{key}
	// We use path style

	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

// writeS3Error writes an S3 XML error response
func (p *ProxyHandler) writeS3Error(w http.ResponseWriter, code, message string, status int) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)

	errorXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
	<Code>%s</Code>
	<Message>%s</Message>
	<RequestId>%s</RequestId>
</Error>`, code, message, generateRequestID())

	if _, err := w.Write([]byte(errorXML)); err != nil {
		Logger.Error("failed to write error response", zap.Error(err), zap.String("code", code))
	}
}

// generateRequestID generates a simple request ID
func generateRequestID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
