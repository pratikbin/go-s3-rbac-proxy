package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Context keys for storing user and bucket information
// Using unexported int type prevents collisions with string-based keys from other packages
type contextKey int

// #nosec G101
const (
	contextKeyUser contextKey = iota
	contextKeyBucket
)

// XML structures for S3 responses
type S3ErrorResponse struct {
	XMLName   xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
}

type Owner struct {
	XMLName     xml.Name `xml:"Owner"`
	ID          string   `xml:"ID"`
	DisplayName string   `xml:"DisplayName"`
}

type Bucket struct {
	XMLName      xml.Name `xml:"Bucket"`
	Name         string   `xml:"Name"`
	CreationDate string   `xml:"CreationDate"`
}

type ListAllMyBucketsResult struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult"`
	Owner   Owner    `xml:"Owner"`
	Buckets []Bucket `xml:"Buckets>Bucket"`
}

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
// #nosec G101
const (
	// Allocate 50 connections per bucket to support 5+ buckets under the 256/IP limit
	// This allows parallel multipart uploads while respecting Hetzner's constraints
	transportMaxConnsPerBucket     = 50
	transportMaxIdleConnsPerBucket = 100
)

// #nosec G101
const (
	metricsUnknownUser   = "unknown"
	metricsServiceBucket = "service"
)

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

type countingReadCloser struct {
	reader io.ReadCloser
	bytes  int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if n > 0 {
		c.bytes += int64(n)
	}
	return n, err //nolint:wrapcheck // io.EOF must not be wrapped
}

func (c *countingReadCloser) Close() error {
	if err := c.reader.Close(); err != nil {
		return fmt.Errorf("failed to close counting reader: %w", err)
	}
	return nil
}

func (c *countingReadCloser) BytesRead() int64 {
	return c.bytes
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{ResponseWriter: w}
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(data)
	r.bytes += int64(n)
	if err != nil {
		return n, fmt.Errorf("failed to write response: %w", err)
	}
	return n, nil
}

func (r *responseRecorder) Status() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

func (r *responseRecorder) BytesWritten() int64 {
	return r.bytes
}

func (r *responseRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hijack connection: %w", err)
	}
	return conn, rw, nil
}

func (r *responseRecorder) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := r.ResponseWriter.(http.Pusher); ok {
		if err := pusher.Push(target, opts); err != nil {
			return fmt.Errorf("failed to push: %w", err)
		}
		return nil
	}
	return http.ErrNotSupported
}

type BufferPool struct {
	pool sync.Pool
}

// NewBufferPool creates a new buffer pool with fixed-size buffers
func NewBufferPool() *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() any {
				// Allocate exactly 64KB buffers
				buf := make([]byte, optimalBufferSize)
				return &buf
			},
		},
	}
}

// Get retrieves a buffer from the pool
func (bp *BufferPool) Get() []byte {
	recordBufferPoolGet()
	bufPtr := bp.pool.Get().(*[]byte)
	return *bufPtr
}

// Put returns a buffer to the pool
func (bp *BufferPool) Put(buf []byte) {
	if cap(buf) != optimalBufferSize {
		// Don't pool buffers of wrong size
		recordBufferPoolDiscard()
		return
	}
	recordBufferPoolPut()
	// Reset the slice to full capacity before returning to pool
	buf = buf[:cap(buf)]
	bp.pool.Put(&buf)
}

// StreamingUpload tracks an active streaming/chunked upload
type StreamingUpload struct {
	UserAccessKey string
	Bucket        string
	Key           string
	StartTime     time.Time
	LastSeen      time.Time // Last time data was received
	BytesReceived int64
	UploadID      string // For multipart uploads
}

// StreamingUploadTracker manages concurrent streaming uploads with limits
type StreamingUploadTracker struct {
	mu              sync.RWMutex
	uploads         map[string]*StreamingUpload // key: request ID or connection ID
	userUploadCount map[string]int              // user access key -> count
	maxConcurrent   int
	maxSize         int64
	maxDuration     time.Duration
	stopJanitor     chan struct{}
}

// NewStreamingUploadTracker creates a new tracker with security limits
func NewStreamingUploadTracker(maxConcurrent int, maxSize int64, maxDuration time.Duration) *StreamingUploadTracker {
	t := &StreamingUploadTracker{
		uploads:         make(map[string]*StreamingUpload),
		userUploadCount: make(map[string]int),
		maxConcurrent:   maxConcurrent,
		maxSize:         maxSize,
		maxDuration:     maxDuration,
		stopJanitor:     make(chan struct{}),
	}
	return t
}

// StartJanitor runs a background goroutine to clean up stale uploads
func (t *StreamingUploadTracker) StartJanitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				t.cleanupStaleUploads()
			case <-t.stopJanitor:
				ticker.Stop()
				return
			}
		}
	}()
}

// Stop stops the janitor goroutine
func (t *StreamingUploadTracker) Stop() {
	close(t.stopJanitor)
}

func (t *StreamingUploadTracker) cleanupStaleUploads() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	// Idle timeout: if no data for 2 minutes, consider it a zombie
	idleTimeout := 2 * time.Minute

	for id, upload := range t.uploads {
		isStale := false
		var reason string

		// Check absolute duration
		if t.maxDuration > 0 && now.Sub(upload.StartTime) > t.maxDuration {
			isStale = true
			reason = "duration limit exceeded"
		} else if now.Sub(upload.LastSeen) > idleTimeout {
			// Check idle time
			isStale = true
			reason = "idle timeout exceeded"
		}

		if isStale {
			Logger.Warn("cleaning up stale streaming upload",
				zap.String("id", id),
				zap.String("user", upload.UserAccessKey),
				zap.String("bucket", upload.Bucket),
				zap.String("key", upload.Key),
				zap.String("reason", reason),
			)
			t.cleanupUpload(id, upload.UserAccessKey)
		}
	}
}

// TryStartUpload attempts to start a new streaming upload with security checks
func (t *StreamingUploadTracker) TryStartUpload(id, userAccessKey, bucket, key, uploadID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check user concurrency limit
	if t.maxConcurrent > 0 {
		currentCount := t.userUploadCount[userAccessKey]
		if currentCount >= t.maxConcurrent {
			return fmt.Errorf("user %s has reached maximum concurrent streaming uploads (%d)", userAccessKey, t.maxConcurrent)
		}
	}

	// Create and register the upload
	now := time.Now()
	upload := &StreamingUpload{
		UserAccessKey: userAccessKey,
		Bucket:        bucket,
		Key:           key,
		StartTime:     now,
		LastSeen:      now,
		BytesReceived: 0,
		UploadID:      uploadID,
	}

	t.uploads[id] = upload
	t.userUploadCount[userAccessKey]++

	return nil
}

// UpdateBytes updates the byte count for an upload and checks size limits
func (t *StreamingUploadTracker) UpdateBytes(id string, bytes int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	upload, exists := t.uploads[id]
	if !exists {
		return fmt.Errorf("upload not found: %s", id)
	}

	now := time.Now()
	upload.BytesReceived += bytes
	upload.LastSeen = now

	// Check size limit
	if t.maxSize > 0 && upload.BytesReceived > t.maxSize {
		t.cleanupUpload(id, upload.UserAccessKey)
		return fmt.Errorf("streaming upload exceeded maximum size (%d bytes)", t.maxSize)
	}

	// Check duration limit
	if t.maxDuration > 0 && now.Sub(upload.StartTime) > t.maxDuration {
		t.cleanupUpload(id, upload.UserAccessKey)
		return fmt.Errorf("streaming upload exceeded maximum duration (%v)", t.maxDuration)
	}

	return nil
}

// CompleteUpload marks an upload as completed and cleans up resources
func (t *StreamingUploadTracker) CompleteUpload(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if upload, exists := t.uploads[id]; exists {
		t.cleanupUpload(id, upload.UserAccessKey)
	}
}

// cleanupUpload removes an upload and updates user count
func (t *StreamingUploadTracker) cleanupUpload(id, userAccessKey string) {
	delete(t.uploads, id)
	if count, exists := t.userUploadCount[userAccessKey]; exists {
		if count <= 1 {
			delete(t.userUploadCount, userAccessKey)
		} else {
			t.userUploadCount[userAccessKey] = count - 1
		}
	}
}

type streamingReader struct {
	io.ReadCloser
	id          string
	tracker     *StreamingUploadTracker
	recorder    http.ResponseWriter
	idleTimeout time.Duration
}

func (r *streamingReader) Read(p []byte) (int, error) {
	if r.idleTimeout > 0 {
		// Set read deadline to catch idle connections
		rc := http.NewResponseController(r.recorder)
		if err := rc.SetReadDeadline(time.Now().Add(r.idleTimeout)); err != nil {
			// Some writers might not support setting deadlines (e.g. in tests)
			// We log it but continue as the janitor provides secondary protection
			Logger.Debug("failed to set read deadline", zap.Error(err))
		}
	}

	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		if updateErr := r.tracker.UpdateBytes(r.id, int64(n)); updateErr != nil {
			// If limits exceeded (size/duration), return error to terminate the upload
			return n, updateErr
		}
	}
	return n, err //nolint:wrapcheck // standard io behavior
}

func (r *streamingReader) Close() error {
	r.tracker.CompleteUpload(r.id)
	return r.ReadCloser.Close() //nolint:wrapcheck
}

// ProxyHandler handles the reverse proxy logic
type ProxyHandler struct {
	authMiddleware *AuthMiddleware
	masterCreds    MasterCredentials
	securityConfig SecurityConfig
	backendURL     *url.URL       // Parsed once, reused for every request
	backendSigner  *BackendSigner // Custom SigV4 signer for backend requests
	proxy          *httputil.ReverseProxy
	bufferPool     *BufferPool  // Zero-allocation buffer pool
	transports     sync.Map     // Per-bucket transports: map[string]*http.Transport
	transportMu    sync.RWMutex // Protects transport creation
	uploadTracker  *StreamingUploadTracker
}

// NewProxyHandler creates a new proxy handler with zero-allocation optimizations
func NewProxyHandler(authMiddleware *AuthMiddleware, masterCreds MasterCredentials, securityConfig SecurityConfig) *ProxyHandler {
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

	// Initialize streaming upload tracker with security limits
	uploadTracker := NewStreamingUploadTracker(
		securityConfig.MaxConcurrentStreamingUploads,
		securityConfig.MaxStreamingUploadSize,
		securityConfig.GetMaxStreamingUploadDuration(),
	)
	// Start background janitor to clean up stale uploads
	uploadTracker.StartJanitor(1 * time.Minute)

	handler := &ProxyHandler{
		authMiddleware: authMiddleware,
		masterCreds:    masterCreds,
		securityConfig: securityConfig,
		backendURL:     backendURL,
		backendSigner:  backendSigner,
		bufferPool:     bufferPool,
		uploadTracker:  uploadTracker,
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

// Stop stops background tasks
func (p *ProxyHandler) Stop() {
	if p.uploadTracker != nil {
		p.uploadTracker.Stop()
	}
}

// ServeHTTP handles incoming requests
func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	recorder := newResponseRecorder(w)

	inFlightRequests.Inc()
	defer inFlightRequests.Dec()

	var bodyCounter *countingReadCloser
	if r.Body != nil {
		bodyCounter = &countingReadCloser{reader: r.Body}
		r.Body = bodyCounter
	}

	bucket := extractBucket(r)
	bucketLabel := bucket
	if bucketLabel == "" {
		bucketLabel = metricsServiceBucket
	}
	userLabel := metricsUnknownUser

	defer func() {
		duration := time.Since(startTime)
		statusCode := recorder.Status()
		recordRequestMetrics(r.Method, strconv.Itoa(statusCode), bucketLabel, userLabel, duration.Seconds())
		if bodyCounter != nil {
			recordDataTransfer("inbound", userLabel, bucketLabel, bodyCounter.BytesRead())
		}
		recordDataTransfer("outbound", userLabel, bucketLabel, recorder.BytesWritten())
	}()

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
		p.writeS3Error(recorder, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided.", http.StatusForbidden)
		return
	}
	userLabel = user.AccessKey

	// SECURITY FIX: Intercept ListBuckets (GET /) to prevent exposing all buckets
	if r.URL.Path == "/" && r.Method == http.MethodGet {
		Logger.Debug("intercepting ListBuckets request", zap.String("user", user.AccessKey))
		p.handleListBuckets(recorder, r, user)
		return
	}

	// Extract bucket name from path
	if bucket == "" {
		// Other service-level operations (not ListBuckets)
		Logger.Debug("service-level operation", zap.String("path", r.URL.Path))
		// Block unknown service-level operations for security
		p.writeS3Error(recorder, "AccessDenied", "Service-level operation not supported", http.StatusForbidden)
		return
	}

	// Check authorization
	if !user.IsAuthorized(bucket) {
		Logger.Warn("authorization failed",
			zap.String("user", user.AccessKey),
			zap.String("bucket", bucket),
		)
		recordRBACDenied(user.AccessKey, bucket)
		p.writeS3Error(recorder, "AccessDenied", "Access Denied", http.StatusForbidden)
		return
	}

	// Handle streaming upload tracking and security limits
	if r.Header.Get(contentSHA256Header) == streamingPayload {
		requestID := generateRequestID()
		uploadID := r.URL.Query().Get("uploadId")

		if err := p.uploadTracker.TryStartUpload(requestID, user.AccessKey, bucket, r.URL.Path, uploadID); err != nil {
			Logger.Warn("streaming upload rejected",
				zap.Error(err),
				zap.String("user", user.AccessKey),
				zap.String("bucket", bucket),
			)
			p.writeS3Error(recorder, "ServiceUnavailable", "Too many concurrent streaming uploads", http.StatusServiceUnavailable)
			return
		}

		// Wrap body with streaming tracker and idle timeout enforcement
		// Use 60s idle timeout for streaming uploads
		r.Body = &streamingReader{
			ReadCloser:  r.Body,
			id:          requestID,
			tracker:     p.uploadTracker,
			recorder:    recorder,
			idleTimeout: 60 * time.Second,
		}

		Logger.Info("tracking streaming upload",
			zap.String("id", requestID),
			zap.String("user", user.AccessKey),
			zap.String("bucket", bucket),
		)
	}

	// Store user in context for use in director (using typed keys to avoid collisions)
	ctx := context.WithValue(r.Context(), contextKeyUser, user)
	ctx = context.WithValue(ctx, contextKeyBucket, bucket)
	r = r.WithContext(ctx)

	// Proxy the request
	p.proxy.ServeHTTP(recorder, r)

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
func (p *ProxyHandler) handleListBuckets(w http.ResponseWriter, _ *http.Request, user *User) {
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
	creationDate := time.Now().UTC().Format(time.RFC3339)

	// Create bucket list
	var bucketList []Bucket
	for _, bucketName := range buckets {
		bucketList = append(bucketList, Bucket{
			Name:         bucketName,
			CreationDate: creationDate,
		})
	}

	result := ListAllMyBucketsResult{
		Owner: Owner{
			ID:          user.AccessKey,
			DisplayName: user.AccessKey,
		},
		Buckets: bucketList,
	}

	// Write response
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	xmlHeader := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	if _, err := w.Write(xmlHeader); err != nil {
		Logger.Error("failed to write XML header", zap.Error(err))
		return
	}

	encoder := xml.NewEncoder(w)
	encoder.Indent("", "\t")
	if err := encoder.Encode(result); err != nil {
		Logger.Error("failed to encode ListBuckets response", zap.Error(err))
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

	// 4. Integrity Verification (Optional - Performance vs Security Trade-off)
	// When enabled, verifies that the body matches the client-provided X-Amz-Content-Sha256 hash
	// This prevents tampering between client signature and proxy, at the cost of buffering the body
	var payloadHash string
	if p.securityConfig.VerifyContentIntegrity &&
		originalContentSha256 != "" &&
		originalContentSha256 != unsignedPayload &&
		!isStreamingUpload &&
		req.Body != nil {
		// SECURITY: Check body size to prevent OOM attacks
		// If Content-Length exceeds max size, fall back to UNSIGNED-PAYLOAD
		if req.ContentLength > p.securityConfig.MaxVerifyBodySize {
			Logger.Warn("body too large for integrity verification - falling back to UNSIGNED-PAYLOAD",
				zap.String("path", req.URL.Path),
				zap.Int64("content_length", req.ContentLength),
				zap.Int64("max_size", p.securityConfig.MaxVerifyBodySize))
			payloadHash = unsignedPayload
		} else if req.ContentLength < 0 {
			// Content-Length unknown (chunked encoding) - skip verification
			Logger.Debug("unknown content length - skipping integrity verification",
				zap.String("path", req.URL.Path))
			payloadHash = unsignedPayload
		} else {
			// Size is within limits - proceed with verification
			// Read and buffer the entire body to compute its hash
			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				Logger.Error("failed to read body for integrity verification",
					zap.Error(err),
					zap.String("path", req.URL.Path))
				return
			}
			if err := req.Body.Close(); err != nil {
				Logger.Warn("failed to close request body",
					zap.Error(err),
					zap.String("path", req.URL.Path))
			}

			// Double-check actual size (in case Content-Length was wrong)
			if int64(len(bodyBytes)) > p.securityConfig.MaxVerifyBodySize {
				Logger.Warn("actual body size exceeds limit - security violation detected",
					zap.String("path", req.URL.Path),
					zap.Int("actual_size", len(bodyBytes)),
					zap.Int64("claimed_size", req.ContentLength),
					zap.Int64("max_size", p.securityConfig.MaxVerifyBodySize))
				// Don't forward - this could be an attack
				return
			}

			// Compute SHA256 of the actual body
			hasher := sha256.New()
			hasher.Write(bodyBytes)
			computedHash := hex.EncodeToString(hasher.Sum(nil))

			// Verify it matches the client's claim
			if computedHash != strings.ToLower(originalContentSha256) {
				Logger.Warn("content integrity verification failed - hash mismatch",
					zap.String("path", req.URL.Path),
					zap.String("claimed_hash", originalContentSha256),
					zap.String("computed_hash", computedHash),
					zap.Int("body_size", len(bodyBytes)))
				// Don't forward the request - this is a security violation
				return
			}

			// Restore the body for backend forwarding
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			// Use the verified hash when signing to backend
			payloadHash = computedHash

			Logger.Debug("content integrity verified",
				zap.String("path", req.URL.Path),
				zap.String("hash", computedHash),
				zap.Int("body_size", len(bodyBytes)))
		}
	} else {
		// Default: Use UNSIGNED-PAYLOAD for maximum streaming performance
		// Rely on TLS for transport security (client→proxy→backend all encrypted)
		payloadHash = unsignedPayload
	}

	// 5. Remove ONLY client's authorization headers (leave Content-Length, Content-Type, etc.)
	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Date")
	req.Header.Del(securityTokenHeaderKey)
	req.Header.Del("X-Amz-Content-Sha256")

	// 6. Sign the request with our custom backend signer
	// CRITICAL: Our custom signer uses S3EncodePath internally, giving us full control
	// over the canonical URI encoding. It will use req.URL.Path and encode it strictly
	// according to S3 rules, ensuring the signature matches what the HTTP client sends.
	// IMPORTANT: AWS SigV4 requires UTC timestamps
	err := p.backendSigner.SignRequest(req, payloadHash, time.Now().UTC())
	if err != nil {
		Logger.Error("failed to sign backend request", zap.Error(err))
		return
	}

	// 7. Debug logging (only when debug level is enabled)
	if Logger.Core().Enabled(zap.DebugLevel) {
		Logger.Debug("request signed and forwarding to backend",
			zap.String("original_host", originalHost),
			zap.String("backend_host", req.Host),
			zap.String("path", req.URL.Path),
			zap.String("encoded_path", S3EncodePath(req.URL.Path)),
			zap.Bool("streaming", isStreamingUpload),
			zap.String("payload_hash", payloadHash),
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
	startTime := time.Now()
	resp, err := transport.RoundTrip(req)
	duration := time.Since(startTime)

	bucketLabel := bucket
	if bucketLabel == "" {
		bucketLabel = metricsServiceBucket
	}
	recordBackendLatency(req.Method, bucketLabel, duration.Seconds())

	if err != nil {
		return nil, fmt.Errorf("backend roundtrip failed: %w", err)
	}

	return resp, nil
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
func (p *ProxyHandler) createTransport(_ string) *http.Transport {
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
func (p *ProxyHandler) modifyResponse(_ *http.Response) error {
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
// LIMITATION: This function only supports path-style addressing (/bucket/key).
// Virtual-host style addressing (bucket.proxy.com/key) is NOT supported.
// For virtual-host style, the bucket would need to be extracted from the Host header,
// but this implementation assumes all clients use path-style.
//
// If a request comes in with virtual-host style (e.g., Host: bucket.proxy.com, Path: /key),
// this function will return an empty string, which will trigger a 403 "Service-level operation not supported"
// error in ServeHTTP. This is the expected behavior for unsupported addressing styles.
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

// extractBucket extracts the bucket name from an HTTP request, supporting both
// path-style (/bucket/key) and virtual-host style (bucket.proxy.com/key) addressing.
func extractBucket(r *http.Request) string {
	// Remove port from host for analysis
	hostWithoutPort := r.Host
	if idx := strings.LastIndex(hostWithoutPort, ":"); idx != -1 {
		// Check if the part after colon is all digits (a port number)
		portPart := hostWithoutPort[idx+1:]
		isPort := true
		for _, c := range portPart {
			if c < '0' || c > '9' {
				isPort = false
				break
			}
		}
		if isPort {
			hostWithoutPort = hostWithoutPort[:idx]
		}
	}

	// Check for virtual-host style: bucket.domain.com
	// Virtual-host style means the host has at least one dot and the first part
	// before the dot is the bucket name
	if strings.Contains(hostWithoutPort, ".") {
		// Split into first part and the rest
		parts := strings.SplitN(hostWithoutPort, ".", 2)
		bucketCandidate := parts[0]
		rest := parts[1]

		// Check if this looks like virtual-host style
		// Rules:
		// 1. bucketCandidate must not be empty
		// 2. bucketCandidate must not be all digits (could be IP octet)
		// 3. rest must contain at least one dot (domain.tld) or be localhost
		if bucketCandidate != "" && !isAllDigits(bucketCandidate) {
			// Check if rest looks like a domain (contains dot) or is localhost
			if strings.Contains(rest, ".") || rest == "localhost" {
				return bucketCandidate
			}
		}
	}

	// Fall back to path-style extraction
	return extractBucketFromPath(r.URL.Path)
}

// isAllDigits checks if a string contains only digits
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// writeS3Error writes an S3 XML error response
func (p *ProxyHandler) writeS3Error(w http.ResponseWriter, code, message string, status int) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)

	errorResp := S3ErrorResponse{
		Code:      code,
		Message:   message,
		RequestID: generateRequestID(),
	}

	xmlHeader := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	if _, err := w.Write(xmlHeader); err != nil {
		Logger.Error("failed to write XML header", zap.Error(err), zap.String("code", code))
		return
	}

	encoder := xml.NewEncoder(w)
	encoder.Indent("", "\t")
	if err := encoder.Encode(errorResp); err != nil {
		Logger.Error("failed to encode error response", zap.Error(err), zap.String("code", code))
	}
}

// generateRequestID generates a cryptographically secure random request ID
// Returns a 16-byte hex string (32 characters) for uniqueness in distributed systems
// Format: lowercase hex (e.g., "a1b2c3d4e5f6789012345678abcdef01")
func generateRequestID() string {
	// Allocate 16 bytes for the random ID
	b := make([]byte, 16)

	// Read cryptographically secure random bytes
	// crypto/rand.Read never returns an error on Unix/Windows systems
	// but we handle it defensively
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID only if crypto/rand fails
		// (should never happen in practice)
		Logger.Error("failed to generate random request ID, falling back to timestamp",
			zap.Error(err))
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}

	// Encode as lowercase hexadecimal string (32 characters)
	return hex.EncodeToString(b)
}
