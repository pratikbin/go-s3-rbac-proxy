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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"go.uber.org/zap"
)

// ProxyHandler handles the reverse proxy logic
type ProxyHandler struct {
	authMiddleware *AuthMiddleware
	masterCreds    MasterCredentials
	backendURL     *url.URL        // Parsed once, reused for every request
	awsCreds       aws.Credentials // Cached credentials
	proxy          *httputil.ReverseProxy
	signer         *v4.Signer
}

// NewProxyHandler creates a new proxy handler
func NewProxyHandler(authMiddleware *AuthMiddleware, masterCreds MasterCredentials) *ProxyHandler {
	// Parse backend URL once during initialization
	backendURL, err := url.Parse(masterCreds.Endpoint)
	if err != nil {
		panic(fmt.Sprintf("invalid backend endpoint: %v", err))
	}

	handler := &ProxyHandler{
		authMiddleware: authMiddleware,
		masterCreds:    masterCreds,
		backendURL:     backendURL,
		awsCreds: aws.Credentials{
			AccessKeyID:     masterCreds.AccessKey,
			SecretAccessKey: masterCreds.SecretKey,
		},
		signer: v4.NewSigner(),
	}

	// Create reverse proxy with custom transport
	handler.proxy = &httputil.ReverseProxy{
		Director:       handler.director,
		Transport:      handler.createTransport(),
		ModifyResponse: handler.modifyResponse,
		ErrorHandler:   handler.errorHandler,
	}

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

	// Extract bucket name from path
	bucket := extractBucketFromPath(r.URL.Path)
	if bucket == "" {
		// Root path or service-level operations (like ListBuckets)
		// For security, we might want to block this or return empty list
		Logger.Debug("service-level operation", zap.String("path", r.URL.Path))
		// Allow it but it will be filtered by backend permissions
	}

	// Check authorization
	if bucket != "" && !user.IsAuthorized(bucket) {
		Logger.Warn("authorization failed",
			zap.String("user", user.AccessKey),
			zap.String("bucket", bucket),
		)
		p.writeS3Error(w, "AccessDenied", "Access Denied", http.StatusForbidden)
		return
	}

	// Store user in context for use in director
	ctx := context.WithValue(r.Context(), "user", user)
	ctx = context.WithValue(ctx, "bucket", bucket)
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

// director modifies the request before sending to backend
func (p *ProxyHandler) director(req *http.Request) {
	// Store original host for logging (only in debug mode)
	var originalHost string
	if Logger.Core().Enabled(zap.DebugLevel) {
		originalHost = req.Host
	}

	// Rewrite request to backend (using pre-parsed URL)
	req.URL.Scheme = p.backendURL.Scheme
	req.URL.Host = p.backendURL.Host
	req.Host = p.backendURL.Host

	// Remove client's authorization headers
	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Date")
	req.Header.Del("X-Amz-Security-Token")
	req.Header.Del("X-Amz-Content-Sha256")

	// Set unsigned payload for streaming
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")

	// Sign the request with master credentials (using cached credentials)
	// Note: We use UNSIGNED-PAYLOAD to avoid reading the body
	err := p.signer.SignHTTP(req.Context(), p.awsCreds, req, "UNSIGNED-PAYLOAD", "s3", p.masterCreds.Region, time.Now())
	if err != nil {
		Logger.Error("failed to sign request", zap.Error(err))
		return
	}

	// Only log in debug mode to reduce overhead
	if Logger.Core().Enabled(zap.DebugLevel) {
		Logger.Debug("request signed and forwarded",
			zap.String("original_host", originalHost),
			zap.String("backend_host", req.Host),
			zap.String("path", req.URL.Path),
		)
	}
}

// createTransport creates a high-performance HTTP transport
func (p *ProxyHandler) createTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1000,              // High connection pool
		MaxIdleConnsPerHost:   100,               // Per-host limit
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,   // Important for 100-continue
		ResponseHeaderTimeout: 30 * time.Second,
		DisableCompression:    false,             // Allow compression
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
	Logger.Error("proxy error",
		zap.Error(err),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
	)

	// Check error type
	if err == io.EOF {
		p.writeS3Error(w, "IncompleteBody", "You did not provide the number of bytes specified by the Content-Length HTTP header", http.StatusBadRequest)
		return
	}

	// Generic error
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

	w.Write([]byte(errorXML))
}

// generateRequestID generates a simple request ID
func generateRequestID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
