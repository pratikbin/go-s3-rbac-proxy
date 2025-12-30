package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// #nosec G101
const (
	// AWS SigV4 algorithm identifier
	algorithm = "AWS4-HMAC-SHA256"
)

// BackendSigner signs backend requests with master credentials using AWS SigV4
// PERFORMANCE: Caches signing key per day to avoid repeated HMAC calculations
type BackendSigner struct {
	accessKey string
	secretKey string
	region    string
	service   string

	// Signing key cache (saves 4 HMAC operations per request)
	mu               sync.RWMutex
	cachedDateStamp  string
	cachedSigningKey []byte
}

// NewBackendSigner creates a new backend signer
func NewBackendSigner(accessKey, secretKey, region string) *BackendSigner {
	return &BackendSigner{
		accessKey: accessKey,
		secretKey: secretKey,
		region:    region,
		service:   "s3",
	}
}

// SignRequest signs an HTTP request for the backend using AWS SigV4
// It uses our strict S3EncodePath for the canonical URI to ensure consistency
func (s *BackendSigner) SignRequest(req *http.Request, payloadHash string, timestamp time.Time) error {
	// 1. Build canonical request components
	method := req.Method

	// CRITICAL: Use our strict S3 encoding for the canonical URI
	canonicalURI := S3EncodePath(req.URL.Path)

	// Build canonical query string
	canonicalQuery := buildCanonicalQueryStringForBackend(req.URL.Query())

	// For backend signing, we need to determine which headers to sign
	// AWS requires: host, x-amz-date, x-amz-content-sha256
	signedHeadersList := []string{"host", "x-amz-content-sha256", "x-amz-date"}

	// 2. Set required headers
	amzDate := timestamp.Format(iso8601BasicFormat)
	dateStamp := timestamp.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	// 3. Build canonical headers
	canonicalHeaders := buildCanonicalHeadersForBackend(req, signedHeadersList)
	signedHeadersStr := strings.Join(signedHeadersList, ";")

	// 4. Build canonical request
	buf := getBuffer()
	defer putBuffer(buf)

	buf.WriteString(method)
	buf.WriteByte('\n')
	buf.WriteString(canonicalURI)
	buf.WriteByte('\n')
	buf.WriteString(canonicalQuery)
	buf.WriteByte('\n')
	buf.WriteString(canonicalHeaders)
	buf.WriteByte('\n')
	buf.WriteString(signedHeadersStr)
	buf.WriteByte('\n')
	buf.WriteString(payloadHash)

	canonicalRequest := buf.String()

	// 5. Build string to sign
	hashedCanonicalRequest := hashSHA256([]byte(canonicalRequest))

	buf2 := getBuffer()
	defer putBuffer(buf2)

	buf2.WriteString(algorithm)
	buf2.WriteString("\n")
	buf2.WriteString(amzDate)
	buf2.WriteString("\n")
	buf2.WriteString(dateStamp)
	buf2.WriteByte('/')
	buf2.WriteString(s.region)
	buf2.WriteByte('/')
	buf2.WriteString(s.service)
	buf2.WriteString("/aws4_request\n")
	buf2.WriteString(hashedCanonicalRequest)

	stringToSign := buf2.String()

	// 6. Calculate signature
	signature := s.calculateSignature(dateStamp, stringToSign)

	// 7. Build and set Authorization header
	credential := fmt.Sprintf("%s/%s/%s/%s/aws4_request",
		s.accessKey, dateStamp, s.region, s.service)

	authHeader := fmt.Sprintf("%s Credential=%s, SignedHeaders=%s, Signature=%s",
		algorithm, credential, signedHeadersStr, signature)

	req.Header.Set("Authorization", authHeader)

	// Debug logging (SECURITY: Never log signatures or credentials)
	if Logger.Core().Enabled(zap.DebugLevel) {
		Logger.Debug("backend request signed",
			zap.String("method", method),
			zap.String("canonical_uri", canonicalURI),
			zap.String("canonical_query", canonicalQuery),
			zap.String("payload_hash", payloadHash),
			// NOTE: Signature omitted for security - never log auth credentials
		)
	}

	return nil
}

// calculateSignature calculates the SigV4 signature for backend requests
// PERFORMANCE: Caches the signing key per day to save 4 HMAC calculations per request
func (s *BackendSigner) calculateSignature(dateStamp, stringToSign string) string {
	// Signing Key Derivation:
	// kSecret = AWS4 + SecretKey
	// kDate = HMAC(kSecret, Date)
	// kRegion = HMAC(kDate, Region)
	// kService = HMAC(kRegion, Service)
	// kSigning = HMAC(kService, "aws4_request")
	// signature = Hex(HMAC(kSigning, StringToSign))

	// Try to get cached signing key (read lock)
	s.mu.RLock()
	if s.cachedDateStamp == dateStamp && s.cachedSigningKey != nil {
		kSigning := s.cachedSigningKey
		s.mu.RUnlock()
		// Fast path: Use cached signing key
		signature := hmacSHA256(kSigning, []byte(stringToSign))
		return hex.EncodeToString(signature)
	}
	s.mu.RUnlock()

	// Slow path: Derive signing key (write lock)
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine might have cached it)
	if s.cachedDateStamp == dateStamp && s.cachedSigningKey != nil {
		kSigning := s.cachedSigningKey
		signature := hmacSHA256(kSigning, []byte(stringToSign))
		return hex.EncodeToString(signature)
	}

	// Derive the signing key (4 HMAC operations)
	kSecret := []byte("AWS4" + s.secretKey)
	kDate := hmacSHA256(kSecret, []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(s.region))
	kService := hmacSHA256(kRegion, []byte(s.service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	// Cache the signing key for this date
	s.cachedDateStamp = dateStamp
	s.cachedSigningKey = kSigning

	// Calculate signature
	signature := hmacSHA256(kSigning, []byte(stringToSign))
	return hex.EncodeToString(signature)
}

// buildCanonicalQueryStringForBackend builds the canonical query string for backend signing
func buildCanonicalQueryStringForBackend(query map[string][]string) string {
	if len(query) == 0 {
		return ""
	}

	// Build list of encoded key=value pairs
	var parts []string
	for k, values := range query {
		encodedKey := uriEncode(k)
		for _, v := range values {
			encodedValue := uriEncode(v)
			parts = append(parts, encodedKey+"="+encodedValue)
		}
	}

	// Sort the encoded pairs
	sort.Strings(parts)

	return strings.Join(parts, "&")
}

// buildCanonicalHeadersForBackend builds the canonical headers string for backend signing
func buildCanonicalHeadersForBackend(req *http.Request, signedHeaders []string) string {
	headerMap := make(map[string]string)
	for _, h := range signedHeaders {
		h = strings.ToLower(strings.TrimSpace(h))
		values := req.Header.Values(h)
		if len(values) > 0 {
			// Join multiple values with comma
			headerMap[h] = strings.Join(values, ",")
		} else if h == "host" {
			// Special case for host header
			headerMap[h] = req.Host
		}
	}

	var keys []string
	for k := range headerMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf := getBuffer()
	defer putBuffer(buf)

	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteString(":")
		buf.WriteString(strings.TrimSpace(headerMap[k]))
		buf.WriteString("\n")
	}

	return buf.String()
}
