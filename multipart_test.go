package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMultipartUploadComplete verifies that CompleteMultipartUpload XML body
// is correctly proxied even when using UNSIGNED-PAYLOAD for signature
func TestMultipartUploadComplete_WithUnsignedPayload(t *testing.T) {
	// Create test user
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	store := NewIdentityStore(users)
	auth := NewAuthMiddleware(store)
	masterCreds := MasterCredentials{
		AccessKey: "master-key",
		SecretKey: "master-secret",
		Endpoint:  "https://backend.example.com",
		Region:    "us-east-1",
	}
	securityConfig := SecurityConfig{
		VerifyContentIntegrity: false, // Use UNSIGNED-PAYLOAD (default)
	}
	proxy := NewProxyHandler(auth, masterCreds, securityConfig)

	// XML body for CompleteMultipartUpload
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUpload>
  <Part>
    <PartNumber>1</PartNumber>
    <ETag>"abc123"</ETag>
  </Part>
  <Part>
    <PartNumber>2</PartNumber>
    <ETag>"def456"</ETag>
  </Part>
</CompleteMultipartUpload>`

	// Create POST request to complete multipart upload
	req := httptest.NewRequest("POST", "/test-bucket/large-file.bin?uploadId=ABC123", strings.NewReader(xmlBody))
	req.Host = "s3.example.com"
	req.Header.Set("Content-Type", "application/xml")
	req.ContentLength = int64(len(xmlBody))

	// When client uses UNSIGNED-PAYLOAD (common for XML bodies)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")

	// Call director to prepare request for backend
	proxy.director(req)

	// Verify request was signed with UNSIGNED-PAYLOAD
	backendHash := req.Header.Get("X-Amz-Content-Sha256")
	if backendHash != "UNSIGNED-PAYLOAD" {
		t.Errorf("Expected UNSIGNED-PAYLOAD, got: %s", backendHash)
	}

	// Verify Authorization header was set (request was signed)
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		t.Error("Expected Authorization header to be set")
	}
	if !strings.Contains(authHeader, "AWS4-HMAC-SHA256") {
		t.Errorf("Expected AWS4-HMAC-SHA256 signature, got: %s", authHeader)
	}

	// CRITICAL: Verify the XML body is still present and readable
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	if string(bodyBytes) != xmlBody {
		t.Errorf("Body mismatch:\nExpected: %s\nGot: %s", xmlBody, string(bodyBytes))
	}

	// Verify body contains the part ETags (Hetzner will parse this)
	if !strings.Contains(string(bodyBytes), `<ETag>"abc123"</ETag>`) {
		t.Error("Body should contain part 1 ETag")
	}
	if !strings.Contains(string(bodyBytes), `<ETag>"def456"</ETag>`) {
		t.Error("Body should contain part 2 ETag")
	}
}

// TestMultipartUploadComplete_WithContentHash verifies that when a client
// provides a content hash for the XML body, it can be optionally verified
func TestMultipartUploadComplete_WithContentHash(t *testing.T) {
	// Create test user
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	store := NewIdentityStore(users)
	auth := NewAuthMiddleware(store)
	masterCreds := MasterCredentials{
		AccessKey: "master-key",
		SecretKey: "master-secret",
		Endpoint:  "https://backend.example.com",
		Region:    "us-east-1",
	}
	securityConfig := SecurityConfig{
		VerifyContentIntegrity: true, // Enable verification
	}
	proxy := NewProxyHandler(auth, masterCreds, securityConfig)

	// XML body for CompleteMultipartUpload
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUpload>
  <Part>
    <PartNumber>1</PartNumber>
    <ETag>"abc123"</ETag>
  </Part>
</CompleteMultipartUpload>`

	// Calculate correct hash
	hash := sha256.Sum256([]byte(xmlBody))
	hashStr := hex.EncodeToString(hash[:])

	// Create POST request with content hash
	req := httptest.NewRequest("POST", "/test-bucket/large-file.bin?uploadId=ABC123", strings.NewReader(xmlBody))
	req.Host = "s3.example.com"
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("X-Amz-Content-Sha256", hashStr)
	req.ContentLength = int64(len(xmlBody))

	// Call director
	proxy.director(req)

	// When integrity verification is enabled and hash is provided,
	// the verified hash should be forwarded to backend
	backendHash := req.Header.Get("X-Amz-Content-Sha256")
	if backendHash != hashStr {
		t.Errorf("Expected verified hash %s, got: %s", hashStr, backendHash)
	}

	// Body should still be readable
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	if string(bodyBytes) != xmlBody {
		t.Errorf("Body mismatch after verification")
	}
}

// TestMultipartInitiate verifies that InitiateMultipartUpload (POST without uploadId)
// works correctly with empty body
func TestMultipartInitiate_EmptyBody(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	store := NewIdentityStore(users)
	auth := NewAuthMiddleware(store)
	masterCreds := MasterCredentials{
		AccessKey: "master-key",
		SecretKey: "master-secret",
		Endpoint:  "https://backend.example.com",
		Region:    "us-east-1",
	}
	securityConfig := SecurityConfig{
		VerifyContentIntegrity: false,
	}
	proxy := NewProxyHandler(auth, masterCreds, securityConfig)

	// POST with ?uploads query parameter initiates multipart upload (empty body)
	req := httptest.NewRequest("POST", "/test-bucket/large-file.bin?uploads", nil)
	req.Host = "s3.example.com"
	req.ContentLength = 0

	// Call director
	proxy.director(req)

	// Should use UNSIGNED-PAYLOAD for empty body
	backendHash := req.Header.Get("X-Amz-Content-Sha256")
	if backendHash != "UNSIGNED-PAYLOAD" {
		t.Errorf("Expected UNSIGNED-PAYLOAD for empty body, got: %s", backendHash)
	}

	// Should have authorization header
	if req.Header.Get("Authorization") == "" {
		t.Error("Expected Authorization header to be set")
	}
}

// TestMultipartUploadPart verifies that uploading individual parts works
func TestMultipartUploadPart_BinaryData(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	store := NewIdentityStore(users)
	auth := NewAuthMiddleware(store)
	masterCreds := MasterCredentials{
		AccessKey: "master-key",
		SecretKey: "master-secret",
		Endpoint:  "https://backend.example.com",
		Region:    "us-east-1",
	}
	securityConfig := SecurityConfig{
		VerifyContentIntegrity: false, // Streaming mode for large parts
	}
	proxy := NewProxyHandler(auth, masterCreds, securityConfig)

	// Binary data for a part (simulate 5MB part)
	partData := bytes.Repeat([]byte("A"), 5*1024*1024) // 5MB

	// PUT with partNumber and uploadId
	req := httptest.NewRequest("PUT", "/test-bucket/large-file.bin?partNumber=1&uploadId=ABC123", bytes.NewReader(partData))
	req.Host = "s3.example.com"
	req.ContentLength = int64(len(partData))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD") // Common for large parts

	// Call director
	proxy.director(req)

	// Should use UNSIGNED-PAYLOAD for streaming efficiency
	backendHash := req.Header.Get("X-Amz-Content-Sha256")
	if backendHash != "UNSIGNED-PAYLOAD" {
		t.Errorf("Expected UNSIGNED-PAYLOAD for large part, got: %s", backendHash)
	}

	// Verify Content-Length is preserved (critical for multipart)
	if req.ContentLength != int64(len(partData)) {
		t.Errorf("Content-Length mismatch: expected %d, got %d", len(partData), req.ContentLength)
	}

	// Body should still be readable (even though we don't buffer it)
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	if len(bodyBytes) != len(partData) {
		t.Errorf("Body size mismatch: expected %d, got %d", len(partData), len(bodyBytes))
	}
}
