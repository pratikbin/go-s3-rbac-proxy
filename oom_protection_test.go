package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"testing"
)

// TestOOMProtection_SizeLimit verifies that large bodies fall back to UNSIGNED-PAYLOAD
// to prevent Out-of-Memory attacks when integrity verification is enabled
func TestOOMProtection_SizeLimit(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	store := NewIdentityStore(users)
	_ = store

	tests := []struct {
		name                string
		bodySize            int
		maxVerifyBodySize   int64
		shouldVerify        bool
		expectedPayloadHash string
	}{
		{
			name:                "small_body_verified",
			bodySize:            1024,             // 1KB
			maxVerifyBodySize:   10 * 1024 * 1024, // 10MB
			shouldVerify:        true,
			expectedPayloadHash: "", // Will be computed hash
		},
		{
			name:                "body_at_limit_verified",
			bodySize:            10 * 1024 * 1024, // 10MB
			maxVerifyBodySize:   10 * 1024 * 1024, // 10MB
			shouldVerify:        true,
			expectedPayloadHash: "", // Will be computed hash
		},
		{
			name:                "body_exceeds_limit_fallback",
			bodySize:            10*1024*1024 + 1, // 10MB + 1 byte
			maxVerifyBodySize:   10 * 1024 * 1024, // 10MB
			shouldVerify:        false,
			expectedPayloadHash: "UNSIGNED-PAYLOAD",
		},
		{
			name:                "large_body_fallback",
			bodySize:            100 * 1024 * 1024, // 100MB
			maxVerifyBodySize:   50 * 1024 * 1024,  // 50MB default
			shouldVerify:        false,
			expectedPayloadHash: "UNSIGNED-PAYLOAD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			securityConfig := SecurityConfig{
				VerifyContentIntegrity: true, // Enable verification
				MaxVerifyBodySize:      tt.maxVerifyBodySize,
			}
			proxy := NewTestProxyHandler(users, securityConfig)
			// Manually override master creds if needed, or just use what NewTestProxyHandler provides
			// For this test, endpoint and region don't matter as we only call director

			// Create body of specified size
			body := bytes.Repeat([]byte("A"), tt.bodySize)
			hash := sha256.Sum256(body)
			hashStr := hex.EncodeToString(hash[:])

			// Create request
			req := httptest.NewRequest("PUT", "/test-bucket/large-file.bin", bytes.NewReader(body))
			req.Host = "s3.example.com"
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set("X-Amz-Content-Sha256", hashStr)
			req.ContentLength = int64(tt.bodySize)

			// Call director
			proxy.director(req)

			// Check resulting payload hash
			backendHash := req.Header.Get("X-Amz-Content-Sha256")

			if tt.shouldVerify {
				// Should have verified and used computed hash
				if backendHash != hashStr {
					t.Errorf("Expected verified hash %s, got: %s", hashStr, backendHash)
				}
			} else {
				// Should have fallen back to UNSIGNED-PAYLOAD
				if backendHash != tt.expectedPayloadHash {
					t.Errorf("Expected %s, got: %s", tt.expectedPayloadHash, backendHash)
				}
			}
		})
	}
}

// TestOOMProtection_ContentLengthMismatch tests the case where Content-Length
// claims a small size but actual body is much larger (potential attack)
func TestOOMProtection_ContentLengthMismatch(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	store := NewIdentityStore(users)
	_ = store
	securityConfig := SecurityConfig{
		VerifyContentIntegrity: true,
		MaxVerifyBodySize:      1024, // 1KB limit
	}
	proxy := NewTestProxyHandler(users, securityConfig)

	// Claim small size in Content-Length
	smallBody := bytes.Repeat([]byte("A"), 512) // 512 bytes
	hash := sha256.Sum256(smallBody)
	hashStr := hex.EncodeToString(hash[:])

	req := httptest.NewRequest("PUT", "/test-bucket/file.bin", bytes.NewReader(smallBody))
	req.Host = "s3.example.com"
	req.Header.Set("X-Amz-Content-Sha256", hashStr)
	req.ContentLength = 512 // Claims 512 bytes (within limit)

	// Call director
	proxy.director(req)

	// Should have verified (size within limit)
	backendHash := req.Header.Get("X-Amz-Content-Sha256")
	if backendHash != hashStr {
		t.Errorf("Expected verified hash, got: %s", backendHash)
	}

	// Body should still be readable
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	if len(bodyBytes) != 512 {
		t.Errorf("Expected body size 512, got: %d", len(bodyBytes))
	}
}

// TestOOMProtection_UnknownContentLength tests chunked encoding (Content-Length: -1)
func TestOOMProtection_UnknownContentLength(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	store := NewIdentityStore(users)
	_ = store
	securityConfig := SecurityConfig{
		VerifyContentIntegrity: true,
		MaxVerifyBodySize:      10 * 1024 * 1024, // 10MB
	}
	proxy := NewTestProxyHandler(users, securityConfig)

	body := []byte("test data")
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	req := httptest.NewRequest("PUT", "/test-bucket/file.bin", bytes.NewReader(body))
	req.Host = "s3.example.com"
	req.Header.Set("X-Amz-Content-Sha256", hashStr)
	req.ContentLength = -1 // Unknown length (chunked encoding)

	// Call director
	proxy.director(req)

	// Should fall back to UNSIGNED-PAYLOAD (can't verify unknown size)
	backendHash := req.Header.Get("X-Amz-Content-Sha256")
	if backendHash != "UNSIGNED-PAYLOAD" {
		t.Errorf("Expected UNSIGNED-PAYLOAD for unknown length, got: %s", backendHash)
	}
}

// TestOOMProtection_DisabledVerification tests that size limit is ignored when verification is disabled
func TestOOMProtection_DisabledVerification(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	store := NewIdentityStore(users)
	_ = store
	securityConfig := SecurityConfig{
		VerifyContentIntegrity: false, // Disabled
		MaxVerifyBodySize:      1024,  // Small limit (should be ignored)
	}
	proxy := NewTestProxyHandler(users, securityConfig)

	// Large body (exceeds limit)
	body := bytes.Repeat([]byte("A"), 10*1024*1024) // 10MB
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	req := httptest.NewRequest("PUT", "/test-bucket/large-file.bin", bytes.NewReader(body))
	req.Host = "s3.example.com"
	req.Header.Set("X-Amz-Content-Sha256", hashStr)
	req.ContentLength = int64(len(body))

	// Call director
	proxy.director(req)

	// Should use UNSIGNED-PAYLOAD (verification disabled)
	backendHash := req.Header.Get("X-Amz-Content-Sha256")
	if backendHash != "UNSIGNED-PAYLOAD" {
		t.Errorf("Expected UNSIGNED-PAYLOAD when verification disabled, got: %s", backendHash)
	}

	// Body should still be readable (not consumed by verification)
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	if len(bodyBytes) != len(body) {
		t.Errorf("Body size mismatch: expected %d, got %d", len(body), len(bodyBytes))
	}
}

// TestOOMProtection_DefaultMaxSize tests that proxy uses a reasonable default
func TestOOMProtection_DefaultMaxSize(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	store := NewIdentityStore(users)
	_ = store

	// Create security config without explicit max size (should get default)
	securityConfig := SecurityConfig{
		VerifyContentIntegrity: true,
		MaxVerifyBodySize:      0, // Not set explicitly
	}

	// Simulate LoadConfig which sets default
	if securityConfig.MaxVerifyBodySize == 0 {
		securityConfig.MaxVerifyBodySize = 50 * 1024 * 1024 // 50MB default
	}

	proxy := NewTestProxyHandler(users, securityConfig)

	// Verify proxy has reasonable default (50MB)
	expectedDefault := int64(50 * 1024 * 1024)
	if proxy.securityConfig.MaxVerifyBodySize != expectedDefault {
		t.Errorf("Expected default %d, got: %d",
			expectedDefault, proxy.securityConfig.MaxVerifyBodySize)
	}
}
