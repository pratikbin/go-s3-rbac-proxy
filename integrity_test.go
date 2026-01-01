package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestContentIntegrityVerification_Disabled(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}
	proxy := NewTestProxyHandler(users, SecurityConfig{VerifyContentIntegrity: false})

	// Create a test body
	testBody := []byte("test content for integrity")
	correctHashStr := ComputeSHA256(testBody)

	// Create request with correct hash
	req := CreateTestRequest("PUT", "/test-bucket/object.txt", testBody, correctHashStr)

	// Call director to prepare request for backend
	proxy.director(req)

	// When integrity verification is disabled, it should use UNSIGNED-PAYLOAD
	backendHash := req.Header.Get("X-Amz-Content-Sha256")
	if backendHash != "UNSIGNED-PAYLOAD" {
		t.Errorf("Expected UNSIGNED-PAYLOAD when verification disabled, got: %s", backendHash)
	}

	// Body should still be readable
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	if !bytes.Equal(bodyBytes, testBody) {
		t.Errorf("Body mismatch: expected %s, got %s", string(testBody), string(bodyBytes))
	}
}

func TestContentIntegrityVerification_Enabled_ValidHash(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}
	proxy := NewTestProxyHandler(users, SecurityConfig{VerifyContentIntegrity: true})

	// Create a test body
	testBody := []byte("test content for integrity verification")
	correctHashStr := ComputeSHA256(testBody)

	// Create request with correct hash
	req := CreateTestRequest("PUT", "/test-bucket/object.txt", testBody, correctHashStr)

	// Call director to prepare request for backend
	proxy.director(req)

	// When integrity verification is enabled and hash is valid,
	// the verified hash should be set (not UNSIGNED-PAYLOAD)
	backendHash := req.Header.Get("X-Amz-Content-Sha256")
	if backendHash != correctHashStr {
		t.Errorf("Expected verified hash %s, got: %s", correctHashStr, backendHash)
	}

	// Body should still be readable after verification
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	if !bytes.Equal(bodyBytes, testBody) {
		t.Errorf("Body mismatch after verification: expected %s, got %s", string(testBody), string(bodyBytes))
	}
}

func TestContentIntegrityVerification_Enabled_InvalidHash(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}
	proxy := NewTestProxyHandler(users, SecurityConfig{VerifyContentIntegrity: true})

	// Create a test body
	testBody := []byte("test content for integrity verification")

	// Use WRONG hash (hash of different content)
	wrongContent := []byte("completely different content")
	wrongHashStr := ComputeSHA256(wrongContent)

	// Create request with wrong hash
	req := CreateTestRequest("PUT", "/test-bucket/object.txt", testBody, wrongHashStr)

	// Call director - this should detect the mismatch and not sign the request
	proxy.director(req)

	// The request should not have been signed (no Authorization header added)
	if req.Header.Get("Authorization") != "" {
		t.Error("Expected request not to be signed with invalid hash")
	}
}

func TestContentIntegrityVerification_SkipsStreamingUploads(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}
	proxy := NewTestProxyHandler(users, SecurityConfig{VerifyContentIntegrity: true})

	// Create request with streaming signature
	testBody := []byte("streaming content")
	req := CreateTestRequest("PUT", "/test-bucket/object.txt", testBody, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")

	// Call director
	proxy.director(req)

	// Streaming uploads should NOT be verified
	backendHash := req.Header.Get("X-Amz-Content-Sha256")
	if backendHash != "UNSIGNED-PAYLOAD" {
		t.Errorf("Streaming uploads should use UNSIGNED-PAYLOAD, got: %s", backendHash)
	}
}

func TestContentIntegrityVerification_SkipsUnsignedPayload(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}
	proxy := NewTestProxyHandler(users, SecurityConfig{VerifyContentIntegrity: true})

	// Create request with UNSIGNED-PAYLOAD
	testBody := []byte("unsigned content")
	req := CreateTestRequest("PUT", "/test-bucket/object.txt", testBody, "UNSIGNED-PAYLOAD")

	// Call director
	proxy.director(req)

	// When client already sends UNSIGNED-PAYLOAD, we should respect it
	backendHash := req.Header.Get("X-Amz-Content-Sha256")
	if backendHash != "UNSIGNED-PAYLOAD" {
		t.Errorf("UNSIGNED-PAYLOAD should be preserved, got: %s", backendHash)
	}
}

func TestContentIntegrityVerification_SkipsEmptyBody(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}
	proxy := NewTestProxyHandler(users, SecurityConfig{VerifyContentIntegrity: true})

	// Create GET request with no body
	req := CreateTestRequest("GET", "/test-bucket/object.txt", nil, "")

	// Call director
	proxy.director(req)

	// Should use UNSIGNED-PAYLOAD for requests without body
	backendHash := req.Header.Get("X-Amz-Content-Sha256")
	if backendHash != "UNSIGNED-PAYLOAD" {
		t.Errorf("Empty body requests should use UNSIGNED-PAYLOAD, got: %s", backendHash)
	}
}

func TestContentIntegrityVerification_CaseInsensitiveHash(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}
	proxy := NewTestProxyHandler(users, SecurityConfig{VerifyContentIntegrity: true})

	// Create a test body
	testBody := []byte("test content")
	correctHashStr := ComputeSHA256(testBody)
	// Use UPPERCASE hash
	upperHashStr := strings.ToUpper(correctHashStr)

	// Create request with uppercase hash
	req := CreateTestRequest("PUT", "/test-bucket/object.txt", testBody, upperHashStr)

	// Call director
	proxy.director(req)

	// Hash comparison should be case-insensitive
	backendHash := req.Header.Get("X-Amz-Content-Sha256")
	if backendHash != correctHashStr {
		t.Errorf("Expected lowercase hash %s, got: %s", correctHashStr, backendHash)
	}
}
