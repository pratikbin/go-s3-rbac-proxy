package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestContentIntegrityVerification(t *testing.T) {
	users := []User{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	tests := []struct {
		name                string
		verifyIntegrity     bool
		method              string
		body                []byte
		clientHash          string
		expectedBackendHash string
		shouldSign          bool
		checkBody           bool
	}{
		{
			name:                "disabled verification",
			verifyIntegrity:     false,
			method:              "PUT",
			body:                []byte("test content for integrity"),
			clientHash:          "", // Will be computed
			expectedBackendHash: "UNSIGNED-PAYLOAD",
			shouldSign:          true,
			checkBody:           true,
		},
		{
			name:                "enabled with valid hash",
			verifyIntegrity:     true,
			method:              "PUT",
			body:                []byte("test content for integrity verification"),
			clientHash:          "", // Will be computed
			expectedBackendHash: "", // Will be computed hash
			shouldSign:          true,
			checkBody:           true,
		},
		{
			name:                "enabled with invalid hash",
			verifyIntegrity:     true,
			method:              "PUT",
			body:                []byte("test content for integrity verification"),
			clientHash:          "wronghash1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			expectedBackendHash: "",
			shouldSign:          false,
			checkBody:           false,
		},
		{
			name:                "skips streaming uploads",
			verifyIntegrity:     true,
			method:              "PUT",
			body:                []byte("streaming content"),
			clientHash:          "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
			expectedBackendHash: "UNSIGNED-PAYLOAD",
			shouldSign:          true,
			checkBody:           false,
		},
		{
			name:                "skips unsigned payload",
			verifyIntegrity:     true,
			method:              "PUT",
			body:                []byte("unsigned content"),
			clientHash:          "UNSIGNED-PAYLOAD",
			expectedBackendHash: "UNSIGNED-PAYLOAD",
			shouldSign:          true,
			checkBody:           false,
		},
		{
			name:                "skips empty body",
			verifyIntegrity:     true,
			method:              "GET",
			body:                nil,
			clientHash:          "",
			expectedBackendHash: "UNSIGNED-PAYLOAD",
			shouldSign:          true,
			checkBody:           false,
		},
		{
			name:                "case insensitive hash",
			verifyIntegrity:     true,
			method:              "PUT",
			body:                []byte("test content"),
			clientHash:          "", // Will be computed and uppercased
			expectedBackendHash: "", // Will be computed lowercase hash
			shouldSign:          true,
			checkBody:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := NewTestProxyHandler(users, SecurityConfig{VerifyContentIntegrity: tt.verifyIntegrity})

			// Compute hash if needed
			clientHash := tt.clientHash
			expectedHash := tt.expectedBackendHash
			if tt.body != nil && clientHash == "" {
				computedHash := ComputeSHA256(tt.body)
				clientHash = computedHash
				if expectedHash == "" {
					expectedHash = computedHash
				}
			}

			// For case insensitive test
			if tt.name == "case insensitive hash" && clientHash != "" {
				clientHash = strings.ToUpper(clientHash)
			}

			// Create request
			req := CreateTestRequest(tt.method, "/test-bucket/object.txt", tt.body, clientHash)

			// Call director
			proxy.director(req)

			// Check backend hash
			backendHash := req.Header.Get("X-Amz-Content-Sha256")
			if expectedHash != "" && backendHash != expectedHash {
				t.Errorf("Expected backend hash %s, got: %s", expectedHash, backendHash)
			}

			// Check signing
			hasAuth := req.Header.Get("Authorization") != ""
			if tt.shouldSign && !hasAuth {
				t.Error("Expected request to be signed but no Authorization header found")
			}
			if !tt.shouldSign && hasAuth {
				t.Error("Expected request not to be signed but Authorization header found")
			}

			// Check body if needed
			if tt.checkBody && tt.body != nil {
				bodyBytes, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("Failed to read body: %v", err)
				}
				if !bytes.Equal(bodyBytes, tt.body) {
					t.Errorf("Body mismatch: expected %s, got %s", string(tt.body), string(bodyBytes))
				}
			}
		})
	}
}
