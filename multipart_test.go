package main

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMultipartUpload(t *testing.T) {
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
	tracker := NewStreamingUploadTracker(5, 1024*1024, time.Hour)

	tests := []struct {
		name                string
		method              string
		path                string
		body                string
		contentType         string
		clientHash          string
		verifyIntegrity     bool
		maxVerifyBodySize   int64
		expectedBackendHash string
		shouldHaveAuth      bool
		checkBodyContent    []string
	}{
		{
			name:                "complete_with_unsigned_payload",
			method:              "POST",
			path:                "/test-bucket/large-file.bin?uploadId=ABC123",
			body:                `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"abc123"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"def456"</ETag></Part></CompleteMultipartUpload>`,
			contentType:         "application/xml",
			clientHash:          "UNSIGNED-PAYLOAD",
			verifyIntegrity:     false,
			maxVerifyBodySize:   0,
			expectedBackendHash: "UNSIGNED-PAYLOAD",
			shouldHaveAuth:      true,
			checkBodyContent:    []string{`<ETag>"abc123"</ETag>`, `<ETag>"def456"</ETag>`},
		},
		{
			name:                "complete_with_content_hash",
			method:              "POST",
			path:                "/test-bucket/large-file.bin?uploadId=DEF456",
			body:                `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"xyz789"</ETag></Part></CompleteMultipartUpload>`,
			contentType:         "application/xml",
			clientHash:          "", // Will be computed
			verifyIntegrity:     true,
			maxVerifyBodySize:   1024 * 1024, // 1MB
			expectedBackendHash: "",          // Will be computed hash
			shouldHaveAuth:      true,
			checkBodyContent:    []string{`<ETag>"xyz789"</ETag>`},
		},
		{
			name:                "initiate_empty_body",
			method:              "POST",
			path:                "/test-bucket/new-file.bin?uploads",
			body:                "",
			contentType:         "",
			clientHash:          "",
			verifyIntegrity:     true,
			maxVerifyBodySize:   1024 * 1024,
			expectedBackendHash: "UNSIGNED-PAYLOAD",
			shouldHaveAuth:      true,
			checkBodyContent:    nil,
		},
		{
			name:                "upload_part_binary_data",
			method:              "PUT",
			path:                "/test-bucket/large-file.bin?partNumber=1&uploadId=GHI789",
			body:                "binary data content for part 1",
			contentType:         "application/octet-stream",
			clientHash:          "", // Will be computed
			verifyIntegrity:     true,
			maxVerifyBodySize:   1024 * 1024,
			expectedBackendHash: "", // Will be computed hash
			shouldHaveAuth:      true,
			checkBodyContent:    []string{"binary data content for part 1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			securityConfig := SecurityConfig{
				VerifyContentIntegrity: tt.verifyIntegrity,
				MaxVerifyBodySize:      tt.maxVerifyBodySize,
			}
			proxy := NewProxyHandler(auth, masterCreds, securityConfig, tracker)

			// Compute hash if needed
			clientHash := tt.clientHash
			expectedHash := tt.expectedBackendHash
			if tt.body != "" && clientHash == "" {
				computedHash := ComputeSHA256([]byte(tt.body))
				clientHash = computedHash
				if expectedHash == "" {
					expectedHash = computedHash
				}
			}

			// Create request
			var bodyReader io.Reader
			if tt.body != "" {
				bodyReader = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(tt.method, tt.path, bodyReader)
			req.Host = "s3.example.com"
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			if tt.body != "" {
				req.ContentLength = int64(len(tt.body))
			}
			if clientHash != "" {
				req.Header.Set("X-Amz-Content-Sha256", clientHash)
			}

			// Call director
			proxy.director(req)

			// Check backend hash
			backendHash := req.Header.Get("X-Amz-Content-Sha256")
			if expectedHash != "" && backendHash != expectedHash {
				t.Errorf("Expected backend hash %s, got: %s", expectedHash, backendHash)
			}

			// Check authorization
			authHeader := req.Header.Get("Authorization")
			if tt.shouldHaveAuth && authHeader == "" {
				t.Error("Expected Authorization header to be set")
			}
			if tt.shouldHaveAuth && !strings.Contains(authHeader, "AWS4-HMAC-SHA256") {
				t.Errorf("Expected AWS4-HMAC-SHA256 signature, got: %s", authHeader)
			}

			// Check body content if needed
			if tt.body != "" || len(tt.checkBodyContent) > 0 {
				bodyBytes, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("Failed to read body: %v", err)
				}

				if tt.body != "" && string(bodyBytes) != tt.body {
					t.Errorf("Body mismatch:\nExpected: %s\nGot: %s", tt.body, string(bodyBytes))
				}

				// Check for specific content
				for _, content := range tt.checkBodyContent {
					if !strings.Contains(string(bodyBytes), content) {
						t.Errorf("Body should contain: %s", content)
					}
				}
			}
		})
	}
}
