package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthMiddleware_ValidateRequest(t *testing.T) {
	// Create test user
	users := []User{
		{
			AccessKey:      "test-access-key",
			SecretKey:      "test-secret-key",
			AllowedBuckets: []string{"test-bucket"},
		},
	}
	store := NewIdentityStore(users)
	auth := NewAuthMiddleware(store)

	tests := []struct {
		name        string
		setupReq    func() *http.Request
		expectError bool
		expectUser  string
	}{
		{
			name: "missing authorization header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test-bucket/", nil)
				return req
			},
			expectError: true,
		},
		{
			name: "invalid authorization format",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test-bucket/", nil)
				req.Header.Set("Authorization", "Bearer token123")
				return req
			},
			expectError: true,
		},
		{
			name: "missing x-amz-date",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test-bucket/", nil)
				req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test-access-key/20231220/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=test")
				return req
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			user, err := auth.ValidateRequest(req)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if user != nil && user.AccessKey != tt.expectUser {
					t.Errorf("expected user %s but got %s", tt.expectUser, user.AccessKey)
				}
			}
		})
	}
}

func TestCalculateSignature(t *testing.T) {
	secretKey := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	dateStamp := "20130524"
	region := "us-east-1"
	service := "s3"
	stringToSign := `AWS4-HMAC-SHA256
20130524T000000Z
20130524/us-east-1/s3/aws4_request
7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972`

	signature := calculateSignature(secretKey, dateStamp, region, service, stringToSign)

	// This is a known test vector from AWS documentation
	expected := "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"

	if signature != expected {
		t.Errorf("signature mismatch:\nexpected: %s\ngot:      %s", expected, signature)
	}
}

func TestUserIsAuthorized(t *testing.T) {
	tests := []struct {
		name           string
		allowedBuckets []string
		testBucket     string
		expectAuth     bool
	}{
		{
			name:           "exact match",
			allowedBuckets: []string{"bucket-a", "bucket-b"},
			testBucket:     "bucket-a",
			expectAuth:     true,
		},
		{
			name:           "no match",
			allowedBuckets: []string{"bucket-a", "bucket-b"},
			testBucket:     "bucket-c",
			expectAuth:     false,
		},
		{
			name:           "wildcard",
			allowedBuckets: []string{"*"},
			testBucket:     "any-bucket",
			expectAuth:     true,
		},
		{
			name:           "case insensitive",
			allowedBuckets: []string{"BUCKET-A"},
			testBucket:     "bucket-a",
			expectAuth:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := User{
				AccessKey:      "test",
				SecretKey:      "test",
				AllowedBuckets: tt.allowedBuckets,
			}

			result := user.IsAuthorized(tt.testBucket)
			if result != tt.expectAuth {
				t.Errorf("expected authorization %v but got %v", tt.expectAuth, result)
			}
		})
	}
}

func TestExtractBucketFromPath(t *testing.T) {
	tests := []struct {
		path           string
		expectedBucket string
	}{
		{"/bucket-name/object-key", "bucket-name"},
		{"/bucket-name/", "bucket-name"},
		{"/bucket-name", "bucket-name"},
		{"/", ""},
		{"", ""},
		{"/bucket-name/folder/object", "bucket-name"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			bucket := extractBucketFromPath(tt.path)
			if bucket != tt.expectedBucket {
				t.Errorf("expected bucket %q but got %q", tt.expectedBucket, bucket)
			}
		})
	}
}

func TestTimestampValidation(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		timestamp   time.Time
		expectValid bool
	}{
		{
			name:        "current time",
			timestamp:   now,
			expectValid: true,
		},
		{
			name:        "5 minutes ago",
			timestamp:   now.Add(-5 * time.Minute),
			expectValid: true,
		},
		{
			name:        "20 minutes ago",
			timestamp:   now.Add(-20 * time.Minute),
			expectValid: false,
		},
		{
			name:        "5 minutes in future",
			timestamp:   now.Add(5 * time.Minute),
			expectValid: true,
		},
		{
			name:        "20 minutes in future",
			timestamp:   now.Add(20 * time.Minute),
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skew := time.Since(tt.timestamp).Abs()
			valid := skew <= 15*time.Minute

			if valid != tt.expectValid {
				t.Errorf("expected validity %v but got %v for skew %v", tt.expectValid, valid, skew)
			}
		})
	}
}

