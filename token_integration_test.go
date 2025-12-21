package main

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthMiddleware_WithSessionToken(t *testing.T) {
	users := []User{
		{
			AccessKey:      "user-token",
			SecretKey:      "secret-token",
			AllowedBuckets: []string{"test-bucket"},
		},
	}
	store := NewIdentityStore(users)
	auth := NewAuthMiddleware(store)

	// Setup request details
	method := "GET"
	path := "/test-bucket/file.txt"
	token := "session-token-value"

	req := httptest.NewRequest(method, path, nil)
	req.Host = "localhost"

	// Add standard headers
	now := time.Now().UTC()
	amzDate := now.Format(iso8601BasicFormat)
	dateStamp := now.Format(iso8601BasicFormatShort)

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", unsignedPayload)
	req.Header.Set("X-Amz-Security-Token", token)

	// Construct Authorization Header with Token signed
	// SignedHeaders including x-amz-security-token
	signedHeaders := "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"

	// Build Canonical Request manually to calculate expected signature
	// We can use the helper functions since we are in package main
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\nx-amz-security-token:%s\n",
		req.Host, unsignedPayload, amzDate, token)

	canonicalRequest := fmt.Sprintf("%s\n%s\n\n%s\n%s\n%s",
		method,
		path, // CanonicalURI (simple path)
		canonicalHeaders,
		signedHeaders,
		unsignedPayload,
	)

	stringToSign := buildStringToSign(amzDate, dateStamp, "us-east-1", "s3", canonicalRequest)
	signature := calculateSignature("secret-token", dateStamp, "us-east-1", "s3", stringToSign)

	cred := fmt.Sprintf("user-token/%s/us-east-1/s3/aws4_request", dateStamp)
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s",
		cred, signedHeaders, signature)

	req.Header.Set("Authorization", authHeader)

	// Validate
	user, err := auth.ValidateRequest(req)
	if err != nil {
		t.Fatalf("Validation failed with session token: %v", err)
	}

	if user.AccessKey != "user-token" {
		t.Errorf("Wrong user returned: %s", user.AccessKey)
	}

	// Test Case 2: Token provided but NOT signed (ignored in canonical headers)
	// This is valid if the client chooses not to sign it, but usually standard clients sign it.
	// If NOT in SignedHeaders, it should NOT be in CanonicalHeaders.

	req2 := httptest.NewRequest(method, path, nil)
	req2.Host = "localhost"
	req2.Header.Set("X-Amz-Date", amzDate)
	req2.Header.Set("X-Amz-Content-Sha256", unsignedPayload)
	req2.Header.Set("X-Amz-Security-Token", token) // Header present

	signedHeaders2 := "host;x-amz-content-sha256;x-amz-date" // Token excluded

	canonicalHeaders2 := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		req2.Host, unsignedPayload, amzDate)

	canonicalRequest2 := fmt.Sprintf("%s\n%s\n\n%s\n%s\n%s",
		method,
		path,
		canonicalHeaders2,
		signedHeaders2,
		unsignedPayload,
	)

	stringToSign2 := buildStringToSign(amzDate, dateStamp, "us-east-1", "s3", canonicalRequest2)
	signature2 := calculateSignature("secret-token", dateStamp, "us-east-1", "s3", stringToSign2)

	authHeader2 := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s",
		cred, signedHeaders2, signature2)

	req2.Header.Set("Authorization", authHeader2)

	user2, err := auth.ValidateRequest(req2)
	if err != nil {
		t.Fatalf("Validation failed with unsigned session token: %v", err)
	}

	if user2.AccessKey != "user-token" {
		t.Errorf("Wrong user returned: %s", user2.AccessKey)
	}
}

func TestAuthMiddleware_TokenDoubleSigningCheck(t *testing.T) {
	// Ensuring that if it IS in SignedHeaders, it IS checked.
}
