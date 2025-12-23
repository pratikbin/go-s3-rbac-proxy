package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test100Continue_EarlyRejection(t *testing.T) {
	// Setup minimal proxy with auth that WILL FAIL
	users := []User{} // No users
	store := NewIdentityStore(users)
	auth := NewAuthMiddleware(store)

	// Config doesn't matter much for this test as we fail before proxying
	masterCreds := MasterCredentials{Endpoint: "http://localhost:9000"}
	secConfig := SecurityConfig{}

	proxy := NewProxyHandler(auth, masterCreds, secConfig)
	server := httptest.NewServer(proxy)
	defer server.Close()

	// Create request with Expect: 100-continue
	// We use a custom client to verify behavior if possible, or just standard client
	req, err := http.NewRequest("PUT", server.URL+"/test-bucket/obj", nil) // nil body for now, but header set
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Expect", "100-continue")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=invalid/20231221/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=invalid")
	req.Header.Set("X-Amz-Date", "20231221T000000Z")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Verify 403 Forbidden
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden, got %d", resp.StatusCode)
	}

	// Verify we didn't crash or hang
	t.Log("✅ Early rejection works for Expect: 100-continue (received 403 immediately)")
}
