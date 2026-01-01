package main

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// TestIntegration_RangeRequest verifies partial content retrieval
func TestIntegration_RangeRequest(t *testing.T) {
	t.Parallel()

	// Setup
	users := []User{
		{
			AccessKey:      "user-range",
			SecretKey:      "secret-range",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	proxyURL, _, backend, cleanup := SetupMockEnv(users)
	defer cleanup()

	ctx := context.Background()
	client, err := CreateS3Client(ctx, proxyURL, "user-range", "secret-range")
	if err != nil {
		t.Fatalf("Failed to create S3 client: %v", err)
	}

	// 1. Upload a file
	content := []byte("0123456789") // 10 bytes
	key := "range-test.txt"
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String(key),
		Body:   bytes.NewReader(content),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// 2. Perform Range Request (Allocating mock backend support first)
	// We modified mockS3Backend in integration_test.go to support Range header.

	// Request bytes 2-5 (inclusive) -> "2345"
	rangeHeader := "bytes=2-5"
	resp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String(key),
		Range:  aws.String(rangeHeader),
	})
	if err != nil {
		t.Fatalf("GetObject with Range failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 3. Verify Response
	// Verify Content-Range header if SDK exposes it (it usually does in ContentRange field)
	if resp.ContentRange != nil {
		t.Logf("Content-Range: %s", *resp.ContentRange)
	}

	// Verify status code implied by method (SDK doesn't always expose status code directly depending on version,
	// but usually success is 200 or 206. If it was 200, it would return full content.)

	part, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	expected := []byte("2345")
	if !bytes.Equal(part, expected) {
		t.Errorf("Range request mismatch. Expected %q, got %q", expected, part)
		// If we got full content "0123456789", it means Range header was dropped or ignored.
		// If we got "23456789", start was respected but end wasn't.
	} else {
		t.Logf("✅ Range request success: got %q", part)
	}

	// Verify backend received the Range header
	// We need to inspect backend.lastHeaders
	headers := backend.GetLastHeaders()
	if headers.Get("Range") == "" {
		t.Errorf("Proxy did not forward Range header to backend")
	} else {
		t.Logf("✅ Proxy passed Range header: %s", headers.Get("Range"))
	}
}
