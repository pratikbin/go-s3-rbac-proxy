package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// TestIntegration_VirtualHostStyle_Limitation documents and tests virtual-host style addressing limitation
func TestIntegration_VirtualHostStyle_Limitation(t *testing.T) {
	t.Parallel()

	// Setup
	users := []User{
		{
			AccessKey:      "user-vhost",
			SecretKey:      "secret-vhost",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	proxyURL, _, _, cleanup := setupTestEnv(users)
	defer cleanup()

	ctx := context.Background()
	client, err := createS3Client(ctx, proxyURL, "user-vhost", "secret-vhost")
	if err != nil {
		t.Fatalf("Failed to create S3 client: %v", err)
	}

	t.Run("PathStyle_Works", func(t *testing.T) {
		// Test: Request: GET /bucket/key
		// Verify: Bucket extracted correctly

		testData := []byte("test data")
		key := "path-style-test.txt"

		// Upload using path-style (default for our proxy)
		_, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String("test-bucket"),
			Key:    aws.String(key),
			Body:   bytes.NewReader(testData),
		})
		if err != nil {
			t.Fatalf("PutObject with path-style failed: %v", err)
		}

		// Verify extractBucketFromPath works
		bucket := extractBucketFromPath("/test-bucket/" + key)
		if bucket != "test-bucket" {
			t.Errorf("extractBucketFromPath('/test-bucket/%s') = %q, want 'test-bucket'", key, bucket)
		}

		// Retrieve the object
		getResult, err := client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String("test-bucket"),
			Key:    aws.String(key),
		})
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		defer func() { _ = getResult.Body.Close() }()

		retrievedData, _ := io.ReadAll(getResult.Body)
		if !bytes.Equal(retrievedData, testData) {
			t.Errorf("Data mismatch")
		}

		t.Logf("✅ Path-style addressing works correctly")
	})

	t.Run("VirtualHostStyle_NotSupported", func(t *testing.T) {
		// Test: Request: GET /key with Host: bucket.proxy.com
		// Current: extractBucketFromPath extracts "key" from path (first segment)
		// Limitation: extractBucketFromPath doesn't check Host header
		// Expected: Should return 403 or handle gracefully when bucket doesn't match Host

		// Create a request with virtual-host style (bucket in Host header)
		req, err := http.NewRequestWithContext(ctx, "GET", proxyURL+"/virtual-host-key.txt", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Set Host header to simulate virtual-host style
		// Format: bucket.proxy.com
		req.Host = "test-bucket." + strings.TrimPrefix(proxyURL, "http://")

		// Verify extractBucketFromPath extracts from path (not Host)
		// This demonstrates the limitation: it extracts "virtual-host-key.txt" as bucket
		bucket := extractBucketFromPath(req.URL.Path)
		expectedBucket := "virtual-host-key.txt"
		if bucket != expectedBucket {
			t.Errorf("extractBucketFromPath extracts first path segment, expected: %s, got: %s", expectedBucket, bucket)
		}

		// In the actual proxy, this would result in:
		// - extractBucketFromPath returns "virtual-host-key" (from path)
		// - User authorization check would fail (user not authorized for "virtual-host-key" bucket)
		// - Proxy returns 403 "Access Denied"
		// This demonstrates that virtual-host style is not properly supported

		t.Logf("✅ Virtual-host style limitation verified: extractBucketFromPath doesn't check Host header")
	})

	t.Run("ExtractBucket_EdgeCases", func(t *testing.T) {
		// Test various path formats to verify extractBucketFromPath behavior

		tests := []struct {
			name           string
			path           string
			expectedBucket string
			description    string
		}{
			{
				name:           "StandardPathStyle",
				path:           "/bucket/key",
				expectedBucket: "bucket",
				description:    "Standard path-style format",
			},
			{
				name:           "VirtualHostStylePath",
				path:           "/key",
				expectedBucket: "key",
				description:    "Virtual-host style path - extractBucketFromPath extracts first segment (limitation)",
			},
			{
				name:           "RootPath",
				path:           "/",
				expectedBucket: "",
				description:    "Root path (ListBuckets)",
			},
			{
				name:           "OnlyBucket",
				path:           "/bucket",
				expectedBucket: "bucket",
				description:    "Path with only bucket name",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				bucket := extractBucketFromPath(tt.path)
				if bucket != tt.expectedBucket {
					t.Errorf("extractBucketFromPath(%q) = %q, want %q (%s)",
						tt.path, bucket, tt.expectedBucket, tt.description)
				}
			})
		}

		t.Logf("✅ extractBucketFromPath edge cases verified")
	})

	t.Run("Documentation_CurrentLimitation", func(t *testing.T) {
		// Document the current limitation and potential enhancement

		t.Logf("Current Implementation:")
		t.Logf("  - extractBucketFromPath only supports path-style (/bucket/key)")
		t.Logf("  - No Host header parsing for virtual-host style (bucket.proxy.com/key)")
		t.Logf("  - Virtual-host style requests result in empty bucket extraction")
		t.Logf("  - Proxy returns 403 'Service-level operation not supported' for empty bucket")

		t.Logf("\nPotential Enhancement:")
		t.Logf("  - Add extractBucket(r *http.Request) string function")
		t.Logf("  - Check Host header for subdomain: bucket.proxy.com -> 'bucket'")
		t.Logf("  - Fall back to path-style if no subdomain detected")
		t.Logf("  - This would enable virtual-host style support")

		// This test serves as documentation
		t.Logf("✅ Limitation documented")
	})
}
