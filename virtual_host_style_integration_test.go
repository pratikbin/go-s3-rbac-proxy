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

	t.Run("VirtualHostStyle_NowSupported", func(t *testing.T) {
		// Test: Request: GET /key with Host: bucket.proxy.com
		// With new extractBucket function: bucket extracted from Host header
		// Expected: Bucket correctly extracted from Host header

		// Create a request with virtual-host style (bucket in Host header)
		req, err := http.NewRequestWithContext(ctx, "GET", proxyURL+"/virtual-host-key.txt", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Set Host header to simulate virtual-host style
		// Format: bucket.proxy.com
		req.Host = "test-bucket." + strings.TrimPrefix(proxyURL, "http://")

		// Verify extractBucket extracts from Host header (not path)
		bucket := extractBucket(req)
		expectedBucket := "test-bucket"
		if bucket != expectedBucket {
			t.Errorf("extractBucket() = %q, want %q (should extract from Host header)", bucket, expectedBucket)
		}

		t.Logf("✅ Virtual-host style now supported: extractBucket correctly extracts bucket from Host header")
	})

	t.Run("ExtractBucket_EdgeCases", func(t *testing.T) {
		// Test various request formats to verify extractBucket behavior

		tests := []struct {
			name           string
			host           string
			path           string
			expectedBucket string
			description    string
		}{
			{
				name:           "StandardPathStyle",
				host:           strings.TrimPrefix(proxyURL, "http://"),
				path:           "/bucket/key",
				expectedBucket: "bucket",
				description:    "Standard path-style format",
			},
			{
				name:           "VirtualHostStyle",
				host:           "bucket." + strings.TrimPrefix(proxyURL, "http://"),
				path:           "/key",
				expectedBucket: "bucket",
				description:    "Virtual-host style - bucket extracted from Host",
			},
			{
				name:           "RootPath",
				host:           strings.TrimPrefix(proxyURL, "http://"),
				path:           "/",
				expectedBucket: "",
				description:    "Root path (ListBuckets)",
			},
			{
				name:           "OnlyBucket",
				host:           strings.TrimPrefix(proxyURL, "http://"),
				path:           "/bucket",
				expectedBucket: "bucket",
				description:    "Path with only bucket name",
			},
			{
				name:           "VirtualHostWithPort",
				host:           "bucket." + strings.TrimPrefix(proxyURL, "http://") + ":8080",
				path:           "/key",
				expectedBucket: "bucket",
				description:    "Virtual-host style with port",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req, err := http.NewRequestWithContext(ctx, "GET", "http://"+tt.host+tt.path, nil)
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}
				req.Host = tt.host

				bucket := extractBucket(req)
				if bucket != tt.expectedBucket {
					t.Errorf("extractBucket() with host=%q, path=%q = %q, want %q (%s)",
						tt.host, tt.path, bucket, tt.expectedBucket, tt.description)
				}
			})
		}

		t.Logf("✅ extractBucket edge cases verified")
	})

	t.Run("Documentation_FeatureImplemented", func(t *testing.T) {
		// Document that virtual-host style is now supported

		t.Logf("Current Implementation:")
		t.Logf("  - extractBucket() supports both path-style (/bucket/key) and virtual-host style (bucket.proxy.com/key)")
		t.Logf("  - Checks Host header first for virtual-host style")
		t.Logf("  - Falls back to path-style extraction if no bucket in Host header")
		t.Logf("  - Virtual-host style requests now correctly extract bucket from Host header")

		t.Logf("\nImplementation Details:")
		t.Logf("  - extractBucket(r *http.Request) string function added")
		t.Logf("  - Checks Host header for subdomain: bucket.proxy.com -> 'bucket'")
		t.Logf("  - Falls back to path-style if no subdomain detected")
		t.Logf("  - Validates bucket names according to S3 naming rules")

		// This test serves as documentation
		t.Logf("✅ Virtual-host style support implemented")
	})
}
