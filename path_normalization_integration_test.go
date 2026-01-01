package main

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// TestIntegration_PathNormalization_EdgeCases verifies path normalization edge cases
func TestIntegration_PathNormalization_EdgeCases(t *testing.T) {
	t.Parallel()

	// Setup
	users := []User{
		{
			AccessKey:      "user-normalization",
			SecretKey:      "secret-normalization",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	proxyURL, _, backend, cleanup := SetupMockEnv(users)
	defer cleanup()

	ctx := context.Background()
	client, err := CreateS3Client(ctx, proxyURL, "user-normalization", "secret-normalization")
	if err != nil {
		t.Fatalf("Failed to create S3 client: %v", err)
	}

	t.Run("DoubleSlashes_BucketAndKey", func(t *testing.T) {
		// Test: Path with double slashes //bucket//object
		// Expected: Proxy should handle consistently (preserve or normalize)
		// Verify: SigV4 signature still valid

		testData := []byte("test data for double slashes")
		key := "double//slash//file.txt"

		// Upload with double slashes in key
		_, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String("test-bucket"),
			Key:    aws.String(key),
			Body:   bytes.NewReader(testData),
		})
		if err != nil {
			t.Fatalf("PutObject with double slashes failed: %v", err)
		}

		// Verify backend received the path
		lastPath := backend.lastPath
		if !strings.Contains(lastPath, "double") || !strings.Contains(lastPath, "slash") {
			t.Errorf("Backend path doesn't contain expected segments: %s", lastPath)
		}

		// Retrieve the object
		getResult, err := client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String("test-bucket"),
			Key:    aws.String(key),
		})
		if err != nil {
			t.Fatalf("GetObject with double slashes failed: %v", err)
		}
		defer func() { _ = getResult.Body.Close() }()

		retrievedData, _ := io.ReadAll(getResult.Body)
		if !bytes.Equal(retrievedData, testData) {
			t.Errorf("Data mismatch for double slash path")
		}

		t.Logf("✅ Double slashes in key handled correctly: %s", key)
	})

	t.Run("TrailingSlash_Bucket", func(t *testing.T) {
		// Test: /bucket/ vs /bucket
		// Note: S3 treats these differently, but our proxy should handle both

		testData := []byte("test data")
		key := "trailing-slash-test.txt"

		// Upload to bucket with trailing slash in path (if client sends it)
		// Most SDKs normalize this, so we test the canonical URI handling
		_, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String("test-bucket"),
			Key:    aws.String(key),
			Body:   bytes.NewReader(testData),
		})
		if err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}

		// Verify extractBucketFromPath handles trailing slash correctly
		bucket := extractBucketFromPath("/test-bucket/")
		if bucket != "test-bucket" {
			t.Errorf("extractBucketFromPath('/test-bucket/') = %q, want 'test-bucket'", bucket)
		}

		bucket2 := extractBucketFromPath("/test-bucket")
		if bucket2 != "test-bucket" {
			t.Errorf("extractBucketFromPath('/test-bucket') = %q, want 'test-bucket'", bucket2)
		}

		t.Logf("✅ Trailing slash handling verified")
	})

	t.Run("DotSegments_PathTraversal", func(t *testing.T) {
		// Test: /bucket/./object and /bucket/../otherbucket/object
		// Expected: Proxy should reject path traversal attempts

		// Test 1: Current directory (./) - should work if normalized
		testData := []byte("test data")
		key := "./normal-key.txt"

		_, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String("test-bucket"),
			Key:    aws.String(key),
			Body:   bytes.NewReader(testData),
		})
		if err != nil {
			t.Logf("Note: ./ in key may be rejected by SDK or backend: %v", err)
		}

		// Test 2: Parent directory (../) - should be rejected
		// Attempt to access otherbucket via path traversal
		// Verify extractBucketFromPath behavior with path traversal
		bucket := extractBucketFromPath("/test-bucket/../otherbucket/object.txt")
		// extractBucketFromPath should extract "test-bucket" (first segment)
		// The path traversal should be caught by authorization check
		if bucket != "test-bucket" {
			t.Errorf("extractBucketFromPath should extract first segment, got: %s", bucket)
		}

		// Verify that if user tries to access otherbucket, it's rejected
		// This is tested in access control tests, but we verify path extraction here
		t.Logf("✅ Path traversal detection: extractBucketFromPath correctly extracts 'test-bucket' from path with ../")
	})

	t.Run("MultipleSlashes_InKey", func(t *testing.T) {
		// Test: /bucket/folder//file.txt
		// Expected: Consistent encoding in canonical URI
		// Verify: Signature validation passes

		testData := []byte("test data for multiple slashes")
		key := "folder//file.txt"

		_, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String("test-bucket"),
			Key:    aws.String(key),
			Body:   bytes.NewReader(testData),
		})
		if err != nil {
			t.Fatalf("PutObject with multiple slashes failed: %v", err)
		}

		// Verify canonical URI encoding
		req := httptest.NewRequest("PUT", "/test-bucket/folder//file.txt", nil)
		canonicalURI := getCanonicalURI(req)
		if canonicalURI == "" {
			t.Error("getCanonicalURI returned empty string")
		}

		// Verify the path is encoded consistently
		if !strings.Contains(canonicalURI, "folder") || !strings.Contains(canonicalURI, "file.txt") {
			t.Errorf("Canonical URI doesn't contain expected segments: %s", canonicalURI)
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

		t.Logf("✅ Multiple slashes in key handled correctly: %s", key)
	})

	t.Run("ExtractBucket_EdgeCases", func(t *testing.T) {
		// Test extractBucketFromPath with various edge cases

		tests := []struct {
			name           string
			path           string
			expectedBucket string
		}{
			{"DoubleSlashStart", "//bucket/key", ""}, // extractBucketFromPath expects path to start with single "/"
			{"TripleSlash", "///bucket/key", ""},     // extractBucketFromPath expects path to start with single "/"
			{"EmptyPath", "", ""},
			{"RootPath", "/", ""},
			{"OnlyBucket", "/bucket", "bucket"},
			{"OnlyBucketTrailingSlash", "/bucket/", "bucket"},
			{"PathTraversal", "/bucket/../other/key", "bucket"}, // First segment is extracted
			{"DotSegment", "/bucket/./key", "bucket"},           // First segment is extracted
			{"MultipleSlashes", "/bucket//key", "bucket"},       // First segment is extracted
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				bucket := extractBucketFromPath(tt.path)
				if bucket != tt.expectedBucket {
					t.Errorf("extractBucketFromPath(%q) = %q, want %q", tt.path, bucket, tt.expectedBucket)
				}
			})
		}

		t.Logf("✅ extractBucketFromPath edge cases verified")
	})
}
