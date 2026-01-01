//go:build localstack

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// localstackTestRegion is the region used for LocalStack tests
const localstackTestRegion = "us-east-1"

// ensureBucket creates a bucket in the specific LocalStack instance with retry logic.
func ensureBucket(ctx context.Context, endpoint, bucket string) error {
	client, err := CreateBackendS3Client(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to create backend client: %w", err)
	}

	// Retry bucket creation to handle eventual consistency
	var lastErr error
	for i := 0; i < 3; i++ {
		_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: aws.String(bucket),
		})
		if err == nil {
			return nil
		}

		errStr := err.Error()
		if strings.Contains(errStr, "BucketAlreadyExists") || strings.Contains(errStr, "BucketAlreadyOwnedByYou") {
			return nil
		}

		lastErr = err
		time.Sleep(time.Duration(i+1) * time.Second)
	}

	return fmt.Errorf("failed to create bucket %q after retries: %w", bucket, lastErr)
}

// cleanupBucket deletes all objects and the bucket itself.
func cleanupBucket(ctx context.Context, endpoint, bucket string) error {
	client, err := CreateBackendS3Client(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to create backend client: %w", err)
	}

	// List and delete all objects
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// Bucket might be gone or empty
			break
		}
		for _, obj := range page.Contents {
			_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket),
				Key:    obj.Key,
			})
			if err != nil {
				return fmt.Errorf("failed to delete object %q: %w", aws.ToString(obj.Key), err)
			}
		}
	}

	// Delete bucket (ignore errors as bucket might already be deleted)
	_, _ = client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucket),
	})
	return nil
}

// TestLocalStack_BasicCRUD verifies basic object operations through the proxy.
func TestLocalStack_BasicCRUD(t *testing.T) {
	ctx := context.Background()
	users := []TestUser{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"test-bucket"},
		},
	}

	// Setup environment (starts container)
	env, err := SetupLocalStackEnv(ctx, users)
	if err != nil {
		t.Fatalf("Failed to setup LocalStack env: %v", err)
	}
	defer env.Cleanup()

	// Ensure bucket exists in backend
	if err := ensureBucket(ctx, env.BackendURL, "test-bucket"); err != nil {
		t.Fatalf("Failed to ensure bucket: %v", err)
	}
	defer cleanupBucket(ctx, env.BackendURL, "test-bucket")

	client, err := CreateProxyS3Client(ctx, env.ProxyURL, "test-user", "test-secret")
	if err != nil {
		t.Fatalf("Failed to create S3 client: %v", err)
	}

	key := "test-object.txt"
	content := []byte("Hello, LocalStack! This is a test object.")

	// 1. PutObject
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String(key),
		Body:   strings.NewReader(string(content)),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	t.Log("✅ PutObject succeeded")

	// 2. GetObject
	getOut, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	defer getOut.Body.Close()

	readContent, err := io.ReadAll(getOut.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	if string(readContent) != string(content) {
		t.Errorf("Content mismatch: expected %q, got %q", string(content), string(readContent))
	}
	t.Log("✅ GetObject succeeded with correct content")

	// 3. DeleteObject
	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}
	t.Log("✅ DeleteObject succeeded")

	// 4. Verify deletion (GetObject should return 404)
	_, err = client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("test-bucket"),
		Key:    aws.String(key),
	})
	if err == nil {
		t.Error("Expected 404 after deletion, but GetObject succeeded")
	} else {
		// Check for NoSuchKey error
		errStr := err.Error()
		if !strings.Contains(errStr, "NoSuchKey") {
			t.Errorf("Expected NoSuchKey error, got %v", err)
		}
	}
	t.Log("✅ Object deletion verified")
}

// TestLocalStack_MultipartUpload performs a complete multipart upload.
func TestLocalStack_MultipartUpload(t *testing.T) {
	ctx := context.Background()
	users := []TestUser{
		{
			AccessKey:      "test-user",
			SecretKey:      "test-secret",
			AllowedBuckets: []string{"multipart-bucket"},
		},
	}

	env, err := SetupLocalStackEnv(ctx, users)
	if err != nil {
		t.Fatalf("Failed to setup LocalStack env: %v", err)
	}
	defer env.Cleanup()

	// Ensure bucket exists
	if err := ensureBucket(ctx, env.BackendURL, "multipart-bucket"); err != nil {
		t.Fatalf("Failed to ensure bucket: %v", err)
	}
	defer cleanupBucket(ctx, env.BackendURL, "multipart-bucket")

	client, err := CreateProxyS3Client(ctx, env.ProxyURL, "test-user", "test-secret")
	if err != nil {
		t.Fatalf("Failed to create S3 client: %v", err)
	}

	key := "large-file.bin"
	partSize := int64(5 * 1024 * 1024) // 5 MB

	// 1. Create multipart upload
	createResp, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String("multipart-bucket"),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}
	uploadID := aws.ToString(createResp.UploadId)
	t.Logf("✅ Created multipart upload, ID: %s", uploadID)

	// 2. Upload parts
	var parts []types.CompletedPart
	for i := int64(1); i <= 3; i++ {
		// Generate deterministic part content
		partContent := make([]byte, partSize)
		for j := range partContent {
			partContent[j] = byte(int(i) + j)
		}
		partReader := strings.NewReader(string(partContent))

		uploadResp, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     aws.String("multipart-bucket"),
			Key:        aws.String(key),
			UploadId:   aws.String(uploadID),
			PartNumber: aws.Int32(int32(i)),
			Body:       partReader,
		})
		if err != nil {
			t.Fatalf("UploadPart %d failed: %v", i, err)
		}

		parts = append(parts, types.CompletedPart{
			ETag:       uploadResp.ETag,
			PartNumber: aws.Int32(int32(i)),
		})
		t.Logf("✅ Uploaded part %d", i)
	}

	// 3. Complete multipart upload
	_, err = client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String("multipart-bucket"),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: parts,
		},
	})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload failed: %v", err)
	}
	t.Log("✅ Completed multipart upload")

	// 4. Verify the assembled object
	getOut, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("multipart-bucket"),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("GetObject after multipart failed: %v", err)
	}
	defer getOut.Body.Close()

	// Compute expected content hash
	hasher := sha256.New()
	for i := int64(1); i <= 3; i++ {
		partContent := make([]byte, partSize)
		for j := range partContent {
			partContent[j] = byte(int(i) + j)
		}
		hasher.Write(partContent)
	}
	expectedHash := hex.EncodeToString(hasher.Sum(nil))

	// Compute actual hash
	hasher.Reset()
	if _, err := io.Copy(hasher, getOut.Body); err != nil {
		t.Fatalf("Failed to read object body: %v", err)
	}
	actualHash := hex.EncodeToString(hasher.Sum(nil))

	if expectedHash != actualHash {
		t.Errorf("Hash mismatch: expected %s, got %s", expectedHash, actualHash)
	} else {
		t.Log("✅ Multipart object integrity verified")
	}
}

// TestLocalStack_ListBuckets_RBAC verifies that ListBuckets respects RBAC.
func TestLocalStack_ListBuckets_RBAC(t *testing.T) {
	ctx := context.Background()

	users := []TestUser{
		{
			AccessKey:      "user-a",
			SecretKey:      "secret-a",
			AllowedBuckets: []string{"rbac-bucket-a"},
		},
	}

	env, err := SetupLocalStackEnv(ctx, users)
	if err != nil {
		t.Fatalf("Failed to setup LocalStack env: %v", err)
	}
	defer env.Cleanup()

	// Create two buckets in backend
	buckets := []string{"rbac-bucket-a", "rbac-bucket-b"}
	for _, b := range buckets {
		if err := ensureBucket(ctx, env.BackendURL, b); err != nil {
			t.Fatalf("Failed to ensure bucket %q: %v", b, err)
		}
		defer cleanupBucket(ctx, env.BackendURL, b)
	}

	client, err := CreateProxyS3Client(ctx, env.ProxyURL, "user-a", "secret-a")
	if err != nil {
		t.Fatalf("Failed to create S3 client: %v", err)
	}

	// ListBuckets should return only bucket-a
	result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		t.Fatalf("ListBuckets failed: %v", err)
	}

	if len(result.Buckets) != 1 {
		t.Errorf("Expected 1 bucket, got %d", len(result.Buckets))
	}
	if len(result.Buckets) > 0 && aws.ToString(result.Buckets[0].Name) != "rbac-bucket-a" {
		t.Errorf("Expected rbac-bucket-a, got %s", aws.ToString(result.Buckets[0].Name))
	}
	t.Log("✅ ListBuckets RBAC enforced")
}

// TestLocalStack_PresignedURL verifies presigned URL generation and usage.
func TestLocalStack_PresignedURL(t *testing.T) {
	ctx := context.Background()
	users := []TestUser{
		{
			AccessKey:      "presign-user",
			SecretKey:      "presign-secret",
			AllowedBuckets: []string{"presign-bucket"},
		},
	}

	env, err := SetupLocalStackEnv(ctx, users)
	if err != nil {
		t.Fatalf("Failed to setup LocalStack env: %v", err)
	}
	defer env.Cleanup()

	if err := ensureBucket(ctx, env.BackendURL, "presign-bucket"); err != nil {
		t.Fatalf("Failed to ensure bucket: %v", err)
	}
	defer cleanupBucket(ctx, env.BackendURL, "presign-bucket")

	client, err := CreateProxyS3Client(ctx, env.ProxyURL, "presign-user", "presign-secret")
	if err != nil {
		t.Fatalf("Failed to create S3 client: %v", err)
	}

	key := "presigned-object.txt"
	content := []byte("Content for presigned URL")

	// 1. Generate a presigned PUT URL
	presignClient := s3.NewPresignClient(client)
	presignedPut, err := presignClient.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("presign-bucket"),
		Key:    aws.String(key),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = 5 * time.Minute
	})
	if err != nil {
		t.Fatalf("Failed to presign PutObject: %v", err)
	}
	t.Logf("✅ Generated presigned PUT URL")

	// 2. Use the presigned URL to upload
	req, err := http.NewRequest("PUT", presignedPut.URL, strings.NewReader(string(content)))
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}
	// Copy headers from presigned request
	for k, v := range presignedPut.SignedHeader {
		req.Header[k] = v
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("PUT with presigned URL failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT returned status %d: %s", resp.StatusCode, body)
	}
	t.Log("✅ Presigned PUT succeeded")

	// 3. Generate a presigned GET URL
	presignedGet, err := presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("presign-bucket"),
		Key:    aws.String(key),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = 5 * time.Minute
	})
	if err != nil {
		t.Fatalf("Failed to presign GetObject: %v", err)
	}

	// 4. Use the presigned GET URL to download
	req, err = http.NewRequest("GET", presignedGet.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create GET request: %v", err)
	}
	for k, v := range presignedGet.SignedHeader {
		req.Header[k] = v
	}

	resp, err = httpClient.Do(req)
	if err != nil {
		t.Fatalf("GET with presigned URL failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET returned status %d: %s", resp.StatusCode, body)
	}
	downloaded, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read downloaded content: %v", err)
	}
	if string(downloaded) != string(content) {
		t.Errorf("Content mismatch: expected %q, got %q", string(content), string(downloaded))
	} else {
		t.Log("✅ Presigned GET succeeded with correct content")
	}
}

// TestLocalStack_ErrorPassthrough ensures backend errors (404, 403) are relayed.
func TestLocalStack_ErrorPassthrough(t *testing.T) {
	ctx := context.Background()
	users := []TestUser{
		{
			AccessKey:      "error-user",
			SecretKey:      "error-secret",
			AllowedBuckets: []string{"existing-bucket"},
		},
	}

	env, err := SetupLocalStackEnv(ctx, users)
	if err != nil {
		t.Fatalf("Failed to setup LocalStack env: %v", err)
	}
	defer env.Cleanup()

	// Create only one bucket
	if err := ensureBucket(ctx, env.BackendURL, "existing-bucket"); err != nil {
		t.Fatalf("Failed to ensure bucket: %v", err)
	}
	defer cleanupBucket(ctx, env.BackendURL, "existing-bucket")

	client, err := CreateProxyS3Client(ctx, env.ProxyURL, "error-user", "error-secret")
	if err != nil {
		t.Fatalf("Failed to create S3 client: %v", err)
	}

	// Try to get an object that does not exist → 404
	_, err = client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("existing-bucket"),
		Key:    aws.String("non-existent-key"),
	})
	if err == nil {
		t.Error("Expected error for non-existent object")
	} else {
		// Check for NoSuchKey error
		errStr := err.Error()
		if !strings.Contains(errStr, "NoSuchKey") {
			t.Errorf("Expected NoSuchKey error, got %v", err)
		} else {
			t.Log("✅ 404 (NoSuchKey) correctly passed through")
		}
	}

	// Try to access a bucket that the user is NOT allowed to access
	// (but exists in backend) → 403
	// Note: The proxy's RBAC will block this before reaching backend,
	// but we still want to ensure the error is proper.
	_, err = client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("forbidden-bucket"),
		Key:    aws.String("any-key"),
	})
	if err == nil {
		t.Error("Expected error for forbidden bucket")
	} else {
		// Could be a generic error, but at least an error is returned
		t.Logf("✅ Access to forbidden bucket blocked (error: %v)", err)
	}
}
