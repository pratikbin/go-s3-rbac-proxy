package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/localstack"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestEnv represents a complete test environment
type TestEnv struct {
	ProxyURL    string
	BackendURL  string
	Backend     *mockS3Backend
	Cleanup     func()
	ProxyServer *httptest.Server
	Container   testcontainers.Container
}

// SetupMockEnv creates a complete test environment with mock backend and proxy
func SetupMockEnv(users []User) (proxyURL string, backendURL string, backend *mockS3Backend, cleanup func()) {
	// Initialize logger if not already initialized
	if Logger == nil {
		_ = InitLogger("debug", "console")
	}

	// Create mock S3 backend
	backend = newMockS3Backend()
	backendServer := httptest.NewServer(backend)

	// Create identity store and auth middleware
	store := NewIdentityStore(users)
	auth := NewAuthMiddleware(store)

	// Create master credentials pointing to mock backend
	masterCreds := MasterCredentials{
		AccessKey: "master-access-key",
		SecretKey: "master-secret-key",
		Endpoint:  backendServer.URL,
		Region:    "us-east-1",
	}

	// Create security config
	securityConfig := SecurityConfig{
		VerifyContentIntegrity: false, // Use UNSIGNED-PAYLOAD for streaming
		MaxVerifyBodySize:      50 * 1024 * 1024,
	}

	// Initialize streaming upload tracker
	uploadTracker := NewStreamingUploadTracker(
		5,
		1024*1024*1024,
		1*time.Hour,
	)

	// Create proxy handler
	proxyHandler := NewProxyHandler(auth, masterCreds, securityConfig, uploadTracker)
	proxyServer := httptest.NewServer(proxyHandler)

	cleanup = func() {
		proxyServer.Close()
		backendServer.Close()
	}

	return proxyServer.URL, backendServer.URL, backend, cleanup
}

// CreateS3Client creates an AWS SDK v2 S3 client configured for the test proxy
func CreateS3Client(ctx context.Context, proxyURL, accessKey, secretKey string) (*s3.Client, error) {
	// Load config with static credentials
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return nil, err
	}

	// Create S3 client with custom endpoint and path-style addressing
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(proxyURL)
		o.UsePathStyle = true
	})

	return client, nil
}

// CreateProxyS3Client is an alias for CreateS3Client for consistency
func CreateProxyS3Client(ctx context.Context, proxyURL, accessKey, secretKey string) (*s3.Client, error) {
	return CreateS3Client(ctx, proxyURL, accessKey, secretKey)
}

// CreateBackendS3Client creates an AWS SDK v2 S3 client that talks DIRECTLY to LocalStack
func CreateBackendS3Client(ctx context.Context, endpoint string) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
	return client, nil
}

// SetupLocalStackEnv starts a LocalStack container and creates a proxy handler pointing to it.
func SetupLocalStackEnv(ctx context.Context, users []User) (*TestEnv, error) {
	// Initialize logger if not already initialized
	if Logger == nil {
		_ = InitLogger("debug", "console")
	}

	// 1. Start LocalStack Container with health check
	lsContainer, err := localstack.Run(ctx,
		"localstack/localstack:latest",
		testcontainers.WithEnv(map[string]string{
			"SERVICES": "s3",
		}),
		testcontainers.WithWaitStrategy(
			wait.ForHTTP("/_localstack/health").
				WithPort("4566/tcp").
				WithStatusCodeMatcher(func(status int) bool {
					return status == http.StatusOK
				}).
				WithStartupTimeout(120*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start localstack container: %w", err)
	}

	// 2. Get dynamic endpoint
	backendEndpoint, err := lsContainer.PortEndpoint(ctx, "4566/tcp", "http")
	if err != nil {
		_ = lsContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to get localstack endpoint: %w", err)
	}

	// 3. Configure Proxy
	masterCreds := MasterCredentials{
		AccessKey: "test", // Default LocalStack creds
		SecretKey: "test",
		Endpoint:  backendEndpoint,
		Region:    "us-east-1",
	}

	securityConfig := SecurityConfig{
		VerifyContentIntegrity: false,
		MaxVerifyBodySize:      50 * 1024 * 1024,
	}

	identityStore := NewIdentityStore(users)
	auth := NewAuthMiddleware(identityStore)

	// Initialize streaming upload tracker
	uploadTracker := NewStreamingUploadTracker(
		securityConfig.MaxConcurrentStreamingUploads,
		securityConfig.MaxStreamingUploadSize,
		securityConfig.GetMaxStreamingUploadDuration(),
	)

	proxyHandler := NewProxyHandler(auth, masterCreds, securityConfig, uploadTracker)
	proxyServer := httptest.NewServer(proxyHandler)

	// 4. Create test environment
	env := &TestEnv{
		ProxyURL:    proxyServer.URL,
		BackendURL:  backendEndpoint,
		ProxyServer: proxyServer,
		Container:   lsContainer,
	}

	// 5. Setup cleanup
	env.Cleanup = func() {
		proxyServer.Close()
		if err := lsContainer.Terminate(ctx); err != nil {
			fmt.Printf("warning: failed to terminate container: %v\n", err)
		}
	}

	return env, nil
}

// NewTestProxyHandler creates a ProxyHandler for testing purposes
func NewTestProxyHandler(users []User, securityConfig SecurityConfig) *ProxyHandler {
	// Initialize logger if not already initialized
	if Logger == nil {
		_ = InitLogger("debug", "console")
	}

	// Set default MaxVerifyBodySize if not set
	if securityConfig.MaxVerifyBodySize == 0 {
		securityConfig.MaxVerifyBodySize = 50 * 1024 * 1024
	}

	store := NewIdentityStore(users)
	auth := NewAuthMiddleware(store)
	masterCreds := MasterCredentials{
		AccessKey: "master-key",
		SecretKey: "master-secret",
		Endpoint:  "https://backend.example.com",
		Region:    "us-east-1",
	}

	// Initialize streaming upload tracker
	uploadTracker := NewStreamingUploadTracker(
		securityConfig.MaxConcurrentStreamingUploads,
		securityConfig.MaxStreamingUploadSize,
		securityConfig.GetMaxStreamingUploadDuration(),
	)

	return NewProxyHandler(auth, masterCreds, securityConfig, uploadTracker)
}

// CreateTestRequest creates a new HTTP request for testing
func CreateTestRequest(method, path string, body []byte, hashHeader string) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Host = "s3.example.com"
	if hashHeader != "" {
		req.Header.Set("X-Amz-Content-Sha256", hashHeader)
	}
	req.Header.Set("Content-Type", "text/plain")
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	return req
}

// ComputeSHA256 computes the SHA256 hash of the given data as a hex string
func ComputeSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// EnsureBucket creates a bucket in the specific S3 instance with retry logic.
func EnsureBucket(ctx context.Context, endpoint, bucket string) error {
	client, err := CreateBackendS3Client(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to create backend client: %w", err)
	}

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

// CleanupBucket deletes all objects and the bucket itself.
func CleanupBucket(ctx context.Context, endpoint, bucket string) error {
	client, err := CreateBackendS3Client(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to create backend client: %w", err)
	}

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
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

	_, _ = client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucket),
	})
	return nil
}

// Common test users
var (
	TestUserBucketA = User{
		AccessKey:      "user-bucket-a",
		SecretKey:      "secret-a",
		AllowedBuckets: []string{"bucket-a"},
	}
	TestUserBucketB = User{
		AccessKey:      "user-bucket-b",
		SecretKey:      "secret-b",
		AllowedBuckets: []string{"bucket-b"},
	}
	TestUserWildcard = User{
		AccessKey:      "user-wildcard",
		SecretKey:      "secret-wildcard",
		AllowedBuckets: []string{"*"},
	}
)
