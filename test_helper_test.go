package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// TestUser is a simplified user struct for test setup
type TestUser struct {
	AccessKey      string
	SecretKey      string
	AllowedBuckets []string
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

	// Create proxy handler
	proxyHandler := NewProxyHandler(auth, masterCreds, securityConfig)
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

// CreateProxyS3Client creates an AWS SDK v2 S3 client configured for the test PROXY
func CreateProxyS3Client(ctx context.Context, proxyURL, accessKey, secretKey string) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(proxyURL)
		o.UsePathStyle = true
	})

	return client, nil
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
// It returns the test environment with cleanup function.
func SetupLocalStackEnv(ctx context.Context, users []TestUser) (*TestEnv, error) {
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

	// 3. Convert test users to User structs
	var userList []User
	for _, u := range users {
		userList = append(userList, User(u))
	}

	// 4. Configure Proxy
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

	identityStore := NewIdentityStore(userList)
	auth := NewAuthMiddleware(identityStore)
	proxyHandler := NewProxyHandler(auth, masterCreds, securityConfig)
	proxyServer := httptest.NewServer(proxyHandler)

	// 5. Create test environment
	env := &TestEnv{
		ProxyURL:    proxyServer.URL,
		BackendURL:  backendEndpoint,
		ProxyServer: proxyServer,
		Container:   lsContainer,
	}

	// 6. Setup cleanup
	env.Cleanup = func() {
		proxyServer.Close()
		if err := lsContainer.Terminate(ctx); err != nil {
			// Log but don't fail test on cleanup errors
			fmt.Printf("warning: failed to terminate container: %v\n", err)
		}
	}

	return env, nil
}
