package main

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfigReloader(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	initialConfig := `
master_credentials:
  access_key: "master-access-key"
  secret_key: "master-secret-key"
  endpoint: "https://s3.example.com"
  region: "us-east-1"

server:
  listen_addr: ":8080"

security:
  verify_content_integrity: false
  max_verify_body_size: 52428800
  max_streaming_upload_size: 10737418240
  max_streaming_upload_duration: "1h"
  max_concurrent_streaming_uploads: 5

users:
  - access_key: "user1"
    secret_key: "secret1"
    allowed_buckets: ["bucket1", "bucket2"]
  - access_key: "user2"
    secret_key: "secret2"
    allowed_buckets: ["bucket3"]

logging:
  level: "info"
  format: "json"

metrics:
  enabled: false
  address: ":9090"
  path: "/metrics"
`

	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	// Load initial config
	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load initial config: %v", err)
	}

	// Create identity store and auth middleware
	identityStore := NewIdentityStore(config.Users)
	authMiddleware := NewAuthMiddleware(identityStore)

	// Create config reloader
	configReloader := NewConfigReloader(configPath, identityStore, authMiddleware)

	// Test initial state
	if identityStore.GetUserCount() != 2 {
		t.Errorf("expected 2 users, got %d", identityStore.GetUserCount())
	}

	// Test user lookup
	user1, exists := identityStore.GetUser("user1")
	if !exists {
		t.Error("expected user1 to exist")
	}
	if user1 == nil || user1.AccessKey != "user1" {
		t.Error("user1 not found correctly")
	}

	user2, exists := identityStore.GetUser("user2")
	if !exists {
		t.Error("expected user2 to exist")
	}
	if user2 == nil || user2.AccessKey != "user2" {
		t.Error("user2 not found correctly")
	}

	// Update config file with new users
	updatedConfig := `
master_credentials:
  access_key: "master-access-key"
  secret_key: "master-secret-key"
  endpoint: "https://s3.example.com"
  region: "us-east-1"

server:
  listen_addr: ":8080"

security:
  verify_content_integrity: false
  max_verify_body_size: 52428800
  max_streaming_upload_size: 10737418240
  max_streaming_upload_duration: "1h"
  max_concurrent_streaming_uploads: 5

users:
  - access_key: "user1"
    secret_key: "secret1"
    allowed_buckets: ["bucket1", "bucket2"]
  - access_key: "user3"
    secret_key: "secret3"
    allowed_buckets: ["bucket4"]
  - access_key: "user4"
    secret_key: "secret4"
    allowed_buckets: ["bucket5", "bucket6"]

logging:
  level: "info"
  format: "json"

metrics:
  enabled: false
  address: ":9090"
  path: "/metrics"
`

	if err := os.WriteFile(configPath, []byte(updatedConfig), 0644); err != nil {
		t.Fatalf("failed to write updated config: %v", err)
	}

	// Manually trigger reload
	if err := configReloader.ReloadConfig(); err != nil {
		t.Fatalf("failed to reload config: %v", err)
	}

	// Test updated state
	if identityStore.GetUserCount() != 3 {
		t.Errorf("expected 3 users after reload, got %d", identityStore.GetUserCount())
	}

	// Verify user1 still exists (was in both configs)
	if _, exists := identityStore.GetUser("user1"); !exists {
		t.Error("expected user1 to still exist after reload")
	}

	// Verify user2 no longer exists (removed in updated config)
	if _, exists := identityStore.GetUser("user2"); exists {
		t.Error("expected user2 to be removed after reload")
	}

	// Verify new users exist
	user3, exists := identityStore.GetUser("user3")
	if !exists {
		t.Error("expected user3 to exist after reload")
	}
	if user3 == nil || user3.AccessKey != "user3" {
		t.Error("user3 not found correctly")
	}

	user4, exists := identityStore.GetUser("user4")
	if !exists {
		t.Error("expected user4 to exist after reload")
	}
	if user4 == nil || user4.AccessKey != "user4" {
		t.Error("user4 not found correctly")
	}

	// Test with invalid config
	invalidConfig := `
master_credentials:
  # Missing required fields
`

	if err := os.WriteFile(configPath, []byte(invalidConfig), 0644); err != nil {
		t.Fatalf("failed to write invalid config: %v", err)
	}

	// Reload should fail but not crash
	if err := configReloader.ReloadConfig(); err == nil {
		t.Error("expected reload to fail with invalid config")
	}

	// User store should remain unchanged after failed reload
	if identityStore.GetUserCount() != 3 {
		t.Errorf("expected user count to remain 3 after failed reload, got %d", identityStore.GetUserCount())
	}
}

func TestIdentityStoreThreadSafety(t *testing.T) {
	// Create initial users
	users := []User{
		{AccessKey: "user1", SecretKey: "secret1", AllowedBuckets: []string{"bucket1"}},
		{AccessKey: "user2", SecretKey: "secret2", AllowedBuckets: []string{"bucket2"}},
	}

	store := NewIdentityStore(users)

	// Test concurrent reads and writes
	done := make(chan bool)
	var readCount int64
	var writeCount int64

	// Start multiple readers
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				user, exists := store.GetUser("user1")
				if exists && user.AccessKey == "user1" {
					atomic.AddInt64(&readCount, 1)
				}
				time.Sleep(time.Microsecond)
			}
			done <- true
		}(i)
	}

	// Start a writer that updates users
	go func() {
		for i := 0; i < 5; i++ {
			newUsers := []User{
				{AccessKey: "user1", SecretKey: "secret1-updated", AllowedBuckets: []string{"bucket1"}},
				{AccessKey: "user2", SecretKey: "secret2-updated", AllowedBuckets: []string{"bucket2"}},
				{AccessKey: "user3", SecretKey: "secret3", AllowedBuckets: []string{"bucket3"}},
			}
			store.UpdateUsers(newUsers)
			atomic.AddInt64(&writeCount, 1)
			time.Sleep(time.Millisecond)
		}
		done <- true
	}()

	// Wait for all goroutines to complete
	for i := 0; i < 11; i++ {
		<-done
	}

	// Verify final state
	if store.GetUserCount() != 3 {
		t.Errorf("expected 3 users at end, got %d", store.GetUserCount())
	}

	// Verify updates were applied
	user1, exists := store.GetUser("user1")
	if !exists {
		t.Error("user1 should exist")
	}
	if user1.SecretKey != "secret1-updated" {
		t.Errorf("user1 secret not updated, got %s", user1.SecretKey)
	}

	user3, exists := store.GetUser("user3")
	if !exists {
		t.Error("user3 should exist")
	}
	if user3.AccessKey != "user3" {
		t.Error("user3 not found correctly")
	}
}

func TestConfigReloaderSignalHandling(t *testing.T) {
	// Skip this test in CI environments or when signals can't be tested
	if testing.Short() {
		t.Skip("skipping signal test in short mode")
	}

	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	config := `
master_credentials:
  access_key: "master-access-key"
  secret_key: "master-secret-key"
  endpoint: "https://s3.example.com"
  region: "us-east-1"

server:
  listen_addr: ":8080"

security:
  verify_content_integrity: false

users:
  - access_key: "test-user"
    secret_key: "test-secret"
    allowed_buckets: ["test-bucket"]

logging:
  level: "info"
  format: "json"

metrics:
  enabled: false
`

	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Load config
	loadedConfig, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Create components
	identityStore := NewIdentityStore(loadedConfig.Users)
	authMiddleware := NewAuthMiddleware(identityStore)
	configReloader := NewConfigReloader(configPath, identityStore, authMiddleware)

	// Start the reloader
	configReloader.Start()
	defer configReloader.Stop()

	// Verify initial state
	if identityStore.GetUserCount() != 1 {
		t.Errorf("expected 1 user initially, got %d", identityStore.GetUserCount())
	}

	// Note: We can't easily test SIGHUP in a unit test without complex signal handling
	// This test primarily ensures the reloader starts and stops without errors
}
