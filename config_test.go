package main

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create temporary test config
	configContent := `
master_credentials:
  access_key: "test-master-key"
  secret_key: "test-master-secret"
  endpoint: "https://test.example.com"
  region: "us-east-1"

server:
  listen_addr: ":8080"
  read_timeout: "300s"
  write_timeout: "300s"
  idle_timeout: "120s"
  max_header_bytes: 1048576

users:
  - access_key: "user1"
    secret_key: "secret1"
    allowed_buckets:
      - "bucket1"

logging:
  level: "info"
  format: "json"
`

	// Create temp file
	tmpfile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Load config
	config, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Validate master credentials
	if config.MasterCredentials.AccessKey != "test-master-key" {
		t.Errorf("expected access key 'test-master-key', got '%s'", config.MasterCredentials.AccessKey)
	}

	if config.MasterCredentials.Endpoint != "https://test.example.com" {
		t.Errorf("expected endpoint 'https://test.example.com', got '%s'", config.MasterCredentials.Endpoint)
	}

	// Validate server config
	if config.Server.ListenAddr != ":8080" {
		t.Errorf("expected listen addr ':8080', got '%s'", config.Server.ListenAddr)
	}

	// Validate users
	if len(config.Users) != 1 {
		t.Errorf("expected 1 user, got %d", len(config.Users))
	}

	if config.Users[0].AccessKey != "user1" {
		t.Errorf("expected user access key 'user1', got '%s'", config.Users[0].AccessKey)
	}
}

func TestIdentityStore(t *testing.T) {
	users := []User{
		{
			AccessKey:      "user1",
			SecretKey:      "secret1",
			AllowedBuckets: []string{"bucket1"},
		},
		{
			AccessKey:      "user2",
			SecretKey:      "secret2",
			AllowedBuckets: []string{"bucket2"},
		},
	}

	store := NewIdentityStore(users)

	// Test existing user
	user, exists := store.GetUser("user1")
	if !exists {
		t.Error("expected user1 to exist")
	}
	if user.SecretKey != "secret1" {
		t.Errorf("expected secret 'secret1', got '%s'", user.SecretKey)
	}

	// Test non-existing user
	_, exists = store.GetUser("user3")
	if exists {
		t.Error("expected user3 to not exist")
	}
}

func TestServerConfigTimeouts(t *testing.T) {
	config := ServerConfig{
		ReadTimeout:  "30s",
		WriteTimeout: "60s",
		IdleTimeout:  "120s",
	}

	if config.GetReadTimeout().Seconds() != 30 {
		t.Errorf("expected 30s, got %v", config.GetReadTimeout())
	}

	if config.GetWriteTimeout().Seconds() != 60 {
		t.Errorf("expected 60s, got %v", config.GetWriteTimeout())
	}

	if config.GetIdleTimeout().Seconds() != 120 {
		t.Errorf("expected 120s, got %v", config.GetIdleTimeout())
	}
}

func TestInvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name: "missing master credentials",
			content: `
server:
  listen_addr: ":8080"
users:
  - access_key: "user1"
    secret_key: "secret1"
`,
		},
		{
			name: "invalid YAML",
			content: `
this is not: [valid: yaml
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile, err := os.CreateTemp("", "config-*.yaml")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.Remove(tmpfile.Name()) }()

			if _, err := tmpfile.Write([]byte(tt.content)); err != nil {
				t.Fatal(err)
			}
			if err := tmpfile.Close(); err != nil {
				t.Fatal(err)
			}

			_, err = LoadConfig(tmpfile.Name())
			if err == nil {
				t.Error("expected error but got none")
			}
		})
	}
}
