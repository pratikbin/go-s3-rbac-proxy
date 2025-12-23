package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the entire configuration file structure
type Config struct {
	MasterCredentials MasterCredentials `yaml:"master_credentials"`
	Server            ServerConfig      `yaml:"server"`
	Security          SecurityConfig    `yaml:"security"`
	Users             []User            `yaml:"users"`
	Logging           LoggingConfig     `yaml:"logging"`
	Metrics           MetricsConfig     `yaml:"metrics"`
}

// MasterCredentials are the credentials for the backend (Hetzner)
type MasterCredentials struct {
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Endpoint  string `yaml:"endpoint"`
	Region    string `yaml:"region"`
}

// ServerConfig holds server-specific settings
type ServerConfig struct {
	ListenAddr     string `yaml:"listen_addr"`
	ReadTimeout    string `yaml:"read_timeout"`
	WriteTimeout   string `yaml:"write_timeout"`
	IdleTimeout    string `yaml:"idle_timeout"`
	MaxHeaderBytes int    `yaml:"max_header_bytes"`
}

// SecurityConfig holds security-related settings
type SecurityConfig struct {
	// VerifyContentIntegrity enables verification of X-Amz-Content-Sha256 hash against actual body
	// Default: false (for maximum performance, rely on TLS for transport security)
	// When true: Buffers and verifies body hash, then forwards with correct hash to backend
	// Performance impact: Requires reading entire body into memory for hash calculation
	VerifyContentIntegrity bool `yaml:"verify_content_integrity"`

	// MaxVerifyBodySize is the maximum body size (in bytes) for integrity verification
	// Default: 52428800 (50MB) - prevents OOM attacks when verification is enabled
	// Requests larger than this will fall back to UNSIGNED-PAYLOAD
	// Set to 0 to disable size limit (dangerous - use with caution)
	MaxVerifyBodySize int64 `yaml:"max_verify_body_size"`
}

// User represents a client user with RBAC permissions
type User struct {
	AccessKey      string   `yaml:"access_key"`
	SecretKey      string   `yaml:"secret_key"`
	AllowedBuckets []string `yaml:"allowed_buckets"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
	Path    string `yaml:"path"`
}

// LoadConfig reads and parses the YAML configuration file
func LoadConfig(path string) (*Config, error) {
	// Validate path to prevent path traversal attacks
	if path == "" {
		return nil, fmt.Errorf("config path cannot be empty")
	}
	// Clean the path to remove any directory traversal attempts
	cleanPath := filepath.Clean(path)
	// Ensure the cleaned path is not empty and doesn't contain dangerous patterns
	if cleanPath == "." || cleanPath == ".." || strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid config path")
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	// Validate master credentials
	if config.MasterCredentials.AccessKey == "" || config.MasterCredentials.SecretKey == "" {
		return nil, fmt.Errorf("master credentials are missing")
	}
	if config.MasterCredentials.Endpoint == "" {
		return nil, fmt.Errorf("master endpoint is missing")
	}
	if config.MasterCredentials.Region == "" {
		config.MasterCredentials.Region = "us-east-1" // Default
	}

	// Validate server config
	if config.Server.ListenAddr == "" {
		config.Server.ListenAddr = ":8080"
	}

	// Validate security config
	if config.Security.MaxVerifyBodySize == 0 {
		// Default to 50MB to prevent OOM attacks
		config.Security.MaxVerifyBodySize = 50 * 1024 * 1024 // 50MB
	}

	// Validate logging config
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "json"
	}

	// Validate metrics config
	if config.Metrics.Address == "" {
		config.Metrics.Address = ":9090"
	}
	if config.Metrics.Path == "" {
		config.Metrics.Path = "/metrics"
	}

	return &config, nil
}

// GetReadTimeout parses and returns the read timeout duration
func (s *ServerConfig) GetReadTimeout() time.Duration {
	d, err := time.ParseDuration(s.ReadTimeout)
	if err != nil {
		return 300 * time.Second
	}
	return d
}

// GetWriteTimeout parses and returns the write timeout duration
func (s *ServerConfig) GetWriteTimeout() time.Duration {
	d, err := time.ParseDuration(s.WriteTimeout)
	if err != nil {
		return 300 * time.Second
	}
	return d
}

// GetIdleTimeout parses and returns the idle timeout duration
func (s *ServerConfig) GetIdleTimeout() time.Duration {
	d, err := time.ParseDuration(s.IdleTimeout)
	if err != nil {
		return 120 * time.Second
	}
	return d
}

// IdentityStore manages user lookups
type IdentityStore struct {
	users map[string]*User // Map of access_key -> User
}

// NewIdentityStore creates a new identity store from config
func NewIdentityStore(users []User) *IdentityStore {
	store := &IdentityStore{
		users: make(map[string]*User),
	}

	for i := range users {
		store.users[users[i].AccessKey] = &users[i]
	}

	return store
}

// GetUser retrieves a user by access key
func (s *IdentityStore) GetUser(accessKey string) (*User, bool) {
	user, exists := s.users[accessKey]
	return user, exists
}

// IsAuthorized checks if a user is authorized to access a specific bucket
func (u *User) IsAuthorized(bucket string) bool {
	for _, allowed := range u.AllowedBuckets {
		if allowed == "*" || strings.EqualFold(allowed, bucket) {
			return true
		}
	}
	return false
}
