package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// #nosec G101
const (
	defaultConfigPath = "./config.yaml"
	shutdownTimeout   = 30 * time.Second
)

func main() {
	// Parse command-line flags
	configPath := flag.String("config", defaultConfigPath, "Path to config file")
	flag.Parse()

	// Set GOMAXPROCS to use all available CPUs
	runtime.GOMAXPROCS(runtime.NumCPU())
	fmt.Printf("Starting S3 IAM Proxy with GOMAXPROCS=%d\n", runtime.GOMAXPROCS(0))

	// Load configuration
	config, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	if err := InitLogger(config.Logging.Level, config.Logging.Format); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		// Ignore sync errors on shutdown (common on some platforms)
		// Error is typically "sync /dev/stderr: invalid argument" on some systems
		_ = Logger.Sync()
	}()

	Logger.Info("configuration loaded",
		zap.String("listen_addr", config.Server.ListenAddr),
		zap.String("backend_endpoint", config.MasterCredentials.Endpoint),
		zap.Int("num_users", len(config.Users)),
		zap.Bool("verify_content_integrity", config.Security.VerifyContentIntegrity),
		zap.Bool("metrics_enabled", config.Metrics.Enabled),
		zap.String("metrics_addr", config.Metrics.Address),
		zap.String("metrics_path", config.Metrics.Path),
	)

	// Create identity store
	identityStore := NewIdentityStore(config.Users)

	// Create auth middleware
	authMiddleware := NewAuthMiddleware(identityStore)

	// Create configuration reloader
	configReloader := NewConfigReloader(*configPath, identityStore, authMiddleware)
	configReloader.Start()
	defer configReloader.Stop()

	// Optional: Start file watcher for automatic reloads (disabled by default)
	// Uncomment to enable automatic file watching:
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()
	// configReloader.WatchConfigFile(ctx, 30*time.Second)

	// Create proxy handler
	proxyHandler := NewProxyHandler(authMiddleware, config.MasterCredentials, config.Security)

	// Create HTTP server
	server := &http.Server{
		Addr:           config.Server.ListenAddr,
		Handler:        proxyHandler,
		ReadTimeout:    config.Server.GetReadTimeout(),
		WriteTimeout:   config.Server.GetWriteTimeout(),
		IdleTimeout:    config.Server.GetIdleTimeout(),
		MaxHeaderBytes: config.Server.MaxHeaderBytes,
	}

	// Start server in goroutine
	go func() {
		Logger.Info("starting server", zap.String("addr", server.Addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			Logger.Fatal("server failed", zap.Error(err))
		}
	}()

	var metricsServer *http.Server
	if config.Metrics.Enabled {
		metricsMux := http.NewServeMux()
		metricsMux.Handle(config.Metrics.Path, promhttp.Handler())
		metricsServer = &http.Server{
			Addr:              config.Metrics.Address,
			Handler:           metricsMux,
			ReadHeaderTimeout: 5 * time.Second,
		}

		go func() {
			Logger.Info("starting metrics server",
				zap.String("addr", metricsServer.Addr),
				zap.String("path", config.Metrics.Path),
			)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				Logger.Fatal("metrics server failed", zap.Error(err))
			}
		}()
	}

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	Logger.Info("shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		Logger.Error("server forced to shutdown", zap.Error(err))
	}

	if metricsServer != nil {
		if err := metricsServer.Shutdown(ctx); err != nil {
			Logger.Error("metrics server forced to shutdown", zap.Error(err))
		}
	}

	Logger.Info("server stopped")
}
