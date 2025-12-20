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

	"go.uber.org/zap"
)

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
	defer Logger.Sync()

	Logger.Info("configuration loaded",
		zap.String("listen_addr", config.Server.ListenAddr),
		zap.String("backend_endpoint", config.MasterCredentials.Endpoint),
		zap.Int("num_users", len(config.Users)),
	)

	// Create identity store
	identityStore := NewIdentityStore(config.Users)

	// Create auth middleware
	authMiddleware := NewAuthMiddleware(identityStore)

	// Create proxy handler
	proxyHandler := NewProxyHandler(authMiddleware, config.MasterCredentials)

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

	Logger.Info("server stopped")
}

