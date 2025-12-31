package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// ConfigReloader manages configuration reloading with SIGHUP support
type ConfigReloader struct {
	configPath     string
	identityStore  *IdentityStore
	authMiddleware *AuthMiddleware
	mu             sync.RWMutex
	reloadChan     chan os.Signal
	stopChan       chan struct{}
	wg             sync.WaitGroup
}

// NewConfigReloader creates a new configuration reloader
func NewConfigReloader(configPath string, identityStore *IdentityStore, authMiddleware *AuthMiddleware) *ConfigReloader {
	return &ConfigReloader{
		configPath:     configPath,
		identityStore:  identityStore,
		authMiddleware: authMiddleware,
		reloadChan:     make(chan os.Signal, 1),
		stopChan:       make(chan struct{}),
	}
}

// Start begins listening for SIGHUP signals
func (cr *ConfigReloader) Start() {
	cr.wg.Add(1)
	go cr.signalHandler()

	Logger.Info("configuration reloader started",
		zap.String("config_path", cr.configPath),
		zap.String("signal", "SIGHUP"),
	)
}

// Stop stops the configuration reloader
func (cr *ConfigReloader) Stop() {
	close(cr.stopChan)
	cr.wg.Wait()
	Logger.Info("configuration reloader stopped")
}

// ReloadConfig reloads the configuration file and updates the identity store
func (cr *ConfigReloader) ReloadConfig() error {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	Logger.Info("reloading configuration", zap.String("config_path", cr.configPath))

	// Load new configuration
	config, err := LoadConfig(cr.configPath)
	if err != nil {
		Logger.Error("failed to reload configuration",
			zap.String("config_path", cr.configPath),
			zap.Error(err),
		)
		return fmt.Errorf("failed to reload config: %w", err)
	}

	// Update identity store with new users
	oldUserCount := cr.identityStore.GetUserCount()
	cr.identityStore.UpdateUsers(config.Users)
	newUserCount := cr.identityStore.GetUserCount()

	Logger.Info("configuration reloaded successfully",
		zap.String("config_path", cr.configPath),
		zap.Int("old_user_count", oldUserCount),
		zap.Int("new_user_count", newUserCount),
		zap.Int("user_count_delta", newUserCount-oldUserCount),
	)

	return nil
}

// signalHandler listens for SIGHUP signals and triggers reloads
func (cr *ConfigReloader) signalHandler() {
	defer cr.wg.Done()

	// Set up signal handling for SIGHUP
	signal.Notify(cr.reloadChan, syscall.SIGHUP)

	for {
		select {
		case <-cr.reloadChan:
			// Handle SIGHUP signal
			if err := cr.ReloadConfig(); err != nil {
				Logger.Error("failed to reload configuration on SIGHUP", zap.Error(err))
			} else {
				Logger.Info("configuration reloaded via SIGHUP")
			}

		case <-cr.stopChan:
			// Stop signal handling
			signal.Stop(cr.reloadChan)
			return
		}
	}
}

// WatchConfigFile starts watching the configuration file for changes (optional)
func (cr *ConfigReloader) WatchConfigFile(ctx context.Context, pollInterval time.Duration) {
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second // Default poll interval
	}

	cr.wg.Add(1)
	go func() {
		defer cr.wg.Done()

		var lastModTime time.Time

		// Get initial modification time
		if info, err := os.Stat(cr.configPath); err == nil {
			lastModTime = info.ModTime()
		}

		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()

		Logger.Info("started configuration file watcher",
			zap.String("config_path", cr.configPath),
			zap.Duration("poll_interval", pollInterval),
		)

		for {
			select {
			case <-ticker.C:
				// Check if file has been modified
				info, err := os.Stat(cr.configPath)
				if err != nil {
					Logger.Warn("failed to stat config file",
						zap.String("config_path", cr.configPath),
						zap.Error(err),
					)
					continue
				}

				currentModTime := info.ModTime()
				if currentModTime.After(lastModTime) {
					Logger.Info("configuration file modified, triggering reload",
						zap.String("config_path", cr.configPath),
						zap.Time("last_modified", lastModTime),
						zap.Time("current_modified", currentModTime),
					)

					if err := cr.ReloadConfig(); err != nil {
						Logger.Error("failed to reload configuration on file change", zap.Error(err))
					}

					lastModTime = currentModTime
				}

			case <-ctx.Done():
				Logger.Info("configuration file watcher stopped")
				return
			}
		}
	}()
}
