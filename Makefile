# Makefile for Go S3 IAM Proxy

.PHONY: help build start stop test test-upload generate-test-files cleanup-test-files lint all

# Variables
BINARY_NAME=s3-proxy
CONFIG_FILE=config.yaml
PID_FILE=/tmp/s3-proxy.pid
LOG_FILE=/tmp/s3-proxy.log
TEST_DIR=tempfiles
MC_ALIAS=localhost
MC_BUCKET=nodeops-registry

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the proxy binary
	@echo "Building $(BINARY_NAME)..."
	@go build -o $(BINARY_NAME) .
	@echo "✓ Build complete: $(BINARY_NAME)"

start: build ## Start the proxy server in background
	@echo "Starting $(BINARY_NAME) in background..."
	@if [ -f $(PID_FILE) ] && kill -0 $$(cat $(PID_FILE)) 2>/dev/null; then \
		echo "✗ Server already running (PID: $$(cat $(PID_FILE)))"; \
		exit 1; \
	fi
	@./$(BINARY_NAME) -config $(CONFIG_FILE) > $(LOG_FILE) 2>&1 & echo $$! > $(PID_FILE)
	@sleep 2
	@if kill -0 $$(cat $(PID_FILE)) 2>/dev/null; then \
		echo "✓ Server started (PID: $$(cat $(PID_FILE)))"; \
		echo "  Logs: tail -f $(LOG_FILE)"; \
	else \
		echo "✗ Server failed to start. Check logs: $(LOG_FILE)"; \
		cat $(LOG_FILE); \
		rm -f $(PID_FILE); \
		exit 1; \
	fi

stop: ## Stop the background server
	@echo "Stopping $(BINARY_NAME)..."
	@if [ -f $(PID_FILE) ]; then \
		PID=$$(cat $(PID_FILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			kill $$PID; \
			sleep 1; \
			if kill -0 $$PID 2>/dev/null; then \
				kill -9 $$PID 2>/dev/null; \
			fi; \
			rm -f $(PID_FILE); \
			echo "✓ Server stopped (PID: $$PID)"; \
		else \
			echo "✗ Server not running (stale PID file)"; \
			rm -f $(PID_FILE); \
		fi \
	else \
		echo "✗ No PID file found. Attempting to kill by name..."; \
		pkill -9 $(BINARY_NAME) 2>/dev/null && echo "✓ Killed $(BINARY_NAME) processes" || echo "✗ No running processes found"; \
	fi
	lsof -i :8080 | awk '{print $2}' | tail -n1 | xargs kill -9 || true

restart: stop start ## Restart the server

status: ## Check server status
	@if [ -f $(PID_FILE) ] && kill -0 $$(cat $(PID_FILE)) 2>/dev/null; then \
		echo "✓ Server is running (PID: $$(cat $(PID_FILE)))"; \
		echo "  Listening on: $$(grep listen_addr $(CONFIG_FILE) | awk '{print $$2}' | tr -d '\"')"; \
		echo "  Uptime: $$(ps -p $$(cat $(PID_FILE)) -o etime= | tr -d ' ')"; \
	else \
		echo "✗ Server is not running"; \
	fi

logs: ## Tail server logs
	@if [ -f $(LOG_FILE) ]; then \
		tail -f $(LOG_FILE); \
	else \
		echo "✗ Log file not found: $(LOG_FILE)"; \
	fi

generate-test-files: ## Generate random test files with special characters (up to 10MB each)
	@echo "Generating test files in $(TEST_DIR)/..."
	@mkdir -p $(TEST_DIR)
	@# Generate files with various special characters and sizes
	@# File 1: Spaces and parentheses
	@dd if=/dev/urandom of=$(TEST_DIR)/"my file (1).txt" bs=1024 count=$$((RANDOM % 1024 + 1)) 2>/dev/null
	@echo "  ✓ Created: my file (1).txt ($$(du -h $(TEST_DIR)/"my file (1).txt" | cut -f1))"
	@# File 2: Brackets and numbers
	@dd if=/dev/urandom of=$(TEST_DIR)/"test [file] 2.bin" bs=1024 count=$$((RANDOM % 2048 + 1)) 2>/dev/null
	@echo "  ✓ Created: test [file] 2.bin ($$(du -h $(TEST_DIR)/"test [file] 2.bin" | cut -f1))"
	@# File 3: Special symbols
	@dd if=/dev/urandom of=$(TEST_DIR)/"data@2024.dat" bs=1024 count=$$((RANDOM % 3072 + 1)) 2>/dev/null
	@echo "  ✓ Created: data@2024.dat ($$(du -h $(TEST_DIR)/"data@2024.dat" | cut -f1))"
	@# File 4: Underscores and hyphens (should not be encoded)
	@dd if=/dev/urandom of=$(TEST_DIR)/"file_name-test.txt" bs=1024 count=$$((RANDOM % 512 + 1)) 2>/dev/null
	@echo "  ✓ Created: file_name-test.txt ($$(du -h $(TEST_DIR)/"file_name-test.txt" | cut -f1))"
	@# File 5: Plus and equals
	@dd if=/dev/urandom of=$(TEST_DIR)/"formula+equals=result.log" bs=1024 count=$$((RANDOM % 4096 + 1)) 2>/dev/null
	@echo "  ✓ Created: formula+equals=result.log ($$(du -h $(TEST_DIR)/"formula+equals=result.log" | cut -f1))"
	@# File 6: Ampersand and comma
	@dd if=/dev/urandom of=$(TEST_DIR)/"data&more,info.csv" bs=1024 count=$$((RANDOM % 5120 + 1)) 2>/dev/null
	@echo "  ✓ Created: data&more,info.csv ($$(du -h $(TEST_DIR)/"data&more,info.csv" | cut -f1))"
	@# File 7: Exclamation and question marks
	@dd if=/dev/urandom of=$(TEST_DIR)/"important!.txt" bs=1024 count=$$((RANDOM % 1536 + 1)) 2>/dev/null
	@echo "  ✓ Created: important!.txt ($$(du -h $(TEST_DIR)/"important!.txt" | cut -f1))"
	@# File 8: Tilde (should not be encoded)
	@dd if=/dev/urandom of=$(TEST_DIR)/"backup~old.bak" bs=1024 count=$$((RANDOM % 2560 + 1)) 2>/dev/null
	@echo "  ✓ Created: backup~old.bak ($$(du -h $(TEST_DIR)/"backup~old.bak" | cut -f1))"
	@# File 9: Large file (5-10MB)
	@dd if=/dev/urandom of=$(TEST_DIR)/"large file (big).bin" bs=1024 count=$$((RANDOM % 5120 + 5120)) 2>/dev/null
	@echo "  ✓ Created: large file (big).bin ($$(du -h $(TEST_DIR)/"large file (big).bin" | cut -f1))"
	@# File 10: Multiple special chars
	@dd if=/dev/urandom of=$(TEST_DIR)/"test[2024]@v1.0_final.tar.gz" bs=1024 count=$$((RANDOM % 3584 + 1)) 2>/dev/null
	@echo "  ✓ Created: test[2024]@v1.0_final.tar.gz ($$(du -h $(TEST_DIR)/"test[2024]@v1.0_final.tar.gz" | cut -f1))"
	@# Create subdirectory with files
	@mkdir -p $(TEST_DIR)/subdir
	@dd if=/dev/urandom of=$(TEST_DIR)/subdir/"nested (file).txt" bs=1024 count=$$((RANDOM % 1024 + 1)) 2>/dev/null
	@echo "  ✓ Created: subdir/nested (file).txt ($$(du -h $(TEST_DIR)/subdir/"nested (file).txt" | cut -f1))"
	@dd if=/dev/urandom of=$(TEST_DIR)/subdir/"data@nested.bin" bs=1024 count=$$((RANDOM % 2048 + 1)) 2>/dev/null
	@echo "  ✓ Created: subdir/data@nested.bin ($$(du -h $(TEST_DIR)/subdir/"data@nested.bin" | cut -f1))"
	@echo ""
	@echo "Summary:"
	@echo "  Total files: $$(find $(TEST_DIR) -type f | wc -l | tr -d ' ')"
	@echo "  Total size: $$(du -sh $(TEST_DIR) | cut -f1)"

cleanup-test-files: ## Delete the tempfiles directory
	@echo "Cleaning up test files..."
	@if [ -d $(TEST_DIR) ]; then \
		rm -rf $(TEST_DIR); \
		echo "✓ Deleted $(TEST_DIR)/"; \
	else \
		echo "✓ $(TEST_DIR)/ does not exist"; \
	fi

test-upload: ## Upload tempfiles directory to S3 via proxy
	@if [ ! -d $(TEST_DIR) ]; then \
		echo "✗ Test files not found. Run 'make generate-test-files' first."; \
		exit 1; \
	fi
	@if ! kill -0 $$(cat $(PID_FILE) 2>/dev/null) 2>/dev/null; then \
		echo "✗ Server not running. Run 'make start' first."; \
		exit 1; \
	fi
	@echo "Uploading $(TEST_DIR)/ to $(MC_ALIAS)/$(MC_BUCKET)/..."
	@echo "Files to upload:"
	@find $(TEST_DIR) -type f -exec echo "  - {}" \;
	@echo ""
	@mc cp -r $(TEST_DIR) $(MC_ALIAS)/$(MC_BUCKET)/
	@echo ""
	@echo "✓ Upload complete. Verifying..."
	@mc ls $(MC_ALIAS)/$(MC_BUCKET)/$(TEST_DIR)/ | head -10

test: build generate-test-files ## Full test: build, generate files, start server, upload, stop
	@echo "=== Running Full Test Suite ==="
	@echo ""
	@$(MAKE) start
	@sleep 2
	@echo ""
	@$(MAKE) test-upload
	@echo ""
	@echo "=== Test Results ==="
	@mc ls $(MC_ALIAS)/$(MC_BUCKET)/$(TEST_DIR)/ | wc -l | xargs echo "  Files uploaded:"
	@echo ""
	@$(MAKE) stop
	@echo ""
	@echo "✓ Full test complete!"

test-quick: start test-upload stop ## Quick test: start, upload, stop (assumes files exist)

lint: ## Run golangci-lint
	@echo "Running golangci-lint..."
	@golangci-lint run
	@echo "✓ Linting complete"

test-go: ## Run Go unit tests
	@echo "Running Go tests..."
	@go test ./...
	@echo "✓ Tests complete"

test-localstack: ## Run integration tests with LocalStack (using testcontainers-go)
	@echo "Running LocalStack integration tests with testcontainers-go..."
	@echo "Note: Tests will automatically start LocalStack containers via testcontainers-go"
	@go test -v -tags=localstack ./...
	@echo "✓ LocalStack tests complete"

localstack-up: ## Start LocalStack manually via Docker Compose (for manual testing)
	@echo "Starting LocalStack via Docker Compose..."
	@docker compose up -d --wait
	@echo "✓ LocalStack is running on http://localhost:4566"

test-all: lint test-go test ## Run all tests (lint, unit tests, integration test)

clean: stop cleanup-test-files ## Stop server and clean up all test files
	@rm -f $(BINARY_NAME)
	@rm -f $(LOG_FILE)
	@rm -f $(PID_FILE)
	@echo "✓ Cleanup complete"

all: build test ## Build and run full test suite

dev: ## Run in development mode (foreground with console logging)
	@echo "Starting $(BINARY_NAME) in development mode..."
	@echo "Press Ctrl+C to stop"
	@./$(BINARY_NAME) -config $(CONFIG_FILE)

install: build ## Install binary to /usr/local/bin
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	@sudo cp $(BINARY_NAME) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "✓ Installed successfully"

uninstall: ## Uninstall binary from /usr/local/bin
	@echo "Uninstalling $(BINARY_NAME)..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "✓ Uninstalled successfully"

.DEFAULT_GOAL := help
