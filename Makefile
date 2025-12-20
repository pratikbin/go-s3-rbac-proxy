.PHONY: build run test clean deps lint docker

# Binary name
BINARY_NAME=s3-proxy

# Build the application
build:
	go build -o $(BINARY_NAME) -v

# Run the application
run: build
	./$(BINARY_NAME) -config config.yaml

# Run tests
test:
	go test -v -race -coverprofile=coverage.out ./...

# View coverage
coverage: test
	go tool cover -html=coverage.out

# Clean build artifacts
clean:
	go clean
	rm -f $(BINARY_NAME)
	rm -f coverage.out

# Download dependencies
deps:
	go mod download
	go mod verify

# Install dependencies
install-deps: deps
	go mod tidy

# Run linter
lint:
	golangci-lint run

# Format code
fmt:
	go fmt ./...

# Build Docker image
docker:
	docker build -t s3-proxy:latest .

# Run Docker container
docker-run:
	docker run -p 8080:8080 -v $(PWD)/config.yaml:/etc/s3-proxy/config.yaml s3-proxy:latest

# Load test (requires vegeta)
load-test:
	@echo "GET http://localhost:8080/test-bucket/" | \
		vegeta attack -duration=10s -rate=50 | \
		vegeta report -type=text

# Help
help:
	@echo "Available targets:"
	@echo "  build        - Build the binary"
	@echo "  run          - Build and run the application"
	@echo "  test         - Run tests with race detection"
	@echo "  coverage     - Generate and view test coverage"
	@echo "  clean        - Remove build artifacts"
	@echo "  deps         - Download dependencies"
	@echo "  install-deps - Download and tidy dependencies"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  docker       - Build Docker image"
	@echo "  docker-run   - Run Docker container"
	@echo "  load-test    - Run load test (requires vegeta)"

