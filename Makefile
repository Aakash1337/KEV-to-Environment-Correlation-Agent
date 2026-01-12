.PHONY: build clean run-cli run-web install test fmt vet tidy help

# Build configuration
BINARY_CLI=kev-mapper
BINARY_WEB=kev-webapp
BUILD_DIR=bin
GO=go
GOFLAGS=-v

# Build both binaries
build: build-cli build-web

# Build CLI binary
build-cli:
	@echo "Building CLI..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_CLI) ./cmd/kev-mapper

# Build web server binary
build-web:
	@echo "Building web server..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_WEB) ./cmd/webapp

# Install dependencies
install:
	@echo "Installing dependencies..."
	$(GO) mod download
	$(GO) mod tidy

# Run CLI
run-cli: build-cli
	@echo "Running KEV Mapper CLI..."
	./$(BUILD_DIR)/$(BINARY_CLI) --help

# Run web server
run-web: build-web
	@echo "Starting KEV Mapper Web UI..."
	./$(BUILD_DIR)/$(BINARY_WEB)

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f kev-mapper kev-webapp

# Run tests
test:
	@echo "Running tests..."
	$(GO) test -v ./...

# Format code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

# Run vet
vet:
	@echo "Running go vet..."
	$(GO) vet ./...

# Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GO) mod tidy

# Quick sync command
sync: build-cli
	@./$(BUILD_DIR)/$(BINARY_CLI) sync

# Full workflow
full-sync: build-cli
	@./$(BUILD_DIR)/$(BINARY_CLI) full-sync

# Show help
help:
	@echo "KEV Mapper - Makefile Commands"
	@echo ""
	@echo "Building:"
	@echo "  make build       - Build both CLI and web server"
	@echo "  make build-cli   - Build CLI only"
	@echo "  make build-web   - Build web server only"
	@echo ""
	@echo "Running:"
	@echo "  make run-cli     - Run CLI (shows help)"
	@echo "  make run-web     - Run web server"
	@echo "  make sync        - Quick KEV sync"
	@echo "  make full-sync   - Run full workflow"
	@echo ""
	@echo "Development:"
	@echo "  make install     - Install dependencies"
	@echo "  make test        - Run tests"
	@echo "  make fmt         - Format code"
	@echo "  make vet         - Run go vet"
	@echo "  make tidy        - Tidy dependencies"
	@echo "  make clean       - Clean build artifacts"
	@echo ""
