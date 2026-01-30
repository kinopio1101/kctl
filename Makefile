# Makefile for kctl
# Support cross-platform builds for Windows, Linux, and macOS

# Binary name
BINARY_NAME=kctl

# Version
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Build time
BUILD_TIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# Git commit
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Output directory
OUTPUT_DIR=bin

# Version package path
VERSION_PKG=kctl/cmd/version

# LDFLAGS for versioning
LDFLAGS=-ldflags "-s -w -X $(VERSION_PKG).version=$(VERSION) -X $(VERSION_PKG).commit=$(GIT_COMMIT) -X $(VERSION_PKG).date=$(BUILD_TIME) -X $(VERSION_PKG).builtBy=make"

# Platform and architecture combinations
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

# Go variables
GO=go
GOFLAGS=-v

.PHONY: help all clean build test

# Default target
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@echo "  help              - Show this help message"
	@echo "  all               - Build all platform/architecture binaries"
	@echo "  build             - Build for current platform"
	@echo "  build-all         - Build all platform/architecture binaries (alias for all)"
	@echo "  linux-amd64       - Build for Linux AMD64"
	@echo "  linux-arm64       - Build for Linux ARM64"
	@echo "  darwin-amd64      - Build for macOS Intel (AMD64)"
	@echo "  darwin-arm64      - Build for macOS Apple Silicon (ARM64)"
	@echo "  windows-amd64     - Build for Windows AMD64"
	@echo "  windows-arm64     - Build for Windows ARM64"
	@echo "  clean             - Remove build artifacts"
	@echo "  test              - Run tests"
	@echo "  fmt               - Format Go code"
	@echo "  lint              - Run linter"
	@echo "  install           - Install binary to GOPATH/bin"

# Build for current platform
build:
	@echo "Building $(BINARY_NAME) for current platform..."
	@mkdir -p $(OUTPUT_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(OUTPUT_DIR)/$(BINARY_NAME) ./main/main.go
	@echo "Build complete: $(OUTPUT_DIR)/$(BINARY_NAME)"

# Build all platforms
all: build-all

# Build all platform/architecture combinations
build-all:
	@echo "Building $(BINARY_NAME) for all platforms..."
	@$(MAKE) linux-amd64
	@$(MAKE) linux-arm64
	@$(MAKE) darwin-amd64
	@$(MAKE) darwin-arm64
	@$(MAKE) windows-amd64
	@$(MAKE) windows-arm64
	@echo ""
	@echo "All builds complete!"
	@echo "Binaries are located in: $(OUTPUT_DIR)/"
	@ls -lh $(OUTPUT_DIR)

# Linux AMD64
linux-amd64:
	@echo "Building for Linux AMD64..."
	@mkdir -p $(OUTPUT_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-amd64 ./main/main.go

# Linux ARM64
linux-arm64:
	@echo "Building for Linux ARM64..."
	@mkdir -p $(OUTPUT_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(OUTPUT_DIR)/$(BINARY_NAME)-linux-arm64 ./main/main.go

# macOS Intel (AMD64)
darwin-amd64:
	@echo "Building for macOS Intel (AMD64)..."
	@mkdir -p $(OUTPUT_DIR)
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(OUTPUT_DIR)/$(BINARY_NAME)-darwin-amd64 ./main/main.go

# macOS Apple Silicon (ARM64)
darwin-arm64:
	@echo "Building for macOS Apple Silicon (ARM64)..."
	@mkdir -p $(OUTPUT_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(OUTPUT_DIR)/$(BINARY_NAME)-darwin-arm64 ./main/main.go

# Windows AMD64
windows-amd64:
	@echo "Building for Windows AMD64..."
	@mkdir -p $(OUTPUT_DIR)
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-amd64.exe ./main/main.go

# Windows ARM64
windows-arm64:
	@echo "Building for Windows ARM64..."
	@mkdir -p $(OUTPUT_DIR)
	GOOS=windows GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(OUTPUT_DIR)/$(BINARY_NAME)-windows-arm64.exe ./main/main.go

# Release build - creates a release directory with compressed archives
release: clean build-all
	@echo "Creating release archives..."
	@mkdir -p release
	@cd $(OUTPUT_DIR) && \
		tar -czf ../release/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz $(BINARY_NAME)-linux-amd64 && \
		tar -czf ../release/$(BINARY_NAME)-$(VERSION)-linux-arm64.tar.gz $(BINARY_NAME)-linux-arm64 && \
		tar -czf ../release/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz $(BINARY_NAME)-darwin-amd64 && \
		tar -czf ../release/$(BINARY_NAME)-$(VERSION)-darwin-arm64.tar.gz $(BINARY_NAME)-darwin-arm64 && \
		zip ../release/$(BINARY_NAME)-$(VERSION)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe && \
		zip ../release/$(BINARY_NAME)-$(VERSION)-windows-arm64.zip $(BINARY_NAME)-windows-arm64.exe
	@echo "Release archives created in: release/"
	@ls -lh release/

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(OUTPUT_DIR)
	@rm -rf release
	@echo "Clean complete"

# Run tests
test:
	@echo "Running tests..."
	$(GO) test -v -race ./...

# Format Go code
fmt:
	@echo "Formatting Go code..."
	$(GO) fmt ./...

# Run linter (requires golangci-lint)
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

# Install binary to GOPATH/bin
install:
	@echo "Installing $(BINARY_NAME)..."
	$(GO) install $(LDFLAGS) ./main/main.go
	@echo "Installed: $(shell go env GOPATH)/bin/$(BINARY_NAME)"

# Show version information
version:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"

# Show build environment info
env:
	@echo "Go Version: $(shell $(GO) version)"
	@echo "GOOS: $(shell go env GOOS)"
	@echo "GOARCH: $(shell go env GOARCH)"
	@echo "GOPATH: $(shell go env GOPATH)"
	@echo "GOROOT: $(shell go env GOROOT)"
