MODULE = $(shell go list -m)
VERSION ?= $(shell git describe --tags --always --dirty --match=v* 2> /dev/null || echo "0.1.0")
GO_VERSION := $(shell grep -E '^go [0-9]+\.[0-9]+\.[0-9]+' go.mod | sed 's/go //g' | tr -d ' ')
LDFLAGS := -ldflags "-X main.Version=${VERSION}"
BINARY := bin/goff

.PHONY: all
all: fmt vet test build ## Run baseline quality checks and build

.PHONY: check-go-version
check-go-version: ## Ensure local Go version matches go.mod
	@go version | grep -q "go$(GO_VERSION)" || (echo "Error: Go version mismatch. Required: $(GO_VERSION), Current: $$(go version | awk '{print $$3}' | sed 's/go//')" && exit 1)
	@echo "Using Go version: $(GO_VERSION)"

.PHONY: build
build: check-go-version ## Build goff binary
	@mkdir -p bin
	go build ${LDFLAGS} -trimpath -o $(BINARY) ./cmd/goff

.PHONY: test
test: check-go-version ## Run tests
	go test -v -race -count=1 ./...

.PHONY: bench
bench: check-go-version ## Run baseline benchmarks
	go test -run '^$$' -bench . -benchmem ./internal/pipeline

.PHONY: lint
lint: ## Run golangci-lint if installed
	golangci-lint run ./...

.PHONY: fmt
fmt: ## Format source
	gofmt -s -w .

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## Tidy module dependencies
	go mod tidy

.PHONY: clean
clean: ## Clean build artifacts
	go clean
	rm -rf bin cover.out coverage.out

.PHONY: help
help: ## List make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-24s\033[0m %s\n", $$1, $$2}'
