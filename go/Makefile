.PHONY: all test lint tidy clean pkgs

all: test-kem test-sha3 test-dsa lint

## List all packages
pkgs:
	go list ./...

## Ensure go.mod is clean
tidy:
	go mod tidy
	git diff --exit-code

build:
	go build -o forgelattice

## Test all packages
test-ml: test-kem test-sha3 test-dsa

test-kem:
	go test -count=1 -v -race -cover ./crypto/kem/...

test-sha3:
	go test -count=1 -v -race -cover ./crypto/sha3/...

test-dsa:
	go test -count=1 -v -race -cover ./crypto/sign/...

## Lint (requires golangci-lint installed)
LINT_BIN := $(shell go env GOPATH)/bin/golangci-lint

lint:
	@if [ ! -f "$(LINT_BIN)" ]; then \
		echo "==> Installing golangci-lint"; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
		| sh -s -- -b $(shell go env GOPATH)/bin v1.64.8; \
	fi
	$(LINT_BIN) run ./...

## Clean build artifacts (optional)
clean:
	go clean ./...