.PHONY: all build lint tidy clean pkgs

all: tidy build lint

## List all packages
pkgs:
	go list ./...

## Ensure go.mod is clean
tidy:
	go mod tidy
	git diff --exit-code

build:
	go build -o fl

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