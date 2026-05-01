SHELL := /bin/bash
GO    ?= go
BIN   := bin/eyeexam
PKG   := github.com/eavalenzuela/eyeexam

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
  -X $(PKG)/internal/version.Version=$(VERSION) \
  -X $(PKG)/internal/version.Commit=$(COMMIT) \
  -X $(PKG)/internal/version.Date=$(DATE)

.PHONY: all
all: build

.PHONY: tools
tools:
	# golangci-lint v2 — .golangci.yml uses v2 schema (`version: "2"`,
	# `linters.default`); v1 binaries reject the config. v2.1.6 (the
	# first v2 release) was built with Go 1.24 and refuses to lint
	# this repo (go.mod targets 1.25). v2.12.0 is what CI picks via
	# `latest`; pin here for matching local installs.
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.0
	$(GO) install mvdan.cc/gofumpt@latest
	$(GO) install gotest.tools/gotestsum@latest

.PHONY: fmt
fmt:
	gofumpt -w .

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: test
test:
	$(GO) test -race -count=1 ./...

.PHONY: testsum
testsum:
	gotestsum --format=testname -- -race -count=1 ./...

.PHONY: build
build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/eyeexam

.PHONY: dist
dist:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/eyeexam-linux-amd64    ./cmd/eyeexam
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/eyeexam-linux-arm64    ./cmd/eyeexam
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/eyeexam-darwin-arm64   ./cmd/eyeexam

.PHONY: clean
clean:
	rm -rf bin dist coverage.* *.out

.PHONY: tidy
tidy:
	$(GO) mod tidy
