IMAGE ?= ghcr.io/example/mcp-oauth-proxy
# Single source of truth for the release version; the Dockerfile reads the same
# file, so `make image` and a plain `docker build` agree.
VERSION ?= $(shell tr -d ' \t\r\n' < VERSION)

.PHONY: all build test lint image push clean dev-upstream

all: test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/mcp-oauth-proxy ./cmd/mcp-oauth-proxy

test:
	go test -race ./...

lint:
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

push: image
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest

clean:
	rm -rf bin

# Stub MCP server for exercising a configuration locally. Prints the identity
# headers the proxy attaches. Not part of the shipped image.
dev-upstream:
	go run ./dev/stub-upstream -addr $(or $(ADDR),127.0.0.1:3000)
