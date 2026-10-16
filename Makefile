GO ?= go

.PHONY: build test race vet check

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/server ./cmd/server
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/client ./cmd/client

test:
	$(GO) test ./... -timeout 180s

race:
	$(GO) test -race -short ./... -timeout 120s

vet:
	$(GO) vet ./...

check: test race vet
