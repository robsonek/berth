VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/robsonek/berth/internal/version.Version=$(VERSION) \
	-X github.com/robsonek/berth/internal/version.Commit=$(COMMIT) \
	-X github.com/robsonek/berth/internal/version.Date=$(DATE)

.PHONY: build test

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o berth .

test:
	go test ./...
