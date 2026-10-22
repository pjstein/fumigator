BIN := bin/fumigator
PKG := ./cmd/fumigator
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build install lint test release clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)

# install puts this exact build on PATH (GOPATH/bin), so `fumigator` and bin/fumigator never differ
install:
	CGO_ENABLED=0 go install -trimpath -ldflags '$(LDFLAGS)' $(PKG)
	@echo "installed $$(go env GOPATH)/bin/fumigator ($(VERSION))"

lint:
	golangci-lint run ./...

test: lint
	go vet ./...
	go test ./...
	$(BIN) pack test

release: build
	@mkdir -p dist
	@for t in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64; do \
	  os=$${t%/*}; arch=$${t#*/}; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o dist/fumigator-$$os-$$arch $(PKG) && echo dist/fumigator-$$os-$$arch; \
	done
	@cp -r packs dist/

clean:
	rm -rf bin dist
