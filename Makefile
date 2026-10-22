BIN := bin/fumigator
PKG := ./cmd/fumigator
VERSION := $(shell date -u +%Y%m%d)

.PHONY: all build test release clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o $(BIN) $(PKG)

test:
	go vet ./...
	go test ./...
	$(BIN) pack test

release: build
	@mkdir -p dist
	@for t in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64; do \
	  os=$${t%/*}; arch=$${t#*/}; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '-s -w' -o dist/fumigator-$$os-$$arch $(PKG) && echo dist/fumigator-$$os-$$arch; \
	done
	@cp -r packs dist/

clean:
	rm -rf bin dist
