# X-Monitor build
BIN := bin
GOFLAGS :=
VERSION := 0.1.0-dev

.PHONY: ui-smoke all build test vet clean install cross es-client

all: build

build:
	@mkdir -p $(BIN)
	go build $(GOFLAGS) -ldflags "-X main.version=$(VERSION)" -o $(BIN)/xmond ./cmd/xmond
	go build $(GOFLAGS) -o $(BIN)/xmon ./cmd/xmon
	go build $(GOFLAGS) -o $(BIN)/xmon-hook ./cmd/xmon-hook
	@echo "built -> $(BIN)/"

test:
	go test ./...

vet:
	go vet ./...

# Verify every target platform compiles (eBPF probe is subprocess-based, so no cgo).
cross:
	GOOS=linux   GOARCH=amd64 go build ./...
	GOOS=linux   GOARCH=arm64 go build ./...
	GOOS=darwin  GOARCH=arm64 go build ./...
	GOOS=windows GOARCH=amd64 go build ./...
	@echo "all platforms compile"

install: build
	install -m 0755 $(BIN)/xmond $(BIN)/xmon $(BIN)/xmon-hook $(HOME)/.local/bin/ 2>/dev/null || \
	  { echo "copy bin/* to a directory on PATH"; }

# macOS only: build the experimental Endpoint Security AUTH client (see macos/XmonES/README.md).
es-client:
	@mkdir -p $(BIN)
	swiftc macos/XmonES/main.swift -o $(BIN)/xmon-es -lEndpointSecurity -lbsm

# Needs a running daemon and Chrome: make ui-smoke URL=http://127.0.0.1:7788 TOKEN=$(cat ~/.xmon/token)
ui-smoke:
	node scripts/ui_smoke.mjs $(URL) $(TOKEN)

clean:
	rm -rf $(BIN)
