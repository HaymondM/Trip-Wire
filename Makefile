GO ?= go
WASM_EXEC := $(shell $(GO) env GOROOT)/lib/wasm/wasm_exec.js

.PHONY: build wasm cli plugin test smoke

build: wasm cli plugin

cli:
	$(GO) build -trimpath -o bin/trip-wire ./cmd/trip-wire

# The Claude Code plugin runs the CLI from inside its own directory.
plugin:
	$(GO) build -trimpath -o claude-code-plugin/bin/trip-wire ./cmd/trip-wire

wasm:
	GOOS=js GOARCH=wasm $(GO) build -trimpath -ldflags="-s -w" -o extension/engine.wasm ./cmd/wasm
	cp "$(WASM_EXEC)" extension/wasm_exec.js

test:
	$(GO) test ./...

smoke: wasm
	node scripts/smoke.mjs
