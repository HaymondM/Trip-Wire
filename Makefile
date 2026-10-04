GO ?= go
WASM_EXEC := $(shell $(GO) env GOROOT)/lib/wasm/wasm_exec.js

.PHONY: build wasm test smoke

build: wasm

wasm:
	GOOS=js GOARCH=wasm $(GO) build -trimpath -ldflags="-s -w" -o extension/engine.wasm ./cmd/wasm
	cp "$(WASM_EXEC)" extension/wasm_exec.js

test:
	$(GO) test ./...

smoke: wasm
	node scripts/smoke.mjs
