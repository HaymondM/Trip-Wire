GO ?= go
WASM_EXEC := $(shell $(GO) env GOROOT)/lib/wasm/wasm_exec.js

CLAUDE ?= claude

.PHONY: build wasm cli plugin install-plugin uninstall-plugin test smoke

build: wasm cli plugin

cli:
	$(GO) build -trimpath -o bin/trip-wire ./cmd/trip-wire

# The Claude Code plugin runs the CLI from inside its own directory.
plugin:
	$(GO) build -trimpath -o claude-code-plugin/bin/trip-wire ./cmd/trip-wire

# Installs the plugin for every Claude Code session (terminal and the desktop
# app's Code tab). Claude Code caches installed plugins by version, so this
# reinstalls to pick up a rebuilt binary; `claude plugin update` won't.
install-plugin: plugin
	$(CLAUDE) plugin marketplace add "$(CURDIR)"
	@$(CLAUDE) plugin uninstall trip-wire@trip-wire >/dev/null 2>&1 || true
	$(CLAUDE) plugin install trip-wire@trip-wire

uninstall-plugin:
	$(CLAUDE) plugin marketplace remove trip-wire

wasm:
	GOOS=js GOARCH=wasm $(GO) build -trimpath -ldflags="-s -w" -o extension/engine.wasm ./cmd/wasm
	cp "$(WASM_EXEC)" extension/wasm_exec.js

test:
	$(GO) test ./...

smoke: wasm
	node scripts/smoke.mjs
