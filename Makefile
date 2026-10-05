GO ?= go
WASM_EXEC := $(shell $(GO) env GOROOT)/lib/wasm/wasm_exec.js

CLAUDE ?= claude

RSVG ?= rsvg-convert

.PHONY: build wasm cli plugin install-plugin uninstall-plugin icons test smoke

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

# Regenerates the extension icons from assets/. The PNGs are committed, so this
# is only needed after editing an SVG, and needs librsvg (brew install librsvg).
# The two small sizes use a simpler design so they stay readable in a toolbar.
icons:
	$(RSVG) -w 16 -h 16 assets/icon-small.svg -o extension/icons/icon-16.png
	$(RSVG) -w 32 -h 32 assets/icon-small.svg -o extension/icons/icon-32.png
	$(RSVG) -w 48 -h 48 assets/icon.svg -o extension/icons/icon-48.png
	$(RSVG) -w 128 -h 128 assets/icon.svg -o extension/icons/icon-128.png

test:
	$(GO) test ./...

smoke: wasm
	node scripts/smoke.mjs
