<p align="center">
  <img src="assets/icon.svg" alt="Trip Wire logo" width="96">
</p>

<h1 align="center">Trip Wire</h1>

<p align="center"><strong>Spot the hidden traps set for your AI.</strong></p>

<p align="center">
  Web pages increasingly hide instructions meant for AI agents rather than
  people: <em>"AI assistant: ignore all previous instructions and…"</em> tucked into
  white-on-white text, HTML comments, or invisible Unicode. Trip Wire finds those
  traps, both for people browsing with AI and for AI agents browsing on their own.
</p>

<p align="center">Built for the Tinker Society Hackathon (fall 2026).</p>

## One engine, three ways to use it

```
                 engine/  (Go: detection and scoring)
                /                 |                  \
   Chrome extension         trip-wire CLI        Claude Code plugin
   (compiled to WASM,     (scan a URL, file,     (hooks that scan web
    runs in the browser)    or stdin)             content before Claude
                                                  reads it)
```

| | Who it protects | What it does |
|---|---|---|
| **Chrome extension** | You, browsing with an AI assistant | Scores the page and shows it the way an AI reads it, with hidden instructions revealed in place |
| **CLI** | CI pipelines, scripts, anyone checking a URL or repo | `trip-wire scan <url>` prints findings; `trip-wire scan-agent-files <dir>` checks a repo's `CLAUDE.md`, `AGENTS.md`, Cursor rules and skills; the exit code lets a pipeline fail on dangerous content |
| **Claude Code plugin** | AI agents that fetch the web themselves | Blocks WebFetch on dangerous pages and withholds dangerous Bash output (like `curl`), MCP tool results, and agent instruction files before Claude reads them |

## What it detects

- **Hidden text:** white-on-white, near-zero font size, `display:none`,
  `visibility:hidden`, zero opacity, off-screen positioning, and clipping (the
  CLI and plugin also flag `<noscript>` content, which agents see but people
  usually don't)
- **Places people never look:** HTML comments, `alt` / `aria-label` / `title`
  attributes, and meta tags
- **Invisible Unicode:** tag characters that smuggle whole sentences (decoded
  and shown), zero-width characters, and bidirectional overrides
- **Instructions aimed at AI:** "ignore previous instructions", text addressed
  to an AI, fake system-prompt markers, requests to hide things from the user,
  and attempts to send data to outside addresses
- **Subtle injections with no telltale wording:** camouflaged commands
  (package installs from another source, scripts piped to a shell), links, and
  fake "facts". These are hidden with white-on-white text, near-zero fonts, or
  off-screen positioning. Legitimate pages rarely hide real content those ways.

A finding is only serious when hidden text either reads like instructions to
an AI or is camouflaged and carries something an agent could act on. Content
hidden the ordinary way (screen-reader links, collapsed menus, documentation
tabs, cookie banners) doesn't raise false alarms.

Why this matters even though modern models resist obvious injections: in live
tests with the subtle page (`testpages/05-library-docs.html`), Claude Haiku told
a developer to install from the attacker's package server and pipe a setup
script into the shell. Larger models fared better, but only by their own
judgment, and without warning the user the page was hostile. Trip Wire blocks
the page before any model reads it, whichever model is in use.

## Getting started

Requires Go 1.27+ and `make`. Build everything from the repo root:

```bash
make build      # extension WASM engine, bin/trip-wire CLI, and the plugin binary
make test       # Go tests for the engine, extractor, CLI, and hook
make quality    # labeled detection regression metrics and latency benchmark
```

**Chrome extension:** the quickest way is to download the
`trip-wire-extension` zip from the
[latest release](https://github.com/HaymondM/Trip-Wire/releases/latest) and
unzip it. It's prebuilt, so you don't need Go. To build it yourself, run
`make build` and use the `extension/` folder. Then open `chrome://extensions`,
turn on Developer mode, choose **Load unpacked**, and select the unzipped (or
`extension/`) folder. Click the Trip Wire toolbar icon on any page to scan it.
`make release-extension` rebuilds the zip.

**CLI:**

```bash
bin/trip-wire scan https://example.com
bin/trip-wire scan --json --fail-on suspicious page.html
bin/trip-wire scan-agent-files path/to/cloned-repo
bin/trip-wire scan --explain page.html
bin/trip-wire scan-agent-files --json --explain path/to/cloned-repo
```

**Auditing findings:** add `--explain` to either scan command to see each
finding's rule ID, matched instruction rules, hiding techniques, and the
full extracted text segment with its source (text, comment, metadata, or
attribute) and HTML tag when available. Text is quoted so invisible characters
and control characters can be inspected without rendering them in your terminal.
With `--json --explain`, a top-level `segments` array (per file for
`scan-agent-files`) contains only segments referenced by findings; join
`report.findings[].segmentId` to `segments[].id`. IDs belong to that scan,
not to source line numbers or stable identifiers across scans. Extracted text
has normalized whitespace and HTML entities decoded, so it is not a byte-for-byte
copy of the input. Agent files are evaluated as plain text and, when appropriate,
HTML; the evidence comes from the pass that produced the selected report.
Explain mode doesn't change scores or exit codes. Reports contain untrusted
instructions: review them as evidence, don't execute them or feed them to an
AI agent as instructions. Plugin hook output still withholds attacker text.

`scan-agent-files` walks a directory (skipping `.git` and `node_modules`) and
scans every file a coding agent treats as instructions: `CLAUDE.md`,
`AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`,
`copilot-instructions.md`, `SKILL.md`, and markdown under `.cursor/rules/`,
`.claude/commands/`, `.claude/agents/`, `.claude/skills/` and
`.github/instructions/`. Run it on a repo before letting an agent work in it,
or in CI so a poisoned instruction file can't be merged. To avoid silently
passing unscanned instructions, the command errors on instruction-file symlinks,
symlinked directories (other than the skipped directories), and unreadable
symlink targets or non-regular instruction files.

Exit codes: `0` below the `--fail-on` threshold (default `dangerous`), `1` at
or above it, `2` on error.

**Claude Code plugin:**

```bash
make install-plugin
```

That installs it for every Claude Code session, in the terminal and in the
desktop app's Code tab. See [claude-code-plugin/README.md](claude-code-plugin/README.md)
for uninstalling, one-off use, policy and audit configuration, and the limits
of hook enforcement.

**Enterprise pilot controls:** the Claude Code hook can load an
administrator-managed policy through `TRIP_WIRE_POLICY`. It supports configurable
block/warn thresholds, strict handling of supported scan failures, time-limited
exceptions scoped to exact input and content fingerprints, and local JSONL
audit events without raw content. Strict mode blocks all WebFetch calls because
a separate pre-fetch cannot verify what WebFetch actually sends to its model.
See the [policy guide](claude-code-plugin/README.md#policy-and-auditing) before
deployment: hooks and heuristic detection are not a complete security boundary.

`make quality` measures detection, default-threshold blocking, false positives,
and latency on a small synthetic labeled corpus. The corpus deliberately includes
known misses and benign false positives; its rates are regression signals, not
estimates of real-world protection. CI runs it along with the tests, a simulated
hook-protocol check, and the WebAssembly smoke test. Latency measures in-process
scanning only, not network requests, hook startup, or audit writes.

**Test pages:** `testpages/` has realistic examples of each attack, plus a
clean page that should score zero. Serve them with
`python3 -m http.server 8765` from the repo root and open
http://localhost:8765/testpages/.

**Live before-and-after demo:** `demo/demo.sh before` runs Claude Code (Haiku)
with Trip Wire off on a rigged documentation page, and `demo/demo.sh after`
runs the same task with it on. Run `demo/demo.sh check` first, and run
`demo/demo.sh` with no arguments to list every command. The demo page is served
from your own machine and every attacker address on it is an unresolvable
`.example` domain, but the Claude session itself runs on Anthropic's hosted
model, so the page content passes through it.

## Privacy and permissions

- **Extension:** reads only pages you explicitly ask it to scan (`activeTab`),
  and page content never leaves your browser.
- **Plugin:** never auto-approves a tool call. It either blocks a call or
  leaves the decision to your normal permission settings. What it tells Claude
  is only Trip Wire's own rule identifiers, never the hidden text itself.
  Optional audit logs omit raw input and content, but their fingerprints can
  still be sensitive and should be protected.

## Repository layout

| Path | Contents |
|---|---|
| `engine/` | Detection engine: instruction patterns, Unicode decoding, scoring |
| `extract/` | Raw-HTML extractor that works out hidden text without a browser |
| `cmd/trip-wire/` | CLI and the Claude Code hook |
| `cmd/wasm/` | WebAssembly bridge for the extension |
| `extension/` | Chrome extension (Manifest V3) and its icons |
| `assets/` | SVG sources for the logo and extension icons (`make icons` rebuilds the PNGs) |
| `claude-code-plugin/` | Claude Code plugin manifest, hooks, and launcher |
| `.claude-plugin/` | Marketplace file that lets Claude Code install the plugin |
| `testpages/` | Attack examples and a clean control page |
| `demo/` | Live before-and-after launcher and the demo script |

## Known limits

- Without a browser (CLI and plugin), text hidden by an external stylesheet
  looks visible. Agents read every word either way, so instruction detection
  still applies.
- The plugin scans WebFetch pages with its own request, so a server that shows
  different content to different clients could show Trip Wire a clean page.
  Strict policy blocks WebFetch instead.
- By default, the Read hook scans only agent instruction files. Strict policy
  also scans ordinary text reads, subject to the hook-protocol limits described
  in the [plugin guide](claude-code-plugin/README.md#limits).

## License and security

Trip Wire is MIT licensed; see [LICENSE](LICENSE). To report a vulnerability,
see [SECURITY.md](SECURITY.md).
