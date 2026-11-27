# Trip Wire for Claude Code

A Claude Code plugin that scans web content for hidden prompt injection before
Claude reads it. It uses the same Go engine as the Trip Wire Chrome extension.

Default behavior:

| When | What Trip Wire does |
|---|---|
| Claude calls **WebFetch** on a dangerous page | Blocks the fetch and tells Claude why |
| Claude calls **WebFetch** on a suspicious page | Lets your normal permission flow run, with a warning attached for Claude |
| Any **Bash** command returns dangerous content | Withholds the output from Claude |
| A Bash command returns suspicious content | Passes it through with a warning attached for Claude |
| Any **MCP tool** (`mcp__*`) returns dangerous content | Withholds the result from Claude and attaches a warning |
| Claude **Reads** an agent instruction file (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `SKILL.md`, `.cursor/rules/*`, `.claude/commands/*`, …) with dangerous content | Withholds the file's content and attaches a warning |
| An MCP result or agent instruction file is suspicious | Passes it through with a warning attached for Claude |
| Trip Wire can't scan a page (network error, etc.) | Doesn't block; tells Claude the content is unverified |

Bash output is judged by content, not by which command produced it. A list of
"web" commands is easy to get around (`/usr/bin/curl`, wrappers, or a file
downloaded earlier and read with `cat`), so every command's output is scanned.
stdout and stderr are scanned separately, so curl's progress meter can't make
an HTML page look like plain text.

MCP results are scanned the same way, whatever the server: tickets, docs, chat
messages and web pages all come back through MCP tools. Read is scanned only
for agent instruction files, the files agents treat as standing orders rather
than data. Scanning every file would flag ordinary code (Trip Wire's own
detection patterns, for one).

Output that looks like source code (a `cat`, `grep` or `git diff` of code) is
scanned with its string literals blanked: test fixtures and detection patterns
are data, not instructions. Comments and docstrings are still scanned as
written, since a planted comment is how an injection hides in a repo, and
invisible or bidi characters inside literals still count. Text with HTML tags
outside string literals is treated as a page, never as code.

Agent instruction files exist to talk to an AI, so in them, plain-sight wording
that addresses an AI or gives it a role ("If you are an AI agent working
here…") isn't flagged. Hidden text, HTML comments, invisible characters,
"ignore previous instructions" wording, exfiltration and risky commands still
are.

Messages to Claude contain only Trip Wire's rule IDs and severity, never the
hidden text itself, so the warning can't carry the injection with it.
The plugin never auto-approves a tool call: it either blocks it or leaves the
decision to your normal permission settings.

Withholding Bash output works by replacing the tool result (`updatedToolOutput`)
with an object in Bash's own shape. A PostToolUse `decision: "block"` does
*not* withhold anything: verified live on Claude Code 2.1.285, the original
output still reached Claude. The WebFetch block uses a PreToolUse `deny`, also
verified live.

MCP results and Read output are withheld the same way, in each tool's own
shape (MCP content blocks, and Read's `file.content`). MCP replacements also
set `updatedMCPToolOutput`. Earlier versions were verified live on Claude Code
2.1.285; the automated protocol test exercises recorded shapes and simulates
applying replacements, but does **not** verify behavior in a live Claude
session. The warning is also attached as context, so if a later Claude Code
version ignores a replacement, Claude is still told not to follow the content.
Verify the installed plugin and your target Claude Code version before relying
on withholding.

## Install

From the repo root (needs Go and the `claude` CLI):

```bash
make install-plugin
```

This builds the binary and installs the plugin for **every** Claude Code
session: the terminal and the desktop app's Code tab. Start a new session to
pick it up. Run `make install-plugin` again after any code change: Claude Code
caches installed plugins by version number, so `claude plugin update` won't
pick up a rebuilt binary, but a reinstall does.

To remove it:

```bash
make uninstall-plugin
```

To try it in a single session without installing anything:

```bash
make plugin && claude --plugin-dir ./claude-code-plugin
```

If the plugin is installed but its binary is missing (for example, installed
straight from GitHub, where build output isn't committed), an unconfigured
hook reports a non-blocking error. If `TRIP_WIRE_POLICY` is set, the launcher
instead returns a blocking error for PreToolUse. A `trip-wire` binary on your
PATH also works.

## Policy and auditing

Without a policy, the plugin warns on `suspicious`, blocks `dangerous`, and
scans only agent instruction files on Read. To deploy shared settings, put a
JSON policy at an absolute, administrator-controlled path outside untrusted
repositories and set `TRIP_WIRE_POLICY` for Claude Code's environment:

```json
{
  "version": 1,
  "strict": true,
  "warn_on": "suspicious",
  "block_on": "dangerous",
  "audit": {
    "path": "/var/log/trip-wire/audit.jsonl",
    "include_clean": false
  },
  "exceptions": []
}
```

```bash
export TRIP_WIRE_POLICY=/etc/trip-wire/policy.json
```

Create the audit directory with appropriate permissions before starting
Claude Code. The policy must be a regular file, and the audit path must not
be a symlink or other non-regular file. The hook reads the policy for each
invocation. Supported thresholds are `suspicious`, `dangerous`, and `never`;
`block_on: "never"` is not allowed in strict mode. Blocking at `suspicious`
catches more attacks but also blocks more benign material. An invalid or
unreadable configured policy denies supported PreToolUse calls rather than
falling back to defaults.

Strict mode:

- Denies **every WebFetch**, without making a separate request: a server can
  change content between a pre-scan and the fetch that reaches the model.
- Scans ordinary text Read results as well as instruction files, Bash output,
  and MCP results. It attempts to withhold unscannable or oversized results
  and results whose required audit event cannot be written.
- Cannot guarantee withholding when the host ignores replacement output, the
  hook fails or times out, or the result has an unsupported shape. For an
  unsupported shape it warns that the result may still be visible and records
  it as unverified. A failed or ignored hook may produce no warning at all.
  Strict mode cannot intercept startup instruction files.

The policy applies only to the Claude Code hook, not the extension or CLI
scans. `scan-agent-files` should still be run before opening an untrusted
repository. An administrator must protect the policy, the environment that
points to it, and the plugin installation; this local configuration is not
tamper-resistant centralized enforcement.

### Audit events

When `audit` is present, Trip Wire appends JSON lines to its absolute `path`.
Each versioned event records a timestamp, hook event, tool name, action, reason,
the policy file's SHA-256 fingerprint, and, when available, verdict, score,
rule IDs and input/content fingerprints. Raw commands, URLs, file contents and
finding excerpts are not logged. Fingerprints
can still reveal predictable inputs through guessing, so treat audit logs as
sensitive. Newly created logs use mode `0600` subject to umask; protect existing
files and their directory, and arrange rotation and forwarding separately.

By default all non-clean findings and unverified results are logged, even if
policy permits them; set `include_clean` to `true` to record clean scans too.
Actions `deny_requested` and `replace_requested` describe what the hook asked
the host to do, not confirmation that the host applied it. If a configured
audit write fails, the hook reports the error. Strict mode also denies the
pre-tool call or attempts to withhold a supported post-tool result; without
strict mode it warns instead.

### Scoped exceptions

An exception downgrades a matching detection from block to warning; the
content then passes through. It requires an expiry, reason, exact event and
tool, and **both** fingerprints from the corresponding audit event:

```json
{
  "id": "reviewed-false-positive",
  "event": "PostToolUse",
  "tool": "Bash",
  "input_sha256": "<input_sha256 from the audit event>",
  "content_sha256": "<content_sha256 from the audit event>",
  "expires_at": "<RFC 3339 expiry, for example 2027-01-01T00:00:00Z>",
  "reason": "Reviewed false positive; tracking ticket ABC-123"
}
```

Replace the placeholders before adding this object to the policy's
`exceptions` array. The ID must be unique and use letters, digits, `.`, `_`
or `-`. Fingerprints cover the complete JSON tool input and response with
object keys normalized; even a metadata change invalidates the exception.
For non-strict WebFetch, the content fingerprint covers the pre-fetched
bytes instead. Strict WebFetch is always denied and cannot be excepted.
Expired exceptions automatically stop matching, and use of an exception is
recorded in the audit log. A non-strict WebFetch exception cannot eliminate
the separate-request gap.

## Try it

With the test pages served locally (`python3 -m http.server 8765` from the
repo root), ask Claude:

> Run `curl -s http://127.0.0.1:8765/testpages/02-job-applicant.html` and summarize the candidate.

Trip Wire withholds the output and Claude reports that the page hides
instructions aimed at AI agents. WebFetch can't reach localhost, so to see the
WebFetch block, point Claude at a public page.

## Limits

- **Claude Code loads the project's own `CLAUDE.md` at startup, without a
  Read**, so the hook never sees it. Before opening a repo you didn't write in
  an agent, run `trip-wire scan-agent-files <repo>`.

- **WebFetch is scanned with a separate request, made before you approve the
  fetch.** It has to happen first: WebFetch hands the raw page to a summarizing
  model, so scanning afterward is too late. The request sends no cookies or
  authorization headers and rejects URLs with embedded user credentials, but
  the URL including its query string is sent to the destination before your
  approval. It is held to WebFetch's own limits: public addresses only
  (checked on the IP actually connected to), no proxy, and no following
  redirects to another host. Local and private URLs aren't pre-fetched at all.
- Because of that separate request, a server that serves different content to
  different clients could show Trip Wire a clean page.
- Without a browser, text hidden by an external stylesheet looks visible. That
  matters less for agents, which read every word either way.
- Detection is heuristic and misses some attacks. A clean verdict is not proof
  that content is safe; `make quality` reports known misses and false positives
  in a synthetic corpus.
- The automated hook-protocol test uses a simulated consumer, not a live
  Claude Code session. PostToolUse replacement depends on the host's protocol;
  unsupported response shapes, hook failures and timeouts cannot be made
  fail-closed by this plugin alone. Bash commands have already run before
  their output is scanned.
