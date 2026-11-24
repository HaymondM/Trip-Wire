# Trip Wire for Claude Code

A Claude Code plugin that scans web content for hidden prompt injection before
Claude reads it. It uses the same Go engine as the Trip Wire Chrome extension.

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

Messages to Claude contain only Trip Wire's own descriptions of what it found,
never the hidden text itself, so the warning can't carry the injection with it.
The plugin never auto-approves a tool call: it either blocks it or leaves the
decision to your normal permission settings.

Withholding Bash output works by replacing the tool result (`updatedToolOutput`)
with an object in Bash's own shape. A PostToolUse `decision: "block"` does
*not* withhold anything: verified live on Claude Code 2.1.285, the original
output still reached Claude. The WebFetch block uses a PreToolUse `deny`, also
verified live.

MCP results and Read output are withheld the same way, in each tool's own
shape (MCP content blocks, and Read's `file.content`). MCP replacements also
set `updatedMCPToolOutput`. Both were verified live on Claude Code 2.1.285
with a headless session: Claude received only Trip Wire's notice, and with the
plugin disabled the same file and MCP result reached Claude in full. The
warning is also attached as context, so if a later Claude Code version ignores
the replacement, Claude is still told not to follow the content.

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
straight from GitHub, where build output isn't committed), the hooks don't
block anything. Claude Code shows a non-blocking error saying web content isn't
being scanned. A `trip-wire` binary on your PATH also works.

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
  model, so scanning afterward is too late. That request sends no cookies or
  credentials, and it's held to WebFetch's own limits: public addresses only
  (checked on the IP actually connected to), no proxy, and no following
  redirects to another host. Local and private URLs aren't pre-fetched at all.
- Because of that separate request, a server that serves different content to
  different clients could show Trip Wire a clean page.
- Without a browser, text hidden by an external stylesheet looks visible. That
  matters less for agents, which read every word either way.
