# Trip Wire for Claude Code

A Claude Code plugin that scans web content for hidden prompt injection before
Claude reads it. It uses the same Go engine as the Trip Wire Chrome extension.

| When | What Trip Wire does |
|---|---|
| Claude calls **WebFetch** on a dangerous page | Blocks the fetch and tells Claude why |
| Claude calls **WebFetch** on a suspicious page | Lets your normal permission flow run, with a warning attached for Claude |
| Any **Bash** command returns dangerous content | Withholds the output from Claude |
| A Bash command returns suspicious content | Passes it through with a warning attached for Claude |
| Trip Wire can't scan a page (network error, etc.) | Doesn't block; tells Claude the content is unverified |

Bash output is judged by content, not by which command produced it. A list of
"web" commands is easy to get around (`/usr/bin/curl`, wrappers, or a file
downloaded earlier and read with `cat`), so every command's output is scanned.
stdout and stderr are scanned separately, so curl's progress meter can't make
an HTML page look like plain text.

Messages to Claude contain only Trip Wire's own descriptions of what it found,
never the hidden text itself, so the warning can't carry the injection with it.
The plugin never auto-approves a tool call: it either blocks it or leaves the
decision to your normal permission settings.

Withholding Bash output works by replacing the tool result (`updatedToolOutput`)
with an object in Bash's own shape. A PostToolUse `decision: "block"` does
*not* withhold anything: verified live on Claude Code 2.1.285, the original
output still reached Claude. The WebFetch block uses a PreToolUse `deny`, also
verified live.

## Try it

```bash
make plugin                                 # from the repo root: builds bin/trip-wire into this folder
claude --plugin-dir ./claude-code-plugin    # load it for one session
```

Then, with the test pages served locally (`python3 -m http.server 8765` from the
repo root), ask Claude:

> Run `curl -s http://127.0.0.1:8765/testpages/02-job-applicant.html` and summarize the candidate.

Trip Wire withholds the output and Claude reports that the page hides
instructions aimed at AI agents. WebFetch can't reach localhost, so to see the
WebFetch block, point Claude at a public page.

## Limits

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
