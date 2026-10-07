# Security policy

Trip Wire is a security tool, so reports about it are taken seriously. It's a
hackathon project maintained by one person, so responses are best effort and
there's no formal timeline.

## Reporting a vulnerability

Please report privately through GitHub: open the repository's **Security** tab
and choose **Report a vulnerability**. Please don't open a public issue for
anything in the list below until it's fixed.

Include what you found, steps to reproduce it, and the version or commit you
tested.

## What to report privately

Anything that lets a web page, or whoever controls its content, attack the
person or agent *using* Trip Wire:

- **Browser extension:** running script in the side panel or the extension's
  context, escaping the page callouts' isolation, or reading pages the user
  didn't ask it to scan.
- **Claude Code plugin and CLI:** getting a dangerous page or command output
  through unscanned, getting the hook to approve a tool call it should leave to
  the user, or making Trip Wire repeat a page's hidden text back to the model.
- **The plugin's pre-fetch of WebFetch URLs:** reaching private or internal
  addresses, following redirects it shouldn't, or sending credentials.

## What to report publicly

**Detection gaps** are expected in a heuristic tool. If you find a hidden
instruction or command that Trip Wire misses, or a legitimate page it flags,
please open a normal issue with a minimal example page. Those reports help.

## Supported versions

Only the latest release and `main` are supported.

## Scope

Please test only against pages and systems you own or have permission to test.
The pages in `testpages/` are harmless examples: their attacker addresses are
unresolvable `.example` domains.
