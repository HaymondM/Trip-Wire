#!/bin/sh
# Runs the Trip Wire Claude Code hook. Prefers the binary built into this
# plugin by `make plugin`, then a trip-wire on PATH.
#
# If neither exists it exits 1, which Claude Code treats as a non-blocking
# error. It must never exit 2: on PreToolUse that would block every WebFetch.

root="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

if [ -x "$root/bin/trip-wire" ]; then
  exec "$root/bin/trip-wire" hook claude-code
fi
if command -v trip-wire >/dev/null 2>&1; then
  exec trip-wire hook claude-code
fi

echo "Trip Wire is installed but its binary is missing, so web content is NOT being scanned. Run 'make plugin' in the Trip Wire repo, or put trip-wire on your PATH." >&2
exit 1
