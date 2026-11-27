#!/bin/sh
# Runs the Trip Wire Claude Code hook. Prefers the binary built into this
# plugin by `make plugin`, then a trip-wire on PATH.
#
# With a configured policy, a missing binary must block PreToolUse rather
# than silently bypassing an administrator's policy.

root="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

if [ -x "$root/bin/trip-wire" ]; then
  exec "$root/bin/trip-wire" hook claude-code
fi
if command -v trip-wire >/dev/null 2>&1; then
  exec trip-wire hook claude-code
fi

echo "Trip Wire is installed but its binary is missing, so web content is NOT being scanned. Run 'make plugin' in the Trip Wire repo, or put trip-wire on your PATH." >&2
if [ -n "${TRIP_WIRE_POLICY:-}" ]; then
  exit 2
fi
exit 1
