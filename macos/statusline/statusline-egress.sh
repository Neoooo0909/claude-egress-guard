#!/bin/bash
# claude-egress-guard — example Claude Code status line (macOS / Linux).
#
# Use alone:   ~/.claude/settings.json → "statusLine": {"type": "command",
#                "command": "~/claude-egress-guard/macos/statusline/statusline-egress.sh"}
# Or append the guard's segment to the output of your existing status line tool, e.g.
#   my-statusline-tool "$@" <<<"$input"; python3 "$GUARD" status --ansi
#
# It prints one line such as
#   exit 203.0.113.10 US | anomalies today 0 | host blocked 12        (yellow)
#   ! exit == real IP 198.51.100.7 | anomalies today 1 (exit 1)       (black on yellow)
# The guard itself never blocks on the network: probes and the macOS sampler run in the
# background and the status line only reads their cached results.

cat >/dev/null   # Claude Code passes session JSON on stdin; this example does not need it
GUARD="${CEG_GUARD:-$HOME/claude-egress-guard/guard/egress_guard.py}"
exec /usr/bin/env python3 "$GUARD" status --ansi
