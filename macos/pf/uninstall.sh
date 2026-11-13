#!/bin/sh
# claude-egress-guard — macOS uninstaller (run with sudo).
# Stops the daemon, clears the pf anchor, releases our pf enable tokens and puts the Claude Code
# managed settings back exactly as they were before the FIRST install.
set -u
[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo sh $0" >&2; exit 1; }

DIR="/Library/Application Support/ClaudeEgressGuard"
ANCHOR="com.apple/250.ClaudeEgressGuard"
LABEL="io.github.claude-egress-guard.pf"
MS="/Library/Application Support/ClaudeCode/managed-settings.json"

# Stop the daemon BEFORE flushing, otherwise its next run would load the rules again
launchctl bootout "system/$LABEL" 2>/dev/null || true
/sbin/pfctl -a "$ANCHOR" -F rules 2>/dev/null || true
/sbin/pfctl -a "$ANCHOR" -F Tables 2>/dev/null || true

# Release the pf references we took (pf stays enabled if another program still holds one)
if [ -f "$DIR/tokens" ]; then
  while read -r t; do [ -n "$t" ] && /sbin/pfctl -X "$t" 2>/dev/null; done < "$DIR/tokens"
fi

# Managed settings: remove if install.sh created the file, restore the pre-install original otherwise
if [ -f "$DIR/managed-settings.created" ]; then
  rm -f "$MS"
  echo "removed $MS (it did not exist before install)"
elif [ -f "$DIR/managed-settings.orig" ]; then
  cp -p "$DIR/managed-settings.orig" "$MS"
  echo "restored $MS to its pre-install content"
fi

rm -f "/Library/LaunchDaemons/$LABEL.plist"
rm -rf "$DIR"
echo "uninstalled: daemon stopped, anchor $ANCHOR cleared."
