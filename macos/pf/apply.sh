#!/bin/sh
# claude-egress-guard — idempotent pf loader (installed copy runs as root).
# Started by LaunchDaemon io.github.claude-egress-guard.pf at boot and every 60 s:
# re-loads the anchor if the system (or another app) reloaded pf and dropped it,
# and exports block counters for the status line.

ANCHOR="com.apple/250.ClaudeEgressGuard"
DIR="/Library/Application Support/ClaudeEgressGuard"
PFCTL=/sbin/pfctl

# Log to the unified log:  log show --predicate 'process == "logger"' --last 1h
log_msg() {
  /usr/bin/logger -t claude-egress-guard "$1"
}

# 1) our anchor is only evaluated through the "com.apple/*" hook of the main ruleset.
#    Load /etc/pf.conf only when the main ruleset is EMPTY (early boot); if another tool installed
#    its own main ruleset, never overwrite it — just log that our anchor is not active.
main_rules=$($PFCTL -sr 2>/dev/null)
if ! printf '%s\n' "$main_rules" | grep -q '^anchor "com.apple/\*"'; then
  if [ -z "$(printf '%s' "$main_rules" | tr -d '[:space:]')" ]; then
    $PFCTL -f /etc/pf.conf >/dev/null 2>&1 && log_msg "loaded /etc/pf.conf (main ruleset was empty)"
  else
    log_msg "WARNING: main pf ruleset has no com.apple/* hook (replaced by another tool); anchor $ANCHOR is NOT evaluated"
  fi
fi
# (the status line turns this into an alert via "anchor_active" in stats.json, see step 4)

# 2) (re)load our anchor when its rules or its Anthropic table are missing
if ! $PFCTL -a "$ANCHOR" -sr 2>/dev/null | grep -q 'ceg_anthropic' \
   || [ "$($PFCTL -a "$ANCHOR" -t ceg_anthropic -T show 2>/dev/null | wc -l | tr -d ' ')" -eq 0 ]; then
  if out=$($PFCTL -a "$ANCHOR" -f "$DIR/rules.conf" 2>&1); then
    log_msg "loaded anchor $ANCHOR"
  else
    log_msg "failed to load anchor: $out"
  fi
fi

# 3) enable pf with a reference token (-E) when disabled; keep tokens for uninstall
if ! $PFCTL -s info 2>/dev/null | grep -q 'Status: Enabled'; then
  token=$($PFCTL -E 2>&1 | awk '/Token/ {print $3}')
  [ -n "$token" ] && echo "$token" >> "$DIR/tokens"
  log_msg "enabled pf (token=$token)"
fi

# 4) export counters (stats.json, world-readable). pf counters reset when rules reload, so keep
#    "last raw value, running total" per counter and only ever add.
rules_v=$($PFCTL -a "$ANCHOR" -vsr 2>/dev/null)

# Sum "Packets:" of block rules; with $1 set, only block rules whose text contains $1
sum_blocked() {
  printf '%s\n' "$rules_v" | awk -v pat="$1" '
    /^block/ { in_block = (pat == "" || index($0, pat) > 0); next }
    /^pass/  { in_block = 0; next }
    in_block && /Packets:/ { for (i = 1; i <= NF; i++) if ($i == "Packets:") sum += $(i + 1); in_block = 0 }
    END { print sum + 0 }'
}

# Turn a raw counter into a running total: $1 = state file name, $2 = current raw value
accumulate() {
  last=0; total=0
  [ -f "$DIR/$1" ] && read -r last total < "$DIR/$1"
  if [ "$2" -ge "${last:-0}" ]; then
    total=$(( ${total:-0} + $2 - ${last:-0} ))
  else
    total=$(( ${total:-0} + $2 ))
  fi
  echo "$2 $total" > "$DIR/$1"
  echo "$total"
}

blocked_total=$(accumulate blocked.state "$(sum_blocked "")")
anthropic_total=$(accumulate anthropic.state "$(sum_blocked "ceg_anthropic")")

# Is the kill switch really in force? pf enabled + main ruleset hooks com.apple/* + our anchor
# has its rules + the Anthropic table is not empty. Exported so the status line can alert.
anchor_active=false
if $PFCTL -s info 2>/dev/null | grep -q 'Status: Enabled' \
   && $PFCTL -sr 2>/dev/null | grep -q '^anchor "com.apple/\*"' \
   && printf '%s\n' "$rules_v" | grep -q 'ceg_anthropic' \
   && [ "$($PFCTL -a "$ANCHOR" -t ceg_anthropic -T show 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ]; then
  anchor_active=true
fi
printf '{"blocked_total": %s, "anthropic_total": %s, "anchor_active": %s, "updated_at": %s}\n' \
  "$blocked_total" "$anthropic_total" "$anchor_active" "$(date +%s)" > "$DIR/stats.json.tmp" \
  && chmod 644 "$DIR/stats.json.tmp" && mv "$DIR/stats.json.tmp" "$DIR/stats.json"
