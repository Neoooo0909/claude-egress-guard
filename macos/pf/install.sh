#!/bin/sh
# claude-egress-guard — macOS installer (run with sudo, from your own account).
#
#   sudo sh macos/pf/install.sh --mode anthropic-only [--proxy-url URL]        # safe with any proxy setup
#   sudo sh macos/pf/install.sh --mode full --proxy-url http://127.0.0.1:7890   # needs a root-owned proxy core
#
# Options:
#   --mode full|anthropic-only   which pf rule set to load (required)
#   --proxy-url URL              local proxy, e.g. http://127.0.0.1:7890. Required for full mode (used to
#                                check who owns the proxy core); also written to Claude Code managed settings
#   --no-proxy LIST              NO_PROXY for managed settings (default: localhost,127.0.0.1,::1)
#   --uid UID                    user whose direct traffic full mode restricts (default: $SUDO_UID)
#   --domestic FILE              domestic IPv4 list for full mode
#                                (default: ~/.config/claude-egress-guard/domestic-ipv4.txt of that user)
#   --no-apple                   full mode: do NOT allow direct traffic to Apple's 17.0.0.0/8
#   --force                      skip the "proxy core must not run as that user" safety checks
#   --no-blocklog                do not install the block log daemon (records what pf refused;
#                                view with ./macos/pf/blocked.py). Needs /usr/bin/python3 (Xcode CLT)
#
# Idempotent: re-running replaces the rules. Undo everything with: sudo sh macos/pf/uninstall.sh
set -eu

die() { echo "error: $*" >&2; exit 1; }
# launchctl bootout can return before the job has exited: wait (max ~5 s) until it is gone
wait_gone() { i=0; while launchctl print "system/$1" >/dev/null 2>&1 && [ $i -lt 20 ]; do sleep 0.25; i=$((i + 1)); done; }
[ "$(uname -s)" = Darwin ] || die "macOS only"
[ "$(id -u)" = 0 ] || die "run with sudo: sudo sh $0 $*"

SRC=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SRC/../.." && pwd)
DIR="/Library/Application Support/ClaudeEgressGuard"
ANCHOR="com.apple/250.ClaudeEgressGuard"
LABEL="io.github.claude-egress-guard.pf"
BL_LABEL="io.github.claude-egress-guard.blocklog"
MS_DIR="/Library/Application Support/ClaudeCode"
MS="$MS_DIR/managed-settings.json"

MODE=""; TUID="${SUDO_UID:-}"; DOMESTIC=""; EXTRA4=", 17.0.0.0/8"
PROXY_URL=""; NO_PROXY_LIST="localhost,127.0.0.1,::1"; FORCE=0; BLOCKLOG=1
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --uid) TUID="$2"; shift 2 ;;
    --domestic) DOMESTIC="$2"; shift 2 ;;
    --no-apple) EXTRA4=""; shift ;;
    --proxy-url) PROXY_URL="$2"; shift 2 ;;
    --no-proxy) NO_PROXY_LIST="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --no-blocklog) BLOCKLOG=0; shift ;;
    *) die "unknown option $1" ;;
  esac
done
case "$MODE" in full|anthropic-only) ;; *) die "--mode full|anthropic-only is required" ;; esac
case "$TUID" in ''|*[!0-9]*) die "--uid must be numeric (could not infer from SUDO_UID)" ;; esac
[ "$TUID" -ne 0 ] || die "refusing to restrict root (uid 0)"
TUSER=$(id -nu "$TUID") || die "no user with uid $TUID"
THOME=$(dscl . -read "/Users/$TUSER" NFSHomeDirectory | awk '{print $2}')
[ -n "$DOMESTIC" ] || DOMESTIC="$THOME/.config/claude-egress-guard/domestic-ipv4.txt"

# Values that end up inside JSON / pf files must be plain (no quotes, spaces, backslashes, '#').
if [ -n "$PROXY_URL" ]; then
  printf '%s' "$PROXY_URL" | grep -q -E '^https?://[A-Za-z0-9._-]+:[0-9]{1,5}/?$' \
    || die "--proxy-url must look like http://127.0.0.1:7890 (no credentials, no path)"
fi
printf '%s' "$NO_PROXY_LIST" | grep -q -E '^[A-Za-z0-9.,:*/_-]+$' || die "--no-proxy has unexpected characters"
NO_PROXY_LIST=$(printf '%s' "$NO_PROXY_LIST" | tr 'A-Z' 'a-z')
case ",$NO_PROXY_LIST," in *",*,"*) die "--no-proxy must not contain '*' (Claude Code would go direct)" ;; esac
case "$NO_PROXY_LIST" in *anthropic*|*claude*) die "--no-proxy must not contain Anthropic/Claude domains" ;; esac
# No entry may cover a domain of config/claude-domains.txt as a suffix (".com", ".datadoghq.com" …)
DOMAINS=$(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$ROOT/config/claude-domains.txt" | grep -v '^$')
set -f  # entries like "*.example.com" must not be expanded as file globs
for e in $(printf '%s' "$NO_PROXY_LIST" | tr ',' ' '); do
  e=${e#\*}; e=${e#.}; e=${e%:[0-9]*}
  [ -n "$e" ] || continue
  for d in $DOMAINS; do
    case "$d" in "$e"|*".$e") die "--no-proxy entry '$e' would send $d DIRECT" ;; esac
  done
done
set +f

# Anthropic ranges from config/anthropic-ranges.txt → "a, b, c"
RANGES=$(grep -v -E '^[[:space:]]*(#|$)' "$ROOT/config/anthropic-ranges.txt" | tr -d ' ' | paste -sd, - | sed 's/,/, /g')
[ -n "$RANGES" ] || die "config/anthropic-ranges.txt is empty"
printf '%s' "$RANGES" | grep -q -E '^[0-9a-fA-F.:/, ]+$' || die "config/anthropic-ranges.txt has unexpected characters"

if [ "$MODE" = full ]; then
  [ -s "$DOMESTIC" ] || die "missing $DOMESTIC — run (as $TUSER): python3 tools/gen_cn_ipv4.py"
  if [ "$FORCE" -ne 1 ]; then
    [ -n "$PROXY_URL" ] || die "full mode needs --proxy-url (to verify the proxy core does not run as $TUSER)"
    # 1) whoever LISTENS on the proxy port is the proxy core: it must not be the restricted user,
    #    otherwise its own upstream connections get blocked → total outage
    PORT=${PROXY_URL##*:}; PORT=${PORT%/}
    owner=$(lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -Fu 2>/dev/null | sed -n 's/^u//p' | head -1)
    [ -n "$owner" ] || die "nothing listens on port $PORT — start your proxy first (or pass --force)"
    [ "$owner" != "$TUID" ] || die "the proxy core listening on :$PORT runs as $TUSER — switch it to a root/service mode, or use --mode anthropic-only"
    # 2) VPN / packet-tunnel extensions running as the user (they listen on no port, so check 1
    #    cannot see them) — e.g. the App Store build of Tailscale (IPNExtension). GUI front-ends of
    #    proxy apps (e.g. "clash-verge") are fine: check 1 already verified the actual core.
    owned=$(ps -axo uid=,comm= | awk -v u="$TUID" '$1 == u { $1 = ""; sub(/^ +/, ""); print }' | grep -i -E \
      'IPNExtension|PacketTunnel|NetworkExtension' || true)
    if [ -n "$owned" ]; then
      echo "These VPN/network extensions run as $TUSER (uid $TUID):" >&2
      echo "$owned" | sed 's/^/   /' >&2
      die "full mode would cut their connections. Use builds whose extension runs as root (e.g. standalone Tailscale), use --mode anthropic-only, or --force if you are sure."
    fi
  fi
fi

# Render rules to a temp file and let pfctl parse them before touching anything
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
if [ "$MODE" = full ]; then
  cp "$DOMESTIC" "$TMP/domestic-ipv4.txt"
  sed -e "s#@ANTHROPIC_RANGES@#$RANGES#" -e "s#@UID@#$TUID#g" -e "s#@EXTRA_ALLOW4@#$EXTRA4#" \
      -e "s#@DOMESTIC_FILE@#$TMP/domestic-ipv4.txt#" "$SRC/rules.full.conf.tmpl" > "$TMP/check.conf"
  sed -e "s#@ANTHROPIC_RANGES@#$RANGES#" -e "s#@UID@#$TUID#g" -e "s#@EXTRA_ALLOW4@#$EXTRA4#" \
      -e "s#@DOMESTIC_FILE@#$DIR/domestic-ipv4.txt#" "$SRC/rules.full.conf.tmpl" > "$TMP/rules.conf"
else
  sed -e "s#@ANTHROPIC_RANGES@#$RANGES#" "$SRC/rules.anthropic-only.conf.tmpl" > "$TMP/rules.conf"
  cp "$TMP/rules.conf" "$TMP/check.conf"
fi
/sbin/pfctl -n -a "$ANCHOR" -f "$TMP/check.conf" >/dev/null 2>&1 || {
  /sbin/pfctl -n -a "$ANCHOR" -f "$TMP/check.conf" 2>&1 | grep -v -E 'Use of -f|present in the main|/etc/pf.conf' >&2
  die "pf rejected the rendered rules"; }
echo "[1/4] rules rendered and parsed ($MODE mode)"

# Install (root-owned, not writable by users: these files run as root)
mkdir -p "$DIR"; chown root:wheel "$DIR"; chmod 755 "$DIR"
install -m 644 -o root -g wheel "$TMP/rules.conf" "$DIR/rules.conf"
[ "$MODE" = full ] && install -m 644 -o root -g wheel "$TMP/domestic-ipv4.txt" "$DIR/domestic-ipv4.txt"
install -m 755 -o root -g wheel "$SRC/apply.sh" "$DIR/apply.sh"
install -m 644 -o root -g wheel "$SRC/$LABEL.plist" "/Library/LaunchDaemons/$LABEL.plist"
HAVE_PY=0
xcode-select -p >/dev/null 2>&1 && /usr/bin/python3 -I -c 'import json' >/dev/null 2>&1 && HAVE_PY=1
if [ "$BLOCKLOG" -eq 1 ] && [ "$HAVE_PY" -eq 0 ]; then
  echo "warning: /usr/bin/python3 unavailable (xcode-select --install) - block log NOT installed" >&2
  BLOCKLOG=0
fi
if [ "$BLOCKLOG" -eq 1 ]; then
  install -m 644 -o root -g wheel "$SRC/blocklog.py" "$DIR/blocklog.py"
  install -m 644 -o root -g wheel "$SRC/$BL_LABEL.plist" "/Library/LaunchDaemons/$BL_LABEL.plist"
fi
echo "[2/4] installed to $DIR$( [ "$BLOCKLOG" -eq 1 ] && echo ' (with block log)')"

# Claude Code managed settings: highest precedence; tools that rewrite ~/.claude/settings.json
# (provider switchers) cannot override them. Merge, never clobber. The ORIGINAL state is recorded
# once (first install only) so that uninstall restores exactly what was there before.
if [ -n "$PROXY_URL" ]; then
  mkdir -p "$MS_DIR"
  if [ ! -e "$DIR/managed-settings.created" ] && [ ! -e "$DIR/managed-settings.orig" ]; then
    if [ -e "$MS" ]; then cp -p "$MS" "$DIR/managed-settings.orig"; else touch "$DIR/managed-settings.created"; fi
  fi
  if xcode-select -p >/dev/null 2>&1 && /usr/bin/python3 -I -c 'import json' >/dev/null 2>&1; then
    /usr/bin/python3 -I - "$MS" "$PROXY_URL" "$NO_PROXY_LIST" <<'PY'
import json, os, sys
path, px, np = sys.argv[1:4]
data = json.load(open(path)) if os.path.exists(path) and os.path.getsize(path) else {}
data.setdefault("env", {}).update({
    "HTTP_PROXY": px, "HTTPS_PROXY": px, "http_proxy": px, "https_proxy": px,
    "NO_PROXY": np, "no_proxy": np, "NODE_USE_ENV_PROXY": "1"})
json.dump(data, open(path, "w"), indent=2)
PY
  elif [ ! -s "$MS" ]; then
    # values were validated above, so plain printf cannot produce invalid JSON
    printf '{\n  "env": {\n    "HTTP_PROXY": "%s",\n    "HTTPS_PROXY": "%s",\n    "http_proxy": "%s",\n    "https_proxy": "%s",\n    "NO_PROXY": "%s",\n    "no_proxy": "%s",\n    "NODE_USE_ENV_PROXY": "1"\n  }\n}\n' \
      "$PROXY_URL" "$PROXY_URL" "$PROXY_URL" "$PROXY_URL" "$NO_PROXY_LIST" "$NO_PROXY_LIST" > "$MS"
  else
    echo "warning: $MS exists and python3 is unavailable; managed settings NOT changed" >&2
  fi
  chown root:wheel "$MS"; chmod 644 "$MS"
  echo "[3/4] managed settings: $MS"
else
  echo "[3/4] managed settings skipped (no --proxy-url)"
fi

# Replace the rules right now (flush + load via apply.sh, which also enables pf), THEN (re)start
# the daemon — so a failing bootstrap cannot leave the anchor empty
launchctl bootout "system/$LABEL" 2>/dev/null || true
wait_gone "$LABEL"
/sbin/pfctl -a "$ANCHOR" -F rules 2>/dev/null || true
/sbin/pfctl -a "$ANCHOR" -F Tables 2>/dev/null || true
sh "$DIR/apply.sh"
launchctl bootstrap system "/Library/LaunchDaemons/$LABEL.plist" \
  || echo "warning: launchctl bootstrap failed — rules are loaded now but will not be re-applied after a reboot" >&2
# Block log daemon: (re)start it, or remove a previous one when --no-blocklog was given
launchctl bootout "system/$BL_LABEL" 2>/dev/null || true
wait_gone "$BL_LABEL"
if [ "$BLOCKLOG" -eq 1 ]; then
  launchctl bootstrap system "/Library/LaunchDaemons/$BL_LABEL.plist" \
    || echo "warning: could not start the block log daemon" >&2
else
  rm -f "/Library/LaunchDaemons/$BL_LABEL.plist" "$DIR/blocklog.py" "$DIR/blocklog.err" \
        "$DIR/blocked.jsonl" "$DIR/blocked.jsonl.1"
fi
echo "[4/4] active anchor rules:"
/sbin/pfctl -a "$ANCHOR" -sr 2>/dev/null | sed 's/^/   /'
/sbin/pfctl -s info 2>/dev/null | head -1
echo "check: sudo pfctl -a $ANCHOR -t ceg_anthropic -T test 160.79.104.10   (expect '1/1 addresses match')"
[ "$BLOCKLOG" -eq 1 ] && echo "what was blocked: $SRC/blocked.py   (log: $DIR/blocked.jsonl)"
echo "done. Undo: sudo sh $SRC/uninstall.sh"
