#!/bin/sh
# claude-egress-guard — capture N seconds of blocked packets as a pcap (run with sudo).
# For everyday use the block log daemon is simpler: ./macos/pf/blocked.py. This script is for raw
# packet detail: it makes sure the block rules carry "log", captures pflog0, reloads the installed
# rules (also on Ctrl-C), and hands the capture file back to you.
#
#   sudo sh macos/pf/diag_pflog.sh ./ceg.pcap 60
#   tcpdump -n -e -r ./ceg.pcap | head
#
# Notes from practice:
#  * macOS fills the pflog header's uid but NOT the pid (always 100000), so blocked packets
#    cannot be mapped to a process — use destination IP/port and TCP flags instead
#    (e.g. SYN-ACK from a local listening port = replies to inbound connections).
#  * tcpdump on pflog0 ignores SIGTERM; we stop it with INT and then KILL.
set -e
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
ANCHOR="com.apple/250.ClaudeEgressGuard"
DIR="/Library/Application Support/ClaudeEgressGuard"
OUT="${1:?usage: sudo sh $0 <out.pcap> [seconds]}"
SECS="${2:-60}"
case "$SECS" in ''|*[!0-9]*) echo "seconds must be a number" >&2; exit 1 ;; esac
[ -f "$DIR/rules.conf" ] || { echo "not installed ($DIR/rules.conf missing)" >&2; exit 1; }

TMP=$(mktemp)
TP=""
# Always put the original rules back and stop tcpdump, even when interrupted
restore() {
  [ -n "$TP" ] && { kill -INT "$TP" 2>/dev/null || true; sleep 1; kill -9 "$TP" 2>/dev/null || true; }
  /sbin/pfctl -a "$ANCHOR" -f "$DIR/rules.conf" 2>/dev/null || true
  rm -f "$TMP"
}
trap restore EXIT INT TERM

# rules installed by older versions have no "log" yet; current ones already do (no-op then)
sed 's/^block return out quick/block return out log quick/' "$DIR/rules.conf" > "$TMP"
ifconfig pflog0 >/dev/null 2>&1 || ifconfig pflog0 create
/sbin/pfctl -a "$ANCHOR" -f "$TMP" 2>/dev/null
/usr/sbin/tcpdump -i pflog0 -n -s 200 -U -w "$OUT" >/dev/null 2>&1 &
TP=$!
sleep "$SECS"
restore
TP=""
trap - EXIT INT TERM
[ -n "${SUDO_UID:-}" ] && chown "$SUDO_UID" "$OUT"
chmod 644 "$OUT"
echo "captured $(stat -f %z "$OUT") bytes to $OUT; rules restored."
