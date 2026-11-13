#!/usr/bin/python3
"""claude-egress-guard — pf block log daemon: records every connection the kill switch refused,
so "what was blocked?" can be answered later (see macos/pf/blocked.py).

Runs as root under LaunchDaemon io.github.claude-egress-guard.blocklog (KeepAlive); both tcpdumps
drop to user "nobody" right after opening their device. Sources:
  1. tcpdump -i pflog0 -e        the block rules carry "log", so the kernel copies every refused
                                 packet to pflog0 → time, destination, protocol, interface. Only
                                 lines of OUR anchor count (other pf users may log blocks too)
  2. tcpdump -i pktap,all -k     DNS queries/answers → IP→domain map; and the RST that pf returns
                                 to the local program ("block return") — pktap tags inbound
                                 packets with the receiving process → which program (TCP)
  3. lsof -i UDP:<port>          process owning the local port right after a block (UDP/QUIC
                                 sockets stay open while retrying, so this usually hits)
pktap does NOT tap pflog0 itself (no process info there) and pflog's own pid field is never filled
on macOS — hence the RST and lsof detours. Process attribution is best effort.

Output: /Library/Application Support/ClaudeEgressGuard/blocked.jsonl (0640 root:admin, rotated to
.1 above 5 MB). One JSON object per line:
  ts/last  first/last packet time    n       packets in this record
  kind     anthropic = Anthropic's address space (any user, incl. root)
           direct    = the restricted user went direct to a non-allowed address (full mode)
  proto, dst, port, iface
  domain   from DNS answers captured on the wire (domain_src "dns"); null when none was seen
  proc     "name:pid" (proc_src "rst" or "lsof"); exe = executable path from proc_pidpath
           (never argv: arguments may hold secrets, and argv[0] can be rewritten by the process)
Merging: a new (kind, proto, dst, port) is written 3 s after its first packet (time to attribute
it), then at most once per 60 s while packets keep coming. Beyond PENDING_MAX distinct targets,
new ones are merged into dst "*" so a flood cannot exhaust memory.

The daemon sends nothing itself (no PTR lookups either: they would hand every blocked foreign
address to the system resolver in clear text).
"""
import ctypes
import ipaddress
import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time

DIR = "/Library/Application Support/ClaudeEgressGuard"
ANCHOR = "com.apple/250.ClaudeEgressGuard"
# pflog stores the anchor's last path component truncated to 15 characters ("250.ClaudeEgres");
# a rule field looks like "0.250.ClaudeEgres.8/0"
ANCHOR_TAG = "." + ANCHOR.rsplit("/", 1)[1][:15] + "."
LOG_PATH = os.path.join(DIR, "blocked.jsonl")
RULES_PATH = os.path.join(DIR, "rules.conf")
LOG_MAX_BYTES = 5 * 1024 * 1024
FIRST_DELAY_SEC = 3.0          # wait this long after the first packet before writing (attribution)
MERGE_WINDOW_SEC = 60.0        # then merge repeats into one record per window
MAP_TTL_SEC = 3600             # IP→domain entries expire after an hour
MAP_MAX = 50000                # and the map never grows beyond this
PENDING_MAX = 5000             # distinct targets aggregated at once; more are merged into dst "*"
TCPDUMP = "/usr/sbin/tcpdump"
LSOF = "/usr/sbin/lsof"
DEFAULT_ANTHROPIC = ["160.79.104.0/23", "2607:6bc0::/48", "2607:6bc0:11::/48"]

# pflog line (tcpdump -e): 2026-01-02 03:04:05.123456 rule 0.250.ClaudeEgres.8/0(match): block out on en0: 192.168.1.20.50127 > 140.82.112.3.443: Flags [S], ...
PFLOG_RE = re.compile(r"^(\S+ \S+) rule (\S+)\(match\): block out on (\S+): (\S+?)\.(\d+) > (\S+?)\.(\d+): (.*)$")
# pktap line (tcpdump -k): 2026-01-02 03:04:05.123456 (en0, proc curl:123, svc BE, in, so) IP 1.2.3.4.443 > 192.168.1.20.50127: Flags [R.], ...
PKTAP_RE = re.compile(r"^\S+ \S+ \((.*?)\) IP6? (\S+?)\.(\d+) > (\S+?)\.(\d+): (.*)$")
DNS_QUERY_RE = re.compile(r"^(\d+)\S* (?:\[[^\]]*\] )*\w+\? (\S+?)\.? \(")
DNS_TXID_RE = re.compile(r"^(\d+)")
DNS_ADDR_RE = re.compile(r"(?:^|[ ,])(?:A|AAAA) ([0-9A-Fa-f:.]+)")
PKTAP_FILTER = ("udp port 53 or (tcp[tcpflags] & tcp-rst != 0)"
                " or (ip6 and tcp and ip6[53] & 0x04 != 0)")   # tcp[] is IPv4-only in libpcap

STOP = threading.Event()
READER_DIED = threading.Event()  # a tcpdump exited unexpectedly → exit non-zero, launchd restarts us
LOCK = threading.Lock()
pending = {}       # (kind, proto, dst, port) -> record being aggregated
ip_names = {}      # ip -> (domain or None, source, monotonic time)
dns_txids = {}     # (txid, client ip, client port, server ip) -> (query name, monotonic time)
rst_procs = {}     # (local_port, remote_ip, remote_port) -> (proc, monotonic time)
port_procs = {}    # (proto, local_port) -> (proc, monotonic time)
lsof_queue = queue.Queue(maxsize=64)
PROCS = []
try:
    _LIBPROC = ctypes.CDLL("/usr/lib/libproc.dylib")
    _LIBPROC.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
except (OSError, AttributeError):
    _LIBPROC = None


def log_err(msg):
    """Diagnostics to stderr (the LaunchDaemon redirects it to blocklog.err)."""
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, file=sys.stderr, flush=True)


def load_anthropic_nets(path=RULES_PATH):
    """Read the <ceg_anthropic> table from the installed rules; built-in default if unreadable."""
    ranges = list(DEFAULT_ANTHROPIC)
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"\s*table\s+<ceg_anthropic>[^{]*\{([^}]*)\}", line)
                if m:
                    ranges = [x.strip() for x in m.group(1).split(",") if x.strip()]
                    break
    except OSError:
        pass
    nets = []
    for x in ranges:
        try:
            nets.append(ipaddress.ip_network(x, strict=False))
        except ValueError:
            log_err(f"ignoring invalid range {x!r}")
    return nets


ANTHROPIC_NETS = load_anthropic_nets()


def is_anthropic(ip):
    """True when ip lies in Anthropic's address space."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in ANTHROPIC_NETS)


def parse_meta(meta):
    """Parse pktap metadata "en0, proc curl:123, eproc X:456, svc BE, in, so" → (process, direction).

    eproc (the effective process a socket was delegated for) wins over proc.
    """
    proc = eproc = direction = None
    for part in (p.strip() for p in meta.split(",")):
        if part.startswith("eproc ") and not part[6:].startswith(":"):
            eproc = part[6:]
        elif part.startswith("proc ") and not part[5:].startswith(":"):
            proc = part[5:]                 # ":0" = no process (e.g. the copy pf sends out)
        elif part in ("in", "out"):
            direction = part
    return eproc or proc, direction


def handle_pflog_line(line):
    """One pflog line of OUR anchor: aggregate "block out" packets by (kind, proto, dst, port)."""
    m = PFLOG_RE.match(line)
    if not m or ANCHOR_TAG not in m.group(2):
        return
    ts, _rule, iface, _src, sport, dst, dport, rest = m.groups()
    proto = "tcp" if rest.startswith("Flags [") else "udp"
    kind = "anthropic" if is_anthropic(dst) else "direct"
    key = (kind, proto, dst, int(dport))
    now = time.monotonic()
    with LOCK:
        if key not in pending and len(pending) >= PENDING_MAX:
            key = (kind, proto, "*", 0)         # flood: merge further targets into one record
        e = pending.get(key)
        if e is None:
            e = pending[key] = {"ts": ts[:19], "last": ts[:19], "n": 0, "iface": iface,
                                "lports": [], "due": now + FIRST_DELAY_SEC}
        e["n"] += 1
        e["last"] = ts[:19]
        if e["ts"] is None:             # a merge window just restarted: this is its first packet
            e["ts"] = ts[:19]
        if sport not in e["lports"] and len(e["lports"]) < 20:
            e["lports"].append(sport)
    if proto == "udp":                          # a refused TCP socket is gone already (RST covers TCP)
        try:
            lsof_queue.put_nowait((proto, sport))
        except queue.Full:
            pass


def handle_pktap_line(line):
    """One pktap line: DNS query/answer → IP→domain map; inbound RST → (local port, remote) → process."""
    m = PKTAP_RE.match(line)
    if not m:
        return
    meta, src, sport, dst, dport, rest = m.groups()
    now = time.monotonic()
    if rest.startswith("Flags [R"):                     # the RST pf sent back: src = blocked remote
        proc, direction = parse_meta(meta)
        if proc and direction == "in":
            with LOCK:
                rst_procs[(dport, src, sport)] = (proc, now)
        return
    if rest.startswith("Flags ["):                      # other TCP (e.g. DNS over TCP): ignore
        return
    if dport == "53":                                   # query: remember (txid, client, server) → name
        q = DNS_QUERY_RE.match(rest)
        if q:
            with LOCK:
                dns_txids[(q.group(1), src, sport, dst)] = (q.group(2).lower(), now)
        return
    if sport == "53":                                   # answer to a query we saw: map its addresses
        t = DNS_TXID_RE.match(rest)
        if not t:
            return
        with LOCK:
            hit = dns_txids.get((t.group(1), dst, dport, src))
        if not hit:                                     # unsolicited/unmatched answers are not trusted
            return
        with LOCK:
            for ip in DNS_ADDR_RE.findall(rest):
                try:
                    ip = str(ipaddress.ip_address(ip.rstrip(".")))
                except ValueError:
                    continue
                ip_names[ip] = (hit[0], "dns", now)


def reader(cmd, handler, name):
    """Run one tcpdump and feed its lines to handler; if it dies, stop the daemon (launchd restarts it)."""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, errors="replace", bufsize=1)
    except OSError as e:
        log_err(f"{name}: cannot start: {e}")
        READER_DIED.set()
        STOP.set()
        return
    PROCS.append(p)
    for line in p.stdout:
        if STOP.is_set():
            break
        try:
            handler(line.rstrip("\n"))
        except Exception as e:  # a bad line must not kill the reader (and is not logged: it may hold IPs)
            log_err(f"{name}: parse error {type(e).__name__}")
    if not STOP.is_set():
        log_err(f"{name}: exited unexpectedly (rc={p.poll()}); stopping so launchd restarts us")
        READER_DIED.set()
        STOP.set()


def lsof_worker():
    """Resolve (proto, local port) → process with lsof; each port at most once per 10 s, ≤ 2 lsof/s."""
    recent = {}
    while not STOP.is_set():
        try:
            proto, lport = lsof_queue.get(timeout=1)
        except queue.Empty:
            continue
        now = time.monotonic()
        if now - recent.get((proto, lport), -99) < 10:
            continue
        recent[(proto, lport)] = now
        if len(recent) > 2000:
            recent = {k: v for k, v in recent.items() if now - v < 10}
        started = time.monotonic()
        try:
            out = subprocess.run([LSOF, "-nP", f"-i{proto.upper()}:{lport}", "-F", "pc"],
                                 capture_output=True, text=True, timeout=3).stdout
        except (OSError, subprocess.TimeoutExpired):
            out = ""
        finally:
            spent = time.monotonic() - started  # rate limit: an lsof costs ~0.1 s of CPU
            if spent < 0.5:
                time.sleep(0.5 - spent)
        pid = cmd = None
        for row in out.splitlines():
            if row.startswith("p") and pid is None:
                pid = row[1:]
            elif row.startswith("c") and pid is not None and cmd is None:
                cmd = row[1:]
        if pid and cmd:
            with LOCK:
                port_procs[(proto, lport)] = (f"{cmd}:{pid}", now)


def executable(proc):
    """"name:pid" → executable path of a still-running process via proc_pidpath (not argv, which
    the process can rewrite and which may contain arguments); None when unknown."""
    if _LIBPROC is None:
        return None
    try:
        pid = int(proc.rsplit(":", 1)[1])
        buf = ctypes.create_string_buffer(4096)
        n = _LIBPROC.proc_pidpath(pid, buf, 4096)
        return buf.value.decode("utf-8", "replace") if n > 0 else None
    except (IndexError, ValueError, OSError):
        return None


def resolve(key, e):
    """Complete one record: domain and process attribution."""
    kind, proto, dst, port = key
    with LOCK:
        hit = ip_names.get(dst)
        proc = proc_src = None
        if proto == "tcp":
            for lp in e["lports"]:
                r = rst_procs.get((lp, dst, str(port)))
                if r:
                    proc, proc_src = r[0], "rst"
                    break
        if not proc:
            for lp in e["lports"]:
                r = port_procs.get((proto, lp))
                if r:
                    proc, proc_src = r[0], "lsof"
                    break
    domain, domain_src = (hit[0], hit[1]) if hit else (None, None)
    rec = {"ts": e["ts"], "last": e["last"], "n": e["n"], "kind": kind, "proto": proto,
           "dst": dst, "port": port, "domain": domain, "domain_src": domain_src,
           "proc": proc, "proc_src": proc_src, "iface": e["iface"]}
    if proc:
        exe = executable(proc)
        if exe:
            rec["exe"] = exe
    return rec


def write_records(recs, path=None):
    """Append JSON lines (0640 root:admin: destinations reveal activity); rotate to .1 above the limit."""
    if not recs:
        return
    path = path or LOG_PATH
    try:
        if os.path.exists(path) and os.path.getsize(path) > LOG_MAX_BYTES:
            os.replace(path, path + ".1")
        new = not os.path.exists(path)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)  # never world-readable
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            if new:
                try:
                    os.fchown(fd, 0, 80)   # group "admin": the user running blocked.py can read
                except OSError:
                    pass
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    except OSError as e:
        log_err(f"cannot write log: {e}")


def flush_due(force=False):
    """Write records whose time has come (3 s after the first packet, then every 60 s); drop idle keys."""
    now = time.monotonic()
    todo = []
    with LOCK:
        for key, e in list(pending.items()):
            if not force and e["due"] > now:
                continue
            if e["n"] == 0:
                del pending[key]
                continue
            todo.append((key, dict(e, lports=list(e["lports"]))))
            e.update(n=0, due=now + MERGE_WINDOW_SEC, ts=None, lports=e["lports"][-5:])
    write_records([resolve(key, e) for key, e in todo])


def prune_maps():
    """Expire DNS/RST/port maps to bound memory."""
    now = time.monotonic()
    with LOCK:
        for d, ttl in ((dns_txids, 60), (rst_procs, 120), (port_procs, 120), (ip_names, MAP_TTL_SEC)):
            for k in [k for k, v in d.items() if now - v[-1] > ttl]:
                del d[k]
        if len(ip_names) > MAP_MAX:
            for k in list(ip_names)[: len(ip_names) - MAP_MAX]:
                del ip_names[k]


def shutdown(*_):
    """TERM/INT: stop reading; main() then stops the tcpdumps."""
    STOP.set()


def main():
    """Start both tcpdump readers and the lsof worker; flush aggregated records twice a second."""
    if subprocess.run(["/sbin/ifconfig", "pflog0"], capture_output=True).returncode != 0:
        subprocess.run(["/sbin/ifconfig", "pflog0", "create"], capture_output=True)
    try:
        with open(RULES_PATH, encoding="utf-8") as f:
            if not re.search(r"^block\b.*\blog\b", f.read(), re.M):
                log_err("warning: the installed block rules have no 'log' keyword; nothing will reach pflog0")
    except OSError:
        pass
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    threads = [
        threading.Thread(target=reader, daemon=True, name="pflog", args=(
            # -e is required: without it tcpdump omits the "rule …: block out on en0:" header.
            # -Z nobody: parse packets without root (privileges are dropped after the device opens)
            [TCPDUMP, "-Z", "nobody", "-i", "pflog0", "-n", "-e", "-l", "-tttt", "-s", "256"],
            handle_pflog_line, "pflog")),
        threading.Thread(target=reader, daemon=True, name="pktap", args=(
            [TCPDUMP, "-Z", "nobody", "-i", "pktap,all", "-n", "-l", "-k", "-tttt", "-s", "2048",
             PKTAP_FILTER], handle_pktap_line, "pktap")),
        threading.Thread(target=lsof_worker, daemon=True, name="lsof"),
    ]
    for t in threads:
        t.start()
    log_err(f"started; Anthropic ranges {[str(n) for n in ANTHROPIC_NETS]}")
    last_prune = time.monotonic()
    while not STOP.wait(0.5):
        flush_due()
        if time.monotonic() - last_prune > 60:
            prune_maps()
            last_prune = time.monotonic()
    flush_due(force=True)
    for p in PROCS:   # tcpdump on pflog0 ignores TERM while idle; output is line-buffered → just kill
        try:
            p.kill()
        except Exception:
            pass
    sys.stderr.flush()
    os._exit(1 if READER_DIED.is_set() else 0)   # do not wait for blocked reader threads


if __name__ == "__main__":
    main()
