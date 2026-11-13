#!/usr/bin/env python3
"""claude-egress-guard — keep every Claude-bound byte on your proxy exit, and fail closed.

Modes (pure standard library, Python 3.8+):
  gate                 Claude Code ``UserPromptSubmit`` hook (macOS / Linux / Windows).
                       Before each prompt, confirm that the exit IP Anthropic sees is an
                       expected one. Anything uncertain → exit code 2 → the prompt is blocked.
  probe <cache.json>   Measure the exit IP on the Anthropic route (through the proxy) and
                       your real IP (through a domestic echo that your rules send DIRECT).
  status [--json|--ansi]  One-line status text for a status line; spawns probe/daemon in the
                       background when their results are stale. Never blocks on the network.
  sample               macOS: one scan of all Claude Code process trees for connections that
                       bypass the proxy.
  daemon               macOS: resident sampler (every 0.5 s, single instance, exits when no
                       Claude Code process has been seen for 60 s).

Safety rule: without a proxy variable this script never contacts a foreign host — it only
asks the domestic echo service for your real IP.

Configuration (environment variables, all optional):
  CEG_CONFIG_DIR   ~/.config/claude-egress-guard  expected-egress.txt, domestic-ipv4.txt, gate-off
  CEG_CACHE_DIR    ~/.cache/claude-egress-guard   probe caches, daily stats, event log
  CEG_TRACE_URL    https://api.anthropic.com/cdn-cgi/trace   (same host as the API → same proxy rule)
  CEG_REAL_IP_URL  http://ip.3322.net   echo service that your proxy rules route DIRECT
  CEG_GATE_FRESH   60     seconds a cached probe result stays good enough for the gate
  CEG_PF_STATS     /Library/Application Support/ClaudeEgressGuard/stats.json   (macOS pf counters)
"""

import bisect
import ctypes
import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

try:  # POSIX only; Windows runs gate/probe/status, which do not need file locks
    import fcntl
except ImportError:
    fcntl = None

HOME = os.path.expanduser("~")
CONFIG_DIR = os.environ.get("CEG_CONFIG_DIR") or os.path.join(HOME, ".config", "claude-egress-guard")
CACHE_DIR = os.environ.get("CEG_CACHE_DIR") or os.path.join(HOME, ".cache", "claude-egress-guard")
TRACE_URL = os.environ.get("CEG_TRACE_URL", "https://api.anthropic.com/cdn-cgi/trace")
REAL_IP_URL = os.environ.get("CEG_REAL_IP_URL", "http://ip.3322.net")
def _int_env(name, default):
    """Integer from the environment; a malformed value falls back to the default instead of
    crashing at import time (a crash would exit 1, which Claude Code treats as "allow")."""
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


GATE_FRESH_SEC = _int_env("CEG_GATE_FRESH", 60)
GATE_DEADLINE_SEC = 15  # whole-gate budget; keep below the hook "timeout" (20 s in the examples)
PF_STATS_PATH = os.environ.get("CEG_PF_STATS", "/Library/Application Support/ClaudeEgressGuard/stats.json")

EXPECTED_PATH = os.path.join(CONFIG_DIR, "expected-egress.txt")
DOMESTIC_PATH = os.path.join(CONFIG_DIR, "domestic-ipv4.txt")
GATE_OFF_FLAG = os.path.join(CONFIG_DIR, "gate-off")
STATS_PATH = os.path.join(CACHE_DIR, "stats.json")
STATS_LOCK = os.path.join(CACHE_DIR, "stats.lock")
EVENTS_PATH = os.path.join(CACHE_DIR, "events.jsonl")

HTTP_TIMEOUT_SEC = 10
GATE_TIMEOUT_SEC = 5
PROBE_EVERY_SEC = 120
PROBE_STALE_SEC = 600
DAEMON_STALE_SEC = 20
EVENTS_MAX_BYTES = 5 * 1024 * 1024
SEEN_MAX = 5000
USER_AGENT = "claude-egress-guard/1.0"

OFFICIAL_SUFFIXES = ("anthropic.com", "claude.ai", "claude.com")
# Loopback, LAN, CGNAT/Tailscale, link-local, multicast: not an "exit"
LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32", "0.0.0.0/8",
    "::1/128", "fe80::/10", "fc00::/7", "ff00::/8", "::/128")]


# ---------------------------------------------------------------- small helpers

def load_json(path):
    """Read a JSON object; return {} when the file is missing or corrupt."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_json(path, data):
    """Atomically write JSON (temp file + rename), creating the parent directory if needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = "%s.tmp.%d" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)


def today():
    """Local date string; daily counters reset when it changes."""
    return time.strftime("%Y-%m-%d")


def update_stats(mutate):
    """Read-modify-write the daily stats under a file lock (when available); reset on a new day."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(STATS_LOCK, "a") as lock:
        if fcntl:
            fcntl.flock(lock, fcntl.LOCK_EX)
        stats = load_json(STATS_PATH)
        if stats.get("day") != today():
            stats = {"day": today(), "counts": {"exit": 0, "direct": 0, "blocked": 0, "anthropic": 0},
                     "seen": []}
        mutate(stats)
        save_json(STATS_PATH, stats)


def log_event(event):
    """Append one JSON line to the event log, rotating it once it grows past 5 MB."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    try:
        if os.path.getsize(EVENTS_PATH) > EVENTS_MAX_BYTES:
            os.replace(EVENTS_PATH, EVENTS_PATH + ".1")
    except OSError:
        pass
    record = {"time": time.strftime("%Y-%m-%d %H:%M:%S")}
    record.update(event)
    with open(EVENTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def is_local(ip):
    """True for loopback / LAN / CGNAT / link-local / multicast addresses (never an exit)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in LOCAL_NETS)


_DOMESTIC = None


def ip_is_domestic(ip):
    """Is an IPv4 address inside domestic-ipv4.txt (binary search)? None if unknown/no list."""
    global _DOMESTIC
    if _DOMESTIC is None:
        starts, ends = [], []
        try:
            with open(DOMESTIC_PATH, encoding="utf-8") as f:  # header comments may be non-ASCII
                for line in f:
                    if not line[:1].isdigit():
                        continue
                    try:  # one malformed line must not truncate the rest of the list
                        net = ipaddress.ip_network(line.split("#", 1)[0].strip(), strict=False)
                    except ValueError:
                        continue
                    starts.append(int(net.network_address))
                    ends.append(int(net.broadcast_address))
        except OSError:
            pass
        order = sorted(range(len(starts)), key=starts.__getitem__)
        _DOMESTIC = ([starts[i] for i in order], [ends[i] for i in order])
    starts, ends = _DOMESTIC
    if not starts:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    value = int(addr)
    i = bisect.bisect_right(starts, value) - 1
    return i >= 0 and value <= ends[i]


# ---------------------------------------------------------------- network helpers

def proxy_url():
    """The HTTPS proxy Claude Code would use (inherited environment), normalised to have a
    scheme ("127.0.0.1:7890" → "http://127.0.0.1:7890")."""
    url = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or "").strip()
    if url and "://" not in url:
        url = "http://" + url
    return url


def redact(url):
    """Proxy URL without credentials, for messages and cache files."""
    parsed = urllib.parse.urlparse(url)
    if parsed.username or parsed.password:
        netloc = parsed.hostname + (":%d" % parsed.port if parsed.port else "")
        return parsed._replace(netloc=netloc).geturl()
    return url


def proxy_alive(url):
    """Can we open a TCP connection to the proxy within 0.5 s?"""
    parsed = urllib.parse.urlparse(url)
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=0.5):
            return True
    except (OSError, TypeError, ValueError):
        return False


def no_proxy_bypasses(host):
    """Would NO_PROXY / no_proxy make a client send `host` DIRECT instead of via the proxy?

    Deliberately stricter than urllib (which only honours a value that is exactly "*"):
    many runtimes treat a "*" ENTRY anywhere in the list as "bypass everything", and accept
    ".example.com" / "*.example.com" suffix forms. Both variable spellings are checked.
    """
    host = host.lower().rstrip(".")
    for var in ("NO_PROXY", "no_proxy"):
        for entry in os.environ.get(var, "").replace(" ", ",").split(","):
            entry = entry.strip().lower()
            if not entry:
                continue
            if entry == "*":
                return True
            entry = entry.split(":", 1)[0] if entry.count(":") == 1 else entry  # drop :port
            entry = entry.lstrip("*").lstrip(".")
            if entry and (host == entry or host.endswith("." + entry)):
                return True
    return False


class _ForcedProxyHandler(urllib.request.ProxyHandler):
    """ProxyHandler that ignores NO_PROXY: the guard's own measurements must always go through
    the proxy, otherwise "measuring the exit" would itself expose the real IP."""

    def proxy_open(self, req, proxy, type):
        """Same as the stdlib implementation minus the proxy_bypass() check."""
        orig_type = req.type
        proxy_type, user, password, hostport = urllib.request._parse_proxy(proxy)
        if proxy_type is None:
            proxy_type = orig_type
        if user and password:
            import base64
            creds = base64.b64encode(("%s:%s" % (urllib.parse.unquote(user),
                                                 urllib.parse.unquote(password))).encode()).decode("ascii")
            req.add_header("Proxy-authorization", "Basic " + creds)
        req.set_proxy(urllib.parse.unquote(hostport), proxy_type)
        if orig_type == proxy_type or orig_type == "https":
            return None
        return self.parent.open(req, timeout=req.timeout)


def make_opener(url):
    """Opener that ALWAYS uses the given proxy (NO_PROXY ignored); with no proxy, explicitly
    disables every proxy (including the macOS/Windows system proxy) — Claude Code also ignores
    the system proxy, so this measures exactly the path it would take."""
    if url:
        return urllib.request.build_opener(_ForcedProxyHandler({"http": url, "https": url}))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get_text(opener, url, attempts=2, timeout=HTTP_TIMEOUT_SEC):
    """GET a small text body; retry once on network errors (proxies drop the odd TLS handshake)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for i in range(attempts):
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.read(4096).decode("utf-8", "replace")
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, OSError):
            if i == attempts - 1:
                raise
            time.sleep(1)
    return ""


def valid_ip(text):
    """Return `text` as a normalised IP string, or None when it is not an IP address
    (an echo service or captive portal answering with HTML must not count as a reading)."""
    try:
        return str(ipaddress.ip_address((text or "").strip()))
    except ValueError:
        return None


def parse_trace(text):
    """Parse Cloudflare's /cdn-cgi/trace ``key=value`` lines → (ip, loc)."""
    kv = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    return valid_ip(kv.get("ip")), kv.get("loc")


def load_expected_ips():
    """Expected exit IPs (one per line, ``#`` comments). Empty set only when the file does not
    exist; an existing but unreadable file raises (the gate then fails closed instead of
    silently downgrading to the weaker "exit != real IP" check)."""
    if not os.path.exists(EXPECTED_PATH):
        return set()
    with open(EXPECTED_PATH, encoding="utf-8") as f:
        return {line.split("#", 1)[0].strip() for line in f} - {""}


def current_api_host():
    """Model API host Claude Code talks to: ANTHROPIC_BASE_URL's host, or the official API."""
    base = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    host = urllib.parse.urlparse(base).hostname if base else None
    return (host or "api.anthropic.com").lower()


def cache_path(proxy, host):
    """Probe cache file for this (proxy, API host) pair, so sessions with different providers
    do not overwrite each other's results."""
    key = hashlib.md5(("%s|%s" % (proxy, host)).encode()).hexdigest()[:12]
    return os.path.join(CACHE_DIR, "egress_%s.json" % key)


# ---------------------------------------------------------------- probe

def probe(path):
    """Measure both routes once and store the result; record an "exit" anomaly when the IP that
    Anthropic sees is your real IP or not in expected-egress.txt."""
    state = load_json(path)
    proxy = proxy_url()
    host = current_api_host()
    state.update(attempt_at=int(time.time()), proxy=redact(proxy), api_host=host)
    save_json(path, state)  # store the attempt time first so callers do not respawn us

    if proxy and not proxy_alive(proxy):
        state.update(error="proxy_down", anthropic_ip=None, anthropic_loc=None)
        save_json(path, state)
        return

    errors = []
    opener = make_opener(proxy)
    if proxy:  # without a proxy, touching Anthropic would itself expose the real IP
        try:
            ip, loc = parse_trace(get_text(opener, TRACE_URL))
            state.update(anthropic_ip=ip, anthropic_loc=loc)
        except (urllib.error.URLError, OSError, ValueError) as e:
            state.update(anthropic_ip=None, anthropic_loc=None)
            errors.append("anthropic: %s" % type(e).__name__)
    else:
        state.update(anthropic_ip=None, anthropic_loc=None)

    try:
        state["real_ip"] = valid_ip(get_text(opener, REAL_IP_URL))
    except (urllib.error.URLError, OSError, ValueError) as e:
        state["real_ip"] = None  # never keep a stale reading: the real IP may have changed
        errors.append("real_ip: %s" % type(e).__name__)

    if state.get("anthropic_ip") or state.get("real_ip"):
        state["fetched_at"] = int(time.time())
    state["error"] = "; ".join(errors) or None
    save_json(path, state)

    aip, rip = state.get("anthropic_ip"), state.get("real_ip")
    expected = load_expected_ips()
    if aip and (aip == rip or (expected and aip not in expected)):
        log_event({"type": "exit", "counted": True, "ip": aip, "loc": state.get("anthropic_loc"),
                   "reason": "equals real IP" if aip == rip else "not in expected list",
                   "api_host": host})

        def bump(stats):
            stats["counts"]["exit"] = stats["counts"].get("exit", 0) + 1
        update_stats(bump)


# ---------------------------------------------------------------- gate (UserPromptSubmit hook)

ANTHROPIC_PROBE_HOSTS = ("api.anthropic.com", "claude.ai", "platform.claude.com")
DOMAINS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "config", "claude-domains.txt")


def guarded_hosts():
    """Hosts that must never be exempted by NO_PROXY: the Anthropic endpoints plus every suffix
    in config/claude-domains.txt (telemetry, auth, billing) when the file is available."""
    hosts = list(ANTHROPIC_PROBE_HOSTS) + ["mcp-proxy.anthropic.com"]
    try:
        with open(DOMAINS_FILE, encoding="utf-8") as f:
            for line in f:
                d = line.split("#", 1)[0].strip().lower().lstrip(".")
                if d:
                    hosts += [d, "x." + d]
    except OSError:
        pass
    return hosts


def _run_with_deadline(fn, seconds):
    """Run fn() in a daemon thread and return its result, or None if it raised or did not finish
    within `seconds` (urllib timeouts are per socket operation, not per request)."""
    box = {}

    def target():
        try:
            box["result"] = fn()
        except Exception:  # any failure = "could not measure" → the caller fails closed
            pass
    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(max(0.1, seconds))
    return box.get("result")


def gate_deny(message):
    """Block the prompt: log it, explain on stderr, exit 2 (Claude Code refuses to send)."""
    try:
        log_event({"type": "gate_block", "counted": False, "reason": message})
    except OSError:
        pass
    sys.stderr.write("[claude-egress-guard] %s\n(temporarily disable: create %s)\n" % (message, GATE_OFF_FLAG))
    sys.exit(2)


def gate():
    """Let the prompt through only when the Anthropic-route exit is verifiably correct.

    Blocks when: no proxy variable / proxy port dead / exit cannot be measured /
    exit == real IP / exit not in the expected list / neither check is possible.
    Uses a cached probe younger than CEG_GATE_FRESH seconds, otherwise measures (≈1 s).
    Third-party providers (ANTHROPIC_BASE_URL) are checked the same way: the prompt may go
    to them, but Claude Code's background telemetry still goes to Anthropic.
    """
    if os.path.exists(GATE_OFF_FLAG):
        sys.exit(0)
    started = time.time()
    proxy = proxy_url()
    if not proxy:
        gate_deny("Claude Code has no proxy variable; this prompt would leave from your real IP. Blocked.")
    for guarded in guarded_hosts():
        if no_proxy_bypasses(guarded):
            gate_deny("NO_PROXY/no_proxy matches %s, so Claude-related traffic would go DIRECT. "
                      "Remove that entry (and any '*') from NO_PROXY. Blocked." % guarded)
    if not proxy_alive(proxy):
        gate_deny("Proxy %s is not reachable (proxy app stopped or restarting). Blocked." % redact(proxy))

    host = current_api_host()
    path = cache_path(proxy, host)
    state = load_json(path)
    now = int(time.time())
    if not state.get("anthropic_ip") or now - state.get("fetched_at", 0) > GATE_FRESH_SEC:
        opener = make_opener(proxy)
        trace = _run_with_deadline(lambda: parse_trace(get_text(opener, TRACE_URL, timeout=GATE_TIMEOUT_SEC)),
                                   GATE_DEADLINE_SEC - 3)
        ip, loc = trace if trace else (None, None)
        if not ip:
            gate_deny("Cannot measure the exit IP through the proxy (exit node down / too slow). Blocked; retry later.")
        # refresh the real IP together with the exit (a cached one may be from another network)
        remaining = GATE_DEADLINE_SEC - (time.time() - started)
        real = _run_with_deadline(lambda: get_text(opener, REAL_IP_URL, attempts=1,
                                                   timeout=GATE_TIMEOUT_SEC), max(1.0, remaining))
        state["real_ip"] = valid_ip(real)
        state.update(proxy=redact(proxy), api_host=host, anthropic_ip=ip, anthropic_loc=loc, fetched_at=now)
        save_json(path, state)

    aip, loc, rip = state["anthropic_ip"], state.get("anthropic_loc") or "", state.get("real_ip")
    expected = load_expected_ips()
    if rip and aip == rip:
        gate_deny("Anthropic would see your REAL IP %s (proxy in direct/global mode?). Blocked." % aip)
    if expected and aip not in expected:
        gate_deny("Exit %s %s is not in %s. Blocked." % (aip, loc, EXPECTED_PATH))
    if not expected and not rip:
        gate_deny("No expected-egress.txt and no real-IP reading: cannot judge the exit. Blocked.")
    if not expected and ipaddress.ip_address(aip).version != ipaddress.ip_address(rip).version:
        gate_deny("Exit %s and real IP %s are different address families, so \"exit != real IP\" proves "
                  "nothing. List your exit in %s. Blocked." % (aip, rip, EXPECTED_PATH))
    sys.exit(0)


# ---------------------------------------------------------------- status (for status lines)

def _spawn(args, lock_dir):
    """Start a detached background worker unless one was started < 2 min ago (lock dir age)."""
    try:
        if os.path.isdir(lock_dir) and time.time() - os.path.getmtime(lock_dir) > 120:
            os.rmdir(lock_dir)
        os.makedirs(CACHE_DIR, exist_ok=True)
        os.mkdir(lock_dir)
    except OSError:
        return
    kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if os.name == "nt":
        kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen([sys.executable, os.path.abspath(__file__)] + args, **kwargs)


def status_text():
    """Compute (alert, text) for a status line and kick off stale background work."""
    proxy, host = proxy_url(), current_api_host()
    now = time.time()
    if not proxy:
        pstate = "none"
    elif proxy_alive(proxy):
        pstate = "up"
    else:
        pstate = "down"

    path = cache_path(proxy, host)
    c = load_json(path)
    if pstate != "down" and now - c.get("attempt_at", 0) > PROBE_EVERY_SEC:
        _spawn(["probe", path], path + ".lock")
    s = load_json(STATS_PATH)
    if sys.platform == "darwin" and now - s.get("sampled_at", 0) > DAEMON_STALE_SEC:
        _spawn(["daemon"], os.path.join(CACHE_DIR, "daemon.spawn"))

    fresh = now - c.get("fetched_at", 0) < PROBE_STALE_SEC
    aip, loc, rip = c.get("anthropic_ip") or "", c.get("anthropic_loc") or "", c.get("real_ip") or ""
    official = any(host == x or host.endswith("." + x) for x in OFFICIAL_SUFFIXES)
    n = s.get("counts", {}) if s.get("day") == today() else {}
    total = n.get("direct", 0) + n.get("exit", 0) + n.get("anthropic", 0)
    parts = [label + str(n.get(k, 0)) for k, label in
             (("anthropic", "anthropic-blocked "), ("direct", "direct "), ("exit", "exit "))] if total else []

    bypass = proxy and any(no_proxy_bypasses(h) for h in guarded_hosts())
    pfd = load_json(PF_STATS_PATH) if sys.platform == "darwin" else {}
    pf_off = pfd.get("anchor_active") is False and now - pfd.get("updated_at", 0) < 300
    if bypass:
        base = "! NO_PROXY bypasses Claude hosts - would go direct"
    elif pf_off:
        base = "! pf kill switch inactive (pf off or main ruleset replaced)"
    elif pstate == "down":
        base = "! proxy down - requests fail"
    elif pstate == "none":
        base = ("! no proxy - direct " + rip) if (fresh and rip) else "! no proxy - would go direct"
    elif not fresh:
        base = "! exit node down" if "anthropic" in (c.get("error") or "") else "~ checking exit..."
    elif not aip:
        base = "! exit node down"
    elif aip == rip:
        base = "! exit == real IP " + aip
    elif not official:
        base = "exit %s %s (provider %s)" % (aip, loc, host)
    else:
        base = "exit %s %s" % (aip, loc)
    alert = base.startswith("!") or total > 0
    text = base + (" | anomalies today %d (%s)" % (total, ", ".join(p for p in parts if not p.endswith(" 0")))
                   if total else " | anomalies today 0")
    if s.get("pf"):
        text += " | host blocked %d" % n.get("blocked", 0)
    return alert, text


def status(as_json=False, ansi=False):
    """Print the status line text: plain, JSON with an "alert" flag, or ANSI-coloured
    (yellow text normally; bold black-on-yellow when something is wrong)."""
    alert, text = status_text()
    if as_json:
        print(json.dumps({"alert": alert, "text": text}, ensure_ascii=False))
    elif ansi:
        style = "\033[1;30;43m" if alert else "\033[33m"
        print("%s %s \033[0m" % (style, text))
    else:
        print(text)


# ---------------------------------------------------------------- macOS sampler

_LIBPROC = ctypes.CDLL("/usr/lib/libproc.dylib") if sys.platform == "darwin" else None
_PID_BUF = (ctypes.c_int * 4096)()
_NAME_BUF = ctypes.create_string_buffer(256)


def is_claude_main(comm):
    """Claude Code's main process: comm "Claude"/"claude" or an executable under claude/versions."""
    comm = comm.strip()
    return comm in ("Claude", "claude") or "/.local/share/claude/versions/" in comm


def find_claude_roots():
    """PIDs of every Claude Code main process (ps, ~25 ms; refreshed every few seconds)."""
    out = subprocess.run(["/bin/ps", "-axo", "pid=,comm="], capture_output=True, text=True, timeout=10).stdout
    roots = set()
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and is_claude_main(parts[1]):
            roots.add(int(parts[0]))
    return roots


def expand_tree(roots):
    """All descendants of the given PIDs via libproc (microseconds) → {pid: name}."""
    tree, stack = {}, list(roots)
    while stack:
        pid = stack.pop()
        if pid in tree:
            continue
        name = "?"
        if _LIBPROC.proc_name(pid, _NAME_BUF, ctypes.sizeof(_NAME_BUF)) > 0:
            name = _NAME_BUF.value.decode("utf-8", "replace")
        tree[pid] = name
        n = _LIBPROC.proc_listchildpids(pid, _PID_BUF, ctypes.sizeof(_PID_BUF))
        stack.extend(_PID_BUF[i] for i in range(max(n, 0)) if _PID_BUF[i] > 0)
    return tree


def split_endpoint(text):
    """Split lsof's ``ip:port`` / ``[v6]:port`` into (ip, port)."""
    if text.startswith("["):
        end = text.index("]")
        return text[1:end], text[end + 2:]
    ip, _, port = text.rpartition(":")
    return ip, port


def list_connections(pids):
    """Connected sockets of the given PIDs via lsof → [(pid, local, remote_ip, remote_port, proto)]."""
    if not pids:
        return []
    proc = subprocess.run(["/usr/sbin/lsof", "-a", "-p", ",".join(map(str, sorted(pids))),
                           "-i", "-n", "-P", "-F", "pPn"], capture_output=True, text=True, timeout=20)
    conns, pid, proto = [], None, None
    for line in proc.stdout.splitlines():
        tag, val = line[:1], line[1:]
        if tag == "p":
            pid = int(val)
        elif tag == "P":
            proto = val
        elif tag == "n" and "->" in val:
            local, remote = val.split("->", 1)
            rip, rport = split_endpoint(remote)
            conns.append((pid, local, rip, rport, proto))
    return conns


def scan(tree, roots):
    """Classify non-local connections of the process trees.

    Counted: a direct connection to a non-domestic IP (real IP shown abroad), or ANY direct
    connection from Claude Code's main process (it should only ever talk to the proxy).
    Logged only: a child process going DIRECT to a domestic IP (by design in many setups).
    """
    findings = []
    for pid, local, rip, rport, proto in list_connections(set(tree)):
        if is_local(rip):
            continue
        if ip_is_domestic(rip) is not True:
            kind, counted = "direct_foreign", True
        elif pid in roots:
            kind, counted = "direct_main", True
        else:
            kind, counted = "direct_domestic_child", False
        key = "%s|%s|%s:%s|%s" % (pid, local, rip, rport, proto)
        findings.append((key, {"type": kind, "counted": counted, "pid": pid, "cmd": tree.get(pid),
                               "remote": "%s:%s" % (rip, rport), "proto": proto}))
    return findings


def read_pf_totals():
    """Cumulative pf block counters exported by the macOS daemon; None when pf is not installed."""
    data = load_json(PF_STATS_PATH)
    if not isinstance(data.get("blocked_total"), (int, float)):
        return None
    return {"blocked": int(data["blocked_total"]), "anthropic": int(data.get("anthropic_total") or 0)}


def record(findings, pf, mode):
    """Log/count new findings and convert pf totals into today's numbers. Returns new keys."""
    recorded = []

    def apply(stats):
        seen = set(stats.get("seen", []))
        for key, event in findings:
            if key in seen:
                continue
            seen.add(key)
            recorded.append(key)
            log_event(event)
            if event["counted"]:
                stats["counts"]["direct"] = stats["counts"].get("direct", 0) + 1
        stats["seen"] = list(seen)[-SEEN_MAX:]
        stats["pf"] = pf is not None
        for name, total in (pf or {}).items():
            base = stats.get(name + "_base")
            if base is None or total < base:
                stats[name + "_base"] = base = total
            today_n, before = total - base, stats["counts"].get(name, 0)
            if name == "anthropic" and today_n > before:
                log_event({"type": "anthropic_blocked", "counted": True, "delta": today_n - before})
            stats["counts"][name] = today_n
        stats["sampled_at"] = int(time.time())
        stats["sampler"] = mode
    update_stats(apply)
    return recorded


def sample():
    """One-shot scan (manual troubleshooting)."""
    if _LIBPROC is None:
        sys.exit("sample/daemon are macOS-only")
    roots = find_claude_roots()
    record(scan(expand_tree(roots), roots), read_pf_totals(), "once")


def daemon():
    """Resident sampler: every 0.5 s re-walk the Claude Code process trees (so short-lived child
    commands are covered), single instance via flock, exit after 60 s without Claude Code."""
    if fcntl is None or _LIBPROC is None:
        return
    os.makedirs(CACHE_DIR, exist_ok=True)
    lock = open(os.path.join(CACHE_DIR, "daemon.flock"), "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return
    roots, roots_at, idle_since, last_beat = set(), 0.0, None, 0.0
    seen_local, seen_day = set(), today()
    while True:
        now = time.time()
        if now - roots_at >= 5:
            roots, roots_at = find_claude_roots(), now
            if roots:
                idle_since = None
            else:
                idle_since = idle_since or now
                if now - idle_since >= 60:
                    return
        if today() != seen_day:
            seen_local, seen_day = set(), today()
        findings = []
        if roots:
            findings = [(k, e) for k, e in scan(expand_tree(roots), roots) if k not in seen_local]
        if findings or now - last_beat >= 5:
            seen_local.update(record(findings, read_pf_totals(), "daemon"))
            seen_local.update(k for k, _ in findings)
            last_beat = now
        time.sleep(0.5)


# ---------------------------------------------------------------- entry point

def main(argv=None):
    """Dispatch: gate | probe <cache> | status [--json] | sample | daemon."""
    argv = sys.argv[1:] if argv is None else argv
    mode = argv[0] if argv else ""
    if mode == "gate":
        try:
            gate()
        except SystemExit:
            raise
        except Exception as e:  # a broken gate must fail closed, but say how to bypass it
            gate_deny("Gate itself failed (%s: %s). Blocked." % (type(e).__name__, e))
    elif mode == "probe" and len(argv) >= 2:
        try:
            probe(argv[1])
        finally:
            try:
                os.rmdir(argv[1] + ".lock")
            except OSError:
                pass
    elif mode == "status":
        status(as_json="--json" in argv, ansi="--ansi" in argv)
    elif mode == "sample":
        sample()
    elif mode == "daemon":
        daemon()
    else:
        # Exit 2 on purpose: this script is mostly run as a UserPromptSubmit hook, and Claude Code
        # treats every other non-zero code as "non-blocking error" → a typo would silently disable
        # the gate. Failing closed makes a misconfigured hook visible immediately.
        sys.stderr.write("[claude-egress-guard] unknown mode %r — expected gate | probe <cache> | "
                         "status | sample | daemon. Blocked.\n" % mode)
        sys.exit(2)


if __name__ == "__main__":
    main()
