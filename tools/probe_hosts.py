#!/usr/bin/env python3
"""Zero-leak probe: list every host a program tries to reach through its proxy.

Starts a fake HTTP proxy that records the target of each CONNECT / absolute-URI request and
answers 403 — nothing is forwarded, so nothing leaves the machine and no quota is used.
Point a program at it to learn which endpoints it contacts (then make sure each of them is
covered by config/claude-domains.txt or config/anthropic-ranges.txt).

Example (do this BEFORE installing managed settings — they take precedence over --settings):
  python3 tools/probe_hosts.py --port 18899 --seconds 60 &
  claude -p "hi" --settings '{"env":{"HTTPS_PROXY":"http://127.0.0.1:18899","HTTP_PROXY":"http://127.0.0.1:18899","NODE_USE_ENV_PROXY":"1"}}'

Only traffic that honours the proxy variables shows up here. Run it with the anthropic-only pf
rules installed so that anything ignoring them is refused instead of leaving from your real IP.

WARNING: a refused proxy can make Claude Code fail its OAuth token refresh. On a machine whose
login you want to keep, use a throwaway session or be ready to run /login again.
"""

import argparse
import collections
import socket
import threading
import time


def handle(conn, hits, lock):
    """Read the request line, record the target host, reply 403 and close."""
    try:
        conn.settimeout(5)
        first = conn.recv(4096).split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = first.split()
        if len(parts) >= 2:
            target = parts[1]
            if target.startswith("http://") or target.startswith("https://"):
                target = target.split("/", 3)[2]
            with lock:
                hits[target] += 1
        conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    except OSError:
        pass
    finally:
        conn.close()


def main(argv=None):
    """CLI entry: listen on 127.0.0.1:<port> for N seconds, then print a host histogram."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=18899)
    ap.add_argument("--seconds", type=int, default=60)
    args = ap.parse_args(argv)

    hits, lock = collections.Counter(), threading.Lock()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(64)
    srv.settimeout(0.5)
    deadline = time.time() + args.seconds
    print("probe proxy on http://127.0.0.1:%d for %ds (refuses everything)" % (args.port, args.seconds))
    while time.time() < deadline:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=handle, args=(conn, hits, lock), daemon=True).start()
    srv.close()
    print("\nrequested targets:")
    for target, n in hits.most_common():
        print("  %4d  %s" % (n, target))


if __name__ == "__main__":
    main()
