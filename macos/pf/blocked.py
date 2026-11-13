#!/usr/bin/env python3
"""claude-egress-guard — show what the pf kill switch blocked (reads the blocklog daemon's log).

  ./macos/pf/blocked.py            today: totals, top sources, last 10 records
  ./macos/pf/blocked.py -d 3       the last 3 days
  ./macos/pf/blocked.py -n 30      list the last 30 records
  ./macos/pf/blocked.py --raw      today's records as JSON lines

The log is readable by the admin group (it reveals where programs tried to connect).
"""
import argparse
import datetime as dt
import json
import os
import sys
from collections import defaultdict

LOG = "/Library/Application Support/ClaudeEgressGuard/blocked.jsonl"
KIND = {"anthropic": "Anthropic", "direct": "direct"}


def load(since, path=None):
    """Records with ts >= since from the log and its rotated predecessor, oldest first."""
    path = path or LOG
    recs = []
    for p in (path + ".1", path):
        try:
            with open(p, encoding="utf-8") as f:
                for line in f:
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    if r.get("ts", "") >= since:
                        recs.append(r)
        except OSError:
            continue
    return sorted(recs, key=lambda r: r.get("ts", ""))


def clean(v):
    """Printable text only: names come from other processes and must not inject terminal escapes."""
    return "".join(c if c.isprintable() else "?" for c in str(v)) if v is not None else ""


def proc_name(r):
    """Process name without the pid, or "?" when it could not be attributed."""
    p = r.get("proc")
    return clean(p.rsplit(":", 1)[0]) if p else "?"


def summarize(recs, tail=10):
    """Return the report lines: totals per kind, top 15 (target, process), the last records."""
    out = []
    by_kind = defaultdict(int)
    for r in recs:
        by_kind[r.get("kind")] += r.get("n", 0)
    total = sum(by_kind.values())
    out.append(f"{total} packets blocked (" +
               ", ".join(f"{KIND.get(k, k)} {v}" for k, v in sorted(by_kind.items())) + ")")
    if not recs:
        return out
    agg = defaultdict(lambda: {"n": 0, "last": "", "kinds": set(), "ports": set()})
    for r in recs:
        g = agg[(clean(r.get("domain") or r.get("dst", "?")), proc_name(r))]
        g["n"] += r.get("n", 0)
        g["last"] = max(g["last"], r.get("last", ""))
        g["kinds"].add(r.get("kind"))
        g["ports"].add(f'{r.get("proto")}/{r.get("port")}')
    out += ["", "top sources (target [ports] | process | packets | last seen):"]
    for (tgt, proc), g in sorted(agg.items(), key=lambda kv: -kv[1]["n"])[:15]:
        flag = "  ! Anthropic" if "anthropic" in g["kinds"] else ""
        out.append(f"  {tgt} [{','.join(sorted(g['ports'])[:3])}] | {proc} | {g['n']} | {g['last'][5:]}{flag}")
    if tail > 0:
        out += ["", f"last {tail} records:"]
        for r in recs[-tail:]:
            exe = f"  <- {clean(r['exe'])[:80]}" if r.get("exe") else ""
            out.append(f"  {clean(r.get('ts'))[5:]} {KIND.get(r.get('kind'), clean(r.get('kind')))} "
                       f"{clean(r.get('proto'))} {clean(r.get('dst'))}:{clean(r.get('port'))} "
                       f"{clean(r.get('domain'))} | {clean(r.get('proc')) or '?'} x{clean(r.get('n'))}{exe}")
    unknown = sum(r.get("n", 0) for r in recs if not r.get("proc"))
    if unknown:
        out += ["", f"note: {unknown} packets have no process (the socket closed before it could be "
                    "looked up) - judge them by domain/IP."]
    return out


def main():
    """Parse arguments and print the report."""
    ap = argparse.ArgumentParser(description="show what the pf kill switch blocked")
    ap.add_argument("-d", "--days", type=int, default=1, help="how many days (1 = today)")
    ap.add_argument("-n", "--tail", type=int, default=10, help="how many recent records to list")
    ap.add_argument("--raw", action="store_true", help="print the records as JSON lines")
    a = ap.parse_args()
    if not os.path.exists(LOG):
        print(f"no block log yet ({LOG}): the blocklog daemon is not installed, or nothing was blocked.")
        return 0
    if not os.access(LOG, os.R_OK):
        print(f"cannot read {LOG}: it is readable by the admin group only (try sudo).")
        return 1
    since = (dt.date.today() - dt.timedelta(days=max(a.days, 1) - 1)).isoformat()
    recs = load(since)
    if a.raw:
        for r in recs:
            print(json.dumps(r, ensure_ascii=False))
        return 0
    print(("today: " if a.days <= 1 else f"last {a.days} days: ") + "\n".join(summarize(recs, a.tail)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
