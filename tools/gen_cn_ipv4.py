#!/usr/bin/env python3
"""Build the "domestic" IPv4 list (default: mainland China) from APNIC's delegation file.

The list has two consumers:
  * macOS pf full mode — your user may still reach these addresses DIRECTLY
    (domestic apps keep working; anything foreign must go through the proxy);
  * guard/egress_guard.py — to tell "direct to a domestic site" (by design) from
    "direct to a foreign IP" (a real-IP leak).

Usage:
  python3 tools/gen_cn_ipv4.py                       # → ~/.config/claude-egress-guard/domestic-ipv4.txt
  python3 tools/gen_cn_ipv4.py --country CN --out /path/file.txt
  python3 tools/gen_cn_ipv4.py --input delegated-apnic-latest   # offline, from a downloaded file

The download honours HTTPS_PROXY / HTTP_PROXY (urllib default behaviour).
"""

import argparse
import ipaddress
import os
import time
import urllib.request

APNIC_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
DEFAULT_OUT = os.path.join(os.path.expanduser("~"), ".config", "claude-egress-guard", "domestic-ipv4.txt")


def parse_delegated(lines, country):
    """Turn ``apnic|CN|ipv4|start|count|date|status`` records into collapsed CIDRs.

    APNIC counts are address counts, not always powers of two, so each range is
    summarised into the minimal set of CIDR blocks.
    """
    nets = []
    for line in lines:
        p = line.strip().split("|")
        if len(p) >= 7 and p[1] == country and p[2] == "ipv4" and p[6] in ("allocated", "assigned"):
            start = ipaddress.IPv4Address(p[3])
            end = start + int(p[4]) - 1
            nets.extend(ipaddress.summarize_address_range(start, end))
    return list(ipaddress.collapse_addresses(nets))


def main(argv=None):
    """CLI entry: download (or read) the delegation file and write the CIDR list."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--country", default="CN", help="ISO country code in the APNIC file (default CN)")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--input", help="use a local delegated-apnic-latest file instead of downloading")
    args = ap.parse_args(argv)

    if args.input:
        with open(args.input, encoding="ascii", errors="replace") as f:
            lines = f.readlines()
    else:
        with urllib.request.urlopen(APNIC_URL, timeout=120) as resp:
            lines = resp.read().decode("ascii", "replace").splitlines()
    nets = parse_delegated(lines, args.country)
    if not nets:
        raise SystemExit("no IPv4 records for country %s" % args.country)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as out:
        out.write("# %s IPv4 (APNIC delegated, generated %s by claude-egress-guard)\n"
                  % (args.country, time.strftime("%Y-%m-%d")))
        out.writelines("%s\n" % n for n in nets)
    total = sum(n.num_addresses for n in nets)
    print("wrote %d prefixes (%.1fM addresses) to %s" % (len(nets), total / 1e6, args.out))


if __name__ == "__main__":
    main()
