#!/usr/bin/env python3
"""Refresh config/anthropic-ranges.txt from AS399358 and check where Claude endpoints resolve.

1. Ask RIPEstat which prefixes AS399358 (Anthropic, PBC) currently announces.
2. Resolve the known Claude endpoints over DNS-over-HTTPS (through your proxy, so the
   lookup itself does not leak) and report any endpoint that resolves OUTSIDE those
   prefixes — such endpoints are not covered by the "block Anthropic" firewall rule and
   rely on your proxy rules (config/claude-domains.txt) instead.

3. With --write, rewrite config/anthropic-ranges.txt: the announced prefixes plus the
   NAT64 form of every IPv4 prefix (64:ff9b::/96 + IPv4) so that IPv6-only networks with
   DNS64/NAT64 cannot reach Anthropic around the IPv4 block. Re-run the installer afterwards.

Usage:  HTTPS_PROXY=http://127.0.0.1:7890 python3 tools/update_anthropic_ranges.py [--write] [--asn 399358]
Refuses to run without HTTPS_PROXY unless --allow-direct is given.
"""

import argparse
import ipaddress
import json
import os
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "config", "anthropic-ranges.txt")
RIPESTAT = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s"
DOH = "https://cloudflare-dns.com/dns-query?name=%s&type=A"
NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")
ENDPOINTS = ["api.anthropic.com", "console.anthropic.com", "mcp-proxy.anthropic.com", "claude.ai",
             "platform.claude.com", "code.claude.com", "claude.com", "downloads.claude.ai"]


def fetch_json(url, headers=None):
    """GET a JSON document (honours HTTPS_PROXY)."""
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "claude-egress-guard"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def announced_prefixes(asn):
    """Prefixes currently announced by the AS, sorted (IPv4 first)."""
    data = fetch_json(RIPESTAT % asn)
    nets = {ipaddress.ip_network(p["prefix"]) for p in data["data"]["prefixes"]}
    return sorted(nets, key=lambda n: (n.version, n))


def resolve_a(name):
    """A records via DNS-over-HTTPS (JSON API)."""
    data = fetch_json(DOH % name, {"accept": "application/dns-json", "User-Agent": "claude-egress-guard"})
    return [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]


def nat64(net):
    """Map an IPv4 prefix into the NAT64 well-known prefix (RFC 6052), e.g. /23 -> /119."""
    base = int(NAT64_WKP.network_address) + int(net.network_address)
    return ipaddress.ip_network((base, 96 + net.prefixlen))


def main(argv=None):
    """CLI entry: print prefixes, check endpoints, optionally rewrite the config file."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--asn", default="399358")
    ap.add_argument("--write", action="store_true", help="rewrite config/anthropic-ranges.txt")
    ap.add_argument("--allow-direct", action="store_true",
                    help="run even though HTTPS_PROXY is not set (lookups then leave from your real IP)")
    ap.add_argument("--force", action="store_true",
                    help="write even if the result is empty or drops prefixes that are in the file now")
    args = ap.parse_args(argv)
    if not (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")) and not args.allow_direct:
        ap.error("HTTPS_PROXY is not set; set it to your local proxy or pass --allow-direct")
    for var in ("NO_PROXY", "no_proxy"):  # this process only: every lookup must use the proxy
        os.environ.pop(var, None)

    nets = announced_prefixes(args.asn)
    print("AS%s announces:" % args.asn)
    for n in nets:
        print("  ", n)
    print("\nendpoint check (A records via DoH):")
    for host in ENDPOINTS:
        try:
            ips = resolve_a(host)
        except OSError as e:
            print("  %-26s lookup failed: %s" % (host, e))
            continue
        inside = [ip for ip in ips if any(ipaddress.ip_address(ip) in n for n in nets)]
        verdict = "covered" if ips and len(inside) == len(ips) else "NOT covered -> relies on proxy rules"
        print("  %-26s %-32s %s" % (host, ",".join(ips) or "-", verdict))

    if args.write:
        # keep the explanatory comment block, drop the previous "# updated" stamp
        header = open(OUT, encoding="utf-8").read().split("\n")
        comments = [l for l in header if l.startswith("#") and not l.startswith("# updated ")]
        mapped = [nat64(n) for n in nets if n.version == 4]
        current = {ipaddress.ip_network(l.strip()) for l in header if l.strip() and not l.startswith("#")}
        dropped = sorted(current - set(nets) - set(mapped), key=lambda n: (n.version, n))
        if (not nets or dropped) and not args.force:
            # an empty or shrinking answer is more likely a lookup problem than Anthropic leaving
            # its address space; installers would otherwise load a weaker (or empty) block list
            print("\nNOT writing: %s. Re-run with --force if this is really intended."
                  % ("no prefixes returned" if not nets else "would drop " + ", ".join(map(str, dropped))))
            return 1
        with open(OUT, "w", encoding="utf-8") as f:
            f.write("\n".join(comments) + "\n")
            f.write("# updated %s\n" % time.strftime("%Y-%m-%d"))
            f.writelines("%s\n" % n for n in nets)
            f.writelines("%s\n" % n for n in mapped)
        print("\nwrote", OUT, "- now re-run the installer so the firewall picks it up")


if __name__ == "__main__":
    raise SystemExit(main())
