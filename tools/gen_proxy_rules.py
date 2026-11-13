#!/usr/bin/env python3
"""Generate proxy-client rule snippets from config/claude-domains.txt.

Every Claude-related domain gets routed to ONE dedicated policy that only contains your
fixed exit node(s) — no DIRECT, no "auto-select across 200 nodes" (a changing exit IP is
itself a risk signal). Paste the output into your client and keep the rules ABOVE any
GEOIP/GEOSITE-based DIRECT rule.

Usage:
  python3 tools/gen_proxy_rules.py --target mihomo   [--policy CLAUDE_EXIT]
  python3 tools/gen_proxy_rules.py --target singbox  [--policy claude-exit]
  python3 tools/gen_proxy_rules.py --target xray     [--policy proxy]
  python3 tools/gen_proxy_rules.py --target surge    [--policy ClaudeExit]
  python3 tools/gen_proxy_rules.py --target all
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LIST = os.path.join(ROOT, "config", "claude-domains.txt")
DEFAULT_POLICY = {"mihomo": "CLAUDE_EXIT", "singbox": "claude-exit", "xray": "proxy", "surge": "ClaudeExit"}


def load_domains(path):
    """Read domain suffixes (one per line, ``#`` comments, blank lines ignored), de-duplicated."""
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            d = line.split("#", 1)[0].strip().lower().lstrip(".")
            if d and d not in out:
                out.append(d)
    return out


def mihomo(domains, policy):
    """Clash / mihomo (Clash Verge Rev, ClashX Meta, FlClash …) YAML snippet."""
    lines = ["# --- claude-egress-guard: put these rules BEFORE any GEOIP / GEOSITE,cn / MATCH rule ---",
             "rules:"]
    lines += ["  - DOMAIN-SUFFIX,%s,%s" % (d, policy) for d in domains]
    lines += ["",
              "# A dedicated group that ONLY contains your fixed exit node(s). Never add DIRECT here,",
              "# and do not use url-test/load-balance across many unrelated nodes (the exit IP would hop).",
              "proxy-groups:",
              "  - name: %s" % policy,
              "    type: select",
              "    proxies: [YOUR_FIXED_EXIT_NODE]"]
    return "\n".join(lines)


def singbox(domains, policy):
    """sing-box (SFM / SFA / Hiddify / GUI.for.SingBox) route rule + selector outbound."""
    snippet = {
        "route": {"rules": [{"domain_suffix": domains, "outbound": policy}],
                  "_comment": "place this rule before geosite/geoip direct rules; keep route.final = your proxy"},
        "outbounds": [{"type": "selector", "tag": policy, "outbounds": ["YOUR_FIXED_EXIT_NODE"],
                       "_comment": "no 'direct' in this selector"}],
    }
    return "// --- claude-egress-guard (merge into your sing-box config; remove _comment keys) ---\n" + \
        json.dumps(snippet, indent=2, ensure_ascii=False)


def xray(domains, policy):
    """xray / v2ray routing rule (v2rayN: add as the FIRST rule of the active routing set)."""
    rule = {"type": "field", "domain": ["domain:%s" % d for d in domains], "outboundTag": policy}
    return ("// --- claude-egress-guard: xray routing rule (first rule of routing.rules) ---\n"
            "// v2rayN GUI: Settings > Routing > your active set > add rule: outboundTag=proxy,\n"
            "// Domain = the list below (one per line). Use a whitelist-style set\n"
            "// ('bypass mainland' / final rule = proxy), NOT a blacklist / GFW-list set.\n"
            + json.dumps(rule, indent=2, ensure_ascii=False))


def surge(domains, policy):
    """Surge for Mac rule lines + a select group."""
    lines = ["# --- claude-egress-guard: [Rule] section, above GEOIP,CN and FINAL ---", "[Rule]"]
    lines += ["DOMAIN-SUFFIX,%s,%s" % (d, policy) for d in domains]
    lines += ["", "[Proxy Group]", "%s = select, YOUR_FIXED_EXIT_NODE" % policy]
    return "\n".join(lines)


GENERATORS = {"mihomo": mihomo, "singbox": singbox, "xray": xray, "surge": surge}


def main(argv=None):
    """CLI entry: print the requested snippet(s) to stdout."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", choices=sorted(GENERATORS) + ["all"], required=True)
    ap.add_argument("--policy", help="policy/outbound name (default depends on target)")
    ap.add_argument("--domains", default=DEFAULT_LIST, help="domain list file")
    args = ap.parse_args(argv)
    domains = load_domains(args.domains)
    if not domains:
        sys.exit("no domains in %s" % args.domains)
    targets = sorted(GENERATORS) if args.target == "all" else [args.target]
    for t in targets:
        print(GENERATORS[t](domains, args.policy or DEFAULT_POLICY[t]))
        print()


if __name__ == "__main__":
    main()
