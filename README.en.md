# claude-egress-guard

**Make every byte bound for Claude / Anthropic leave through the proxy exit you chose — and when the proxy breaks, fail closed instead of falling back to your real IP.**

[中文](README.md) · [Per-proxy setup](docs/proxies.en.md) · [Pitfalls](docs/pitfalls.en.md)

Covers Claude Code (CLI) and its background traffic (model calls, OAuth, MCP, telemetry, updates) on macOS and Windows.
Works with mihomo/Clash (Clash Verge Rev, ClashX Meta, FlClash), sing-box, xray/v2rayN, Surge, and any client that exposes a local HTTP proxy port.

> This is an egress-control, fail-closed network hardening tool. Follow the laws where you live and the terms of the services you use; use at your own risk.

---

## Why: where the real IP actually leaks

"Just turn on a proxy" is not enough. Every row below was observed on real machines:

| # | Leak path | What happens |
|---|---|---|
| 1 | Shell snippet that exports `*_PROXY` only if the proxy port is already listening | A terminal opened before the proxy app is ready (very common after login/restore) — and any Claude Code started from it — goes **direct for its whole lifetime** |
| 2 | Claude Code **does not read the OS system proxy** | Started from an IDE, GUI, launchd/scheduled task or after `proxy_off`, with no `*_PROXY` variables → direct |
| 3 | Provider-switching tools rewrite the `env` block of `~/.claude/settings.json` | Proxy variables you put there silently disappear |
| 4 | Node's built-in `fetch` ignores `*_PROXY` | Node-based MCP servers, scripts and tools go direct |
| 5 | Proxy client switched to "direct/global" mode, a `DIRECT` member in the policy group, or a "blacklist / GFW-list" routing mode | The proxy core itself reaches Anthropic from your real IP; in blacklist mode, telemetry domains that are "not blocked" go direct |
| 6 | Claude's third-party telemetry (Datadog, GrowthBook …) is not in geosite lists | Routed by "local DNS + GEOIP"; if DNS returns a local CDN node, it goes direct |
| 7 | QUIC / WebRTC and other UDP bypass HTTP proxies | Browsers and system services reach foreign hosts directly |
| 8 | Services running as SYSTEM/root do not read the user's proxy settings | e.g. background/VM services of some desktop apps |
| 9 | The exit node's address changed but the client was never updated | All nodes dead, or a different exit IP |

## Design: four layers + monitoring

| Layer | Purpose | macOS | Windows |
|---|---|---|---|
| **L1 proxy variables** | Claude Code always has proxy variables | fail-closed shell snippet + user settings + **managed settings** (highest precedence, tools cannot overwrite) | user environment + **managed settings** |
| **L2 proxy rules** | Claude domains always go to ONE policy that contains only your fixed exit — never `DIRECT` | `tools/gen_proxy_rules.py` generates snippets per client | same |
| **L3 kill switch** | When the proxy breaks, traffic fails instead of going direct | pf: ① **no process** may reach Anthropic's address space directly; ② full mode: your user may not reach any foreign IP directly | Firewall: ① **no program** may reach Anthropic's ranges directly; ② `claude.exe` may only reach loopback / LAN / Tailscale |
| **L4 pre-prompt gate** | Before a prompt is sent, verify the exit Anthropic sees is expected (a measurement up to 60 s old is reused); block if unsure | `UserPromptSubmit` hook | same |
| **Monitoring** | Exit IP and anomaly counters at a glance | status line + resident sampler (direct connections in Claude Code process trees) + pf counters | gate + status text |

Principles:

- **Fail closed**: whichever layer breaks, the result is "request fails", never "goes direct".
- **Measure, don't assume**: the exit is measured via `https://api.anthropic.com/cdn-cgi/trace` — same host as the API, so the same proxy rule; Cloudflare echoes exactly the IP Anthropic sees.
- **No proxy variable → never touch a foreign host**: the guard then only asks the real-IP echo service (default `http://ip.3322.net`, a service inside mainland China — see [Configuration](#configuration)).

---

## Quick start

```bash
git clone https://github.com/<you>/claude-egress-guard.git ~/claude-egress-guard
cd ~/claude-egress-guard
bash tests/run_all.sh            # offline self-check (optional, macOS/Linux)
```

Windows PowerShell does not expand `~` in arguments of native commands; use `git clone https://github.com/<you>/claude-egress-guard.git "$HOME\claude-egress-guard"`.

### Step 1 (all platforms): proxy rules

```bash
python3 tools/gen_proxy_rules.py --target mihomo    # or singbox / xray / surge / all
```

(On Windows with a python.org install, use `py -3` wherever this README says `python3`.)

Paste the output into your client: rules go before any `GEOIP` / `GEOSITE,cn` / `MATCH` rule, plus a policy group that contains **only your fixed exit node(s)** — no `DIRECT`, and no auto-selection across many unrelated nodes (a hopping exit IP is a risk signal on its own). Client-specific notes: [docs/proxies.en.md](docs/proxies.en.md).

### Step 2 (all platforms): declare the expected exit

This is the first request to Anthropic through the proxy: make sure the step 1 rules are active in your client and the client is in rule mode (not "direct" / "global direct").

```bash
# macOS / Linux
curl -s -x http://127.0.0.1:7890 https://api.anthropic.com/cdn-cgi/trace | grep -E '^(ip|loc)='
mkdir -p ~/.config/claude-egress-guard
cp config/expected-egress.example.txt ~/.config/claude-egress-guard/expected-egress.txt
# replace the example address with the exit shown above
```

```powershell
# Windows PowerShell (in 5.1, curl is an alias of Invoke-WebRequest, hence curl.exe)
curl.exe -s -x http://127.0.0.1:10808 https://api.anthropic.com/cdn-cgi/trace | Select-String '^(ip|loc)='
New-Item -ItemType Directory -Force "$HOME\.config\claude-egress-guard" | Out-Null
Copy-Item config\expected-egress.example.txt "$HOME\.config\claude-egress-guard\expected-egress.txt"
notepad "$HOME\.config\claude-egress-guard\expected-egress.txt"   # put the exit shown above
```

### macOS

```bash
# 1) shell: fail-closed proxy variables (use your port)
echo 'CEG_PROXY_URL=http://127.0.0.1:7890; source ~/claude-egress-guard/macos/shell/proxy.zsh' >> ~/.zshrc

# 2) can you use FULL mode? The core LISTENING on the proxy port must not run as your user
lsof -nP -iTCP:7890 -sTCP:LISTEN
#    USER is root → full is possible; USER is you → switch the proxy to a service/TUN-service
#    mode first, or use anthropic-only (the installer runs this check itself, and also looks
#    for VPN network extensions running as your user)

# 3a) block Anthropic's address space only (works whoever runs the proxy core)
sudo sh macos/pf/install.sh --mode anthropic-only --proxy-url http://127.0.0.1:7890

# 3b) full mode: additionally refuse every direct foreign connection of your user
#     (domestic, LAN, Tailscale and Apple stay allowed)
python3 tools/gen_cn_ipv4.py                     # domestic IPv4 list (run as yourself)
sudo sh macos/pf/install.sh --mode full --proxy-url http://127.0.0.1:7890
```

Then merge `hooks` and `statusLine` from [macos/claude/settings.example.json](macos/claude/settings.example.json) into `~/.claude/settings.json` and **start a new Claude Code session** (hooks and managed settings load at startup).

### Windows

```powershell
claude install                       # switch to the native claude.exe (npm builds run inside node.exe)
# elevated PowerShell, logged in as your own account
Set-ExecutionPolicy -Scope Process Bypass    # allow scripts in this window only (Windows blocks .ps1 by default)
cd "$HOME\claude-egress-guard\windows"
.\install.ps1 -ProxyUrl http://127.0.0.1:10808      # v2rayN default 10808; add -ClaudeExe <path> if claude.exe lives elsewhere
.\test-firewall.ps1 -ProxyUrl http://127.0.0.1:10808
```

Gate hook (full Python path, forward slashes):

```json
{"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "timeout": 20,
  "command": "\"C:/Users/<you>/AppData/Local/Programs/Python/Python311/python.exe\" -X utf8 \"C:/Users/<you>/claude-egress-guard/guard/egress_guard.py\" gate"}]}]}}
```

> Windows Firewall filters per program, not per user, so there is no "block all foreign traffic of this user" switch like the macOS full mode. The "Claude Code only local" rule matches the `claude.exe` image only: its child processes (Node-based MCP servers, git, curl/python run by the Bash tool …) are not restricted by it — their direct connections to Anthropic's ranges are still refused by the "Block Anthropic" rule, but direct connections to other foreign hosts rely on the proxy variables alone. Other software is not affected.

### Linux (no bundled scripts yet)

Same idea: `nftables` with `meta skuid` for the per-user rule and `ip daddr` with Anthropic's ranges for the all-process block; Claude Code managed settings live at `/etc/claude-code/managed-settings.json`. PRs welcome.

---

## Verify

In this order: **confirm the rules are active before any direct test** — if they are not, the direct test itself reaches Anthropic from your real IP.

| Check | Command | Expected |
|---|---|---|
| 1. pf is enabled | `sudo pfctl -s info \| head -1` | `Status: Enabled` |
| 2. The main ruleset hooks `com.apple/*` (if another tool replaced it, this project's rules are not evaluated) | `sudo pfctl -sr \| grep '^anchor "com.apple/\*"'` | `anchor "com.apple/*" all` |
| 3. Anthropic ranges are in the table | `sudo pfctl -a com.apple/250.ClaudeEgressGuard -t ceg_anthropic -T test 160.79.104.10` | `1/1 addresses match` |
| 4. Direct to Anthropic is blocked (only after 1–3 pass) | `curl -s -o /dev/null -w '%{http_code}\n' --noproxy '*' -m 5 https://160.79.104.10/` | `000` immediately |
| 5. Full mode: direct foreign is blocked | `curl -s -o /dev/null -w '%{http_code}\n' --noproxy '*' -m 5 https://github.com` | `000` immediately |
| 6. Exit through the proxy | `curl -s -x <proxy> https://api.anthropic.com/cdn-cgi/trace` | `ip=` is your exit |
| 7. Gate | `python3 guard/egress_guard.py gate; echo $?` | `0`; and `2` for `env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy python3 guard/egress_guard.py gate; echo $?` |
| 8. Status line | `python3 guard/egress_guard.py status` | `exit 203.0.113.10 US \| anomalies today 0` |
| 9. Which hosts Claude Code contacts | `python3 tools/probe_hosts.py` (zero-leak probe, see its docstring) | all covered by the domain list or Anthropic's ranges |

On Windows, `test-firewall.ps1` only runs its direct test after confirming that the rule exists, is enabled and the firewall is on for every profile, and it checks that the rule's `claude.exe` path is the one you actually run.

Status line legend:

- `exit <IP> <country>`: the exit Anthropic currently sees; `(provider …)` = model calls go to a third-party provider.
- `! proxy down` / `! no proxy` / `! exit node down` / `! exit == real IP`: alert states.
- `! pf kill switch inactive`: pf is disabled, or another tool replaced the main ruleset so this project's rules are not evaluated (checked by the daemon every 60 s).
- `! NO_PROXY bypasses Claude hosts`: an entry in `NO_PROXY` would send Claude-related domains direct.
- `anomalies today N`: `anthropic-blocked` (a process tried to reach Anthropic directly and pf refused it), `direct` (a direct foreign connection in a Claude Code process tree, or any direct connection of the main process), `exit` (exit not in the expected list).
- `host blocked N`: all packets pf refused machine-wide (includes unrelated apps; not an alert).
- Details: `~/.cache/claude-egress-guard/events.jsonl`.

## Uninstall

```bash
sudo sh macos/pf/uninstall.sh                 # macOS: stop daemon, clear rules, restore managed settings to their pre-install state
```
```powershell
# Windows: elevated PowerShell
Set-ExecutionPolicy -Scope Process Bypass
cd "$HOME\claude-egress-guard\windows"
.\uninstall.ps1                 # add -RemoveUserEnv to also delete the user environment variables
```
Then remove the line from `~/.zshrc` and the hook from `settings.json`.

## FAQ

**The gate blocked me but the network looks fine?** Read the reason (exit not in the list, exit not measurable …). Temporary bypass: `touch ~/.config/claude-egress-guard/gate-off`; delete it to re-enable.

**`503 credential validation failed` in the UI?** That response comes from Anthropic's servers (credential validation outage), not from this project — our blocks show up as "connection refused" with no HTTP status, and local proxy failures are usually 502. Check status.claude.com.

**Why are direct connections to domestic sites not anomalies?** Domestic services go direct by design (`GEOSITE,cn` / `GEOIP,CN` rules). Anomalies are only "direct to a foreign IP" or "any direct connection of Claude Code's main process".

**Why not just use TUN mode?** TUN captures programs that ignore proxy variables, but when the core exits its routes vanish and traffic goes direct. When combining it with this project, note that pf's outbound rules also apply to TUN's utun interface:

- anthropic-only mode: without fake-IP, packets to Anthropic's real addresses are refused before they enter TUN, so programs that rely on TUN alone (no proxy variables) cannot reach Anthropic — failing closed, as intended. Claude Code uses the L1 proxy variables and is unaffected.
- full mode: your user's packets to fake-IPs (198.18.0.0/15) and to real foreign IPs are refused, so TUN is effectively off for your user; all foreign traffic has to use the proxy port.

The kill switch (L3) and the gate (L4) are still needed.

**My exit IP changed.** Update `expected-egress.txt`; until then the gate blocks every prompt (as it should).

## Configuration

`guard/egress_guard.py` reads these environment variables (all optional):

| Variable | Default | Purpose |
|---|---|---|
| `CEG_CONFIG_DIR` | `~/.config/claude-egress-guard` | holds `expected-egress.txt`, `domestic-ipv4.txt`, `gate-off` |
| `CEG_CACHE_DIR` | `~/.cache/claude-egress-guard` | probe caches, daily counters, event log |
| `CEG_TRACE_URL` | `https://api.anthropic.com/cdn-cgi/trace` | exit measurement; same host as the API, so the same proxy rule |
| `CEG_REAL_IP_URL` | `http://ip.3322.net` | echo service for your real IP; **your proxy rules must send it DIRECT**. The default is a service inside mainland China (plain HTTP). Elsewhere, use an echo service in your own region and add a `DIRECT` rule for it — otherwise the "real IP" measured is your exit and the gate blocks every prompt with "exit == real IP" |
| `CEG_GATE_FRESH` | `60` | max age (seconds) of a measurement the gate may reuse |
| `CEG_PF_STATS` | `/Library/Application Support/ClaudeEgressGuard/stats.json` | macOS pf counters |

`macos/shell/proxy.zsh` reads `CEG_PROXY_URL` (default `http://127.0.0.1:7890`) and `CEG_NO_PROXY`.

## Limitations

- Network egress only. Time zone, language, payment method, account behaviour and other non-IP signals are out of scope.
- Refresh Anthropic's ranges now and then: `HTTPS_PROXY=<proxy> python3 tools/update_anthropic_ranges.py --write` (it also lists endpoints outside those ranges, which rely on proxy rules only). **Re-run `install.sh` / `install.ps1` afterwards** so the firewall uses the new ranges.
- The resident sampler polls every 0.5 s; shorter connections can be missed; blocked attempts only show up as pf counters.
- macOS full mode requires proxy cores and VPN extensions not to run as your user (the installer checks who listens on the proxy port and looks for VPN network extensions, and refuses otherwise).
- The gate hook blocks only on exit code 2. A broken hook command (e.g. `python3` not found, exit code 127) is treated by Claude Code as a non-blocking error and the prompt **goes through**. After installing, run check 7 of "Verify" to confirm the gate returns `2` without proxy variables. Keep the hook `timeout` at 20 s or more: the gate itself may take up to 15 s, and a hook timeout is most likely treated as non-blocking too (the prompt goes through).

## License

MIT
