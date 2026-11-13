# Pitfalls

[中文](pitfalls.md) · [Back to README](../README.en.md)

All of these were hit for real while deploying. Each entry: **symptom → cause → what this project does about it**.

## Proxy variables

1. **"Enable the proxy only if the port is listening" shell snippets fail open.** A terminal opened before the proxy is up — and any Claude Code started from it — goes direct for its whole lifetime. A dead proxy port fails *instantly* (connection refused), so the "avoid hangs" reason does not hold. → `macos/shell/proxy.zsh` always exports, and only warns.
2. **Claude Code ignores the OS system proxy.** Started from a GUI, IDE, scheduler or launchd without `*_PROXY` → direct. → Managed settings (highest precedence).
3. **Provider-switching tools rewrite the `env` block of `settings.json`.** → Managed settings are out of their reach.
4. **Node's built-in `fetch` ignores `*_PROXY`.** → `NODE_USE_ENV_PROXY=1` (Node ≥ 22.21 / 24.5); with it, a dead proxy also fails closed.

## macOS pf

5. **`flags S/SA` blocks replies to inbound connections.** Pass rules then only match the first packet of *outgoing* connections; the SYN-ACK your Mac sends back as a server falls through to the block rule → AirDrop, Handoff, Universal Clipboard, AirPlay receiver and LAN dev servers break. → `flags any`.
6. **The App Store build of Tailscale runs its network extension as your user**, so full mode would block its DERP/control traffic. → Use the standalone build (system extension runs as root). Switching builds creates a new node with a new Tailscale IP — update everything that refers to the old address.
7. **Apple services bypass the system proxy to `17.0.0.0/8`** (QUIC and TCP). → Allowed by default in full mode (`--no-apple` to disable); Apple seeing your real IP is unrelated to Claude.
8. **pflog has no pid on macOS** (uid is filled, pid is always 100000), so blocked packets cannot be mapped to processes directly. → The block log (`blocklog.py`) takes two detours: for TCP, the RST that pf's `block return` sends back to the program — `tcpdump -i pktap,all -k` tags the process receiving it; for UDP, `lsof` on the local port right after the block (QUIC sockets stay open while retrying). `pktap` does not capture `pflog0` itself, so there is no process info there. By hand, classify by destination, port and TCP flags (a SYN-ACK from a local listening port = a reply).
9. **tcpdump on `pflog0` needs `-e`**: without it the `rule …: block out on en0:` header is not printed, so rule, direction and interface are lost and nothing can be parsed as a block record.
10. **`tailscale netcheck` reports false failures in full mode**: the CLI sends its own STUN probes as your user. Use `tailscale status --json` (`Health`, `Relay`).
11. **pf rules load about a minute after boot** (when launchd starts third-party daemons). Claude Code is still governed by proxy variables meanwhile; with the proxy not up yet, requests fail rather than go direct.
12. **Files written to `/tmp` by root cannot be deleted by users** (sticky bit) — automation that reuses a log name may read the previous run's result. Use timestamped names.

## Proxy clients

13. **Clash Verge Rev sidecar mode** runs the core as your user (no full mode); restarting while the old core still holds the port makes the new instance pick another port and move the system proxy.
14. **Blacklist (GFW-list) routing leaks**: every unblocked foreign domain goes direct.
15. **`GEOIP` rules trigger local DNS resolution**, exposing domain names to your ISP's resolver. Put known foreign domains before `GEOIP`.
16. **Stale exit node address**: everything foreign fails. Fail-closed guarantees no leak, but "safely broken" is easy to overlook — monitor it.

## Windows

17. **Running PowerShell scripts non-interactively (over SSH, CI …)**: `powershell -Command -` (script on stdin) splits multi-line `if`/`for` blocks so later statements silently never run; child processes started by the script eat the rest of stdin; the default shell is PowerShell, so `%TEMP%` does not expand; a BOM-less `.ps1` with non-ASCII text is read in the ANSI code page. → Add a UTF-8 BOM (or keep scripts ASCII), `scp` it over, run with `-File <absolute path>`.
18. **Managed settings must be UTF-8 without BOM** at `%ProgramFiles%\ClaudeCode\managed-settings.json`.
19. **The firewall filters per program**: an npm-installed Claude Code runs inside `node.exe`. → `claude install` for the native `claude.exe` first.
20. **Desktop apps' background services often run as SYSTEM** and ignore your user's proxy. The all-process "block Anthropic" rule still stops them from reaching Anthropic itself.
21. **Audit subcategory names are localized**: on a non-English Windows `auditpol /set /subcategory:"Filtering Platform Connection"` fails with `0x57` (invalid parameter), and `auditpol /get` prints localized words. → Use the GUID `{0CCE9226-69AE-11D9-BED3-505054503030}`; to read the previous setting, `auditpol /backup` and take the number in the last column (0 none, 1 success, 2 failure, 3 both). Without this audit, WFP netevents do not record drops either.
22. **Testing a firewall rule with curl goes through the proxy**: with `HTTP(S)_PROXY` in the user environment, `curl.exe` uses the local proxy and never hits the rule, which looks like "the rule does not work". → Test with `--noproxy '*'`.
23. **The "Filtering Platform Connection" audit is noisy inbound**: system components kept away from the local proxy port by UWP loopback isolation (`BackgroundTaskHost`, `msedgewebview2` …) retry constantly, possibly dozens of events per minute. `install.ps1` therefore raises the Security log to at least 128 MB; the block log keeps only outbound events raised by this project's rules.

## Operating habits

24. **Never probe Claude Code with a dead proxy on a machine whose login you care about**: a failed token refresh can wipe the local credentials (re-`/login` needed). Use `tools/probe_hosts.py`, ideally with a disposable login.
25. **Never kill processes by fuzzy path matching** — you will hit same-vendor services (e.g. a desktop app's background service). Match exact executable paths.
26. **`503 credential validation failed` comes from the server.** Our blocks show up as "connection refused" with no HTTP status; local proxy failures are usually 502.
27. **Do not validate an exit by status code alone** — connection reuse can return a fast "204" over an old path. Use an endpoint that echoes the IP (`/cdn-cgi/trace`).
