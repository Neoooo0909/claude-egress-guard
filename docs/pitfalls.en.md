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
8. **pflog has no pid on macOS** (uid is filled, pid is always 100000), so blocked packets cannot be mapped to processes. → Classify by destination, port and TCP flags (a SYN-ACK from a local listening port = a reply). See `diag_pflog.sh`.
9. **`tailscale netcheck` reports false failures in full mode**: the CLI sends its own STUN probes as your user. Use `tailscale status --json` (`Health`, `Relay`).
10. **pf rules load about a minute after boot** (when launchd starts third-party daemons). Claude Code is still governed by proxy variables meanwhile; with the proxy not up yet, requests fail rather than go direct.
11. **Files written to `/tmp` by root cannot be deleted by users** (sticky bit) — automation that reuses a log name may read the previous run's result. Use timestamped names.

## Proxy clients

12. **Clash Verge Rev sidecar mode** runs the core as your user (no full mode); restarting while the old core still holds the port makes the new instance pick another port and move the system proxy.
13. **Blacklist (GFW-list) routing leaks**: every unblocked foreign domain goes direct.
14. **`GEOIP` rules trigger local DNS resolution**, exposing domain names to your ISP's resolver. Put known foreign domains before `GEOIP`.
15. **Stale exit node address**: everything foreign fails. Fail-closed guarantees no leak, but "safely broken" is easy to overlook — monitor it.

## Windows

16. **Running PowerShell scripts non-interactively (over SSH, CI …)**: `powershell -Command -` (script on stdin) splits multi-line `if`/`for` blocks so later statements silently never run; child processes started by the script eat the rest of stdin; the default shell is PowerShell, so `%TEMP%` does not expand; a BOM-less `.ps1` with non-ASCII text is read in the ANSI code page. → Add a UTF-8 BOM (or keep scripts ASCII), `scp` it over, run with `-File <absolute path>`.
17. **Managed settings must be UTF-8 without BOM** at `%ProgramFiles%\ClaudeCode\managed-settings.json`.
18. **The firewall filters per program**: an npm-installed Claude Code runs inside `node.exe`. → `claude install` for the native `claude.exe` first.
19. **Desktop apps' background services often run as SYSTEM** and ignore your user's proxy. The all-process "block Anthropic" rule still stops them from reaching Anthropic itself.

## Operating habits

20. **Never probe Claude Code with a dead proxy on a machine whose login you care about**: a failed token refresh can wipe the local credentials (re-`/login` needed). Use `tools/probe_hosts.py`, ideally with a disposable login.
21. **Never kill processes by fuzzy path matching** — you will hit same-vendor services (e.g. a desktop app's background service). Match exact executable paths.
22. **`503 credential validation failed` comes from the server.** Our blocks show up as "connection refused" with no HTTP status; local proxy failures are usually 502.
23. **Do not validate an exit by status code alone** — connection reuse can return a fast "204" over an old path. Use an endpoint that echoes the IP (`/cdn-cgi/trace`).
