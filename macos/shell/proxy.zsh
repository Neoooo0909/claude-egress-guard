# claude-egress-guard — fail-closed proxy variables for interactive shells (zsh/bash).
# Source it from ~/.zshrc (or ~/.bashrc):   source ~/claude-egress-guard/macos/shell/proxy.zsh
#
# Why "fail-closed": the common snippet "turn the proxy on only if the port is listening"
# makes every terminal opened before the proxy app is ready go DIRECT — including any
# Claude Code started from it, for its whole lifetime. A dead proxy port fails instantly
# (connection refused, no hang), so always exporting the variables costs nothing.
#
# Set CEG_PROXY_URL before sourcing if your client uses another port, e.g.
#   Clash / mihomo 7890 · Clash Verge Rev 7897 · v2rayN 10808/10809 · sing-box 2080 · Surge 6152

: "${CEG_PROXY_URL:=http://127.0.0.1:7890}"
: "${CEG_NO_PROXY:=localhost,127.0.0.1,::1}"

# Export proxy variables (both cases) and make Node's built-in fetch honour them.
proxy_on() {
  export http_proxy="$CEG_PROXY_URL" https_proxy="$CEG_PROXY_URL"
  export HTTP_PROXY="$CEG_PROXY_URL" HTTPS_PROXY="$CEG_PROXY_URL"
  export no_proxy="$CEG_NO_PROXY" NO_PROXY="$CEG_NO_PROXY"
  # Node ≥ 22.21 / 24.5: built-in fetch ignores *_PROXY unless this is set
  export NODE_USE_ENV_PROXY=1
}

# Remove everything proxy_on set (requests will then leave from your real IP — on purpose).
proxy_off() {
  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY NODE_USE_ENV_PROXY
}

proxy_on
# Interactive shells only: warn (but stay fail-closed) when the proxy is not listening yet.
_ceg_hp="${CEG_PROXY_URL#*://}"; _ceg_hp="${_ceg_hp%%/*}"; _ceg_hp="${_ceg_hp##*@}"  # host:port, no credentials
case $- in
  *i*) nc -z -G 1 "${_ceg_hp%:*}" "${_ceg_hp##*:}" >/dev/null 2>&1 \
         || echo "claude-egress-guard: proxy ${_ceg_hp} not listening — requests will fail (not go direct). proxy_off to go direct." >&2 ;;
esac
unset _ceg_hp
