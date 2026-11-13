#!/bin/bash
# claude-egress-guard — run every offline check. Exit code != 0 on any failure.
#   bash tests/run_all.sh
set -u
cd "$(dirname "$0")/.."
fail=0
step() { printf '\n== %s\n' "$1"; }
ok() { echo "   ok  $1"; }
bad() { echo "   FAIL $1"; fail=1; }

step "python unit tests"
python3 -m unittest discover -s tests -p 'test_*.py' 2>&1 | tail -4
[ "${PIPESTATUS[0]}" -eq 0 ] && ok unittest || bad unittest

step "python syntax (parsed with the Python 3.8 grammar, then byte-compiled)"
for f in guard/*.py tools/*.py; do
  python3 -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1], feature_version=(3, 8))' "$f" \
    && python3 -m py_compile "$f" && ok "$f" || bad "$f"
done

step "shell syntax"
for f in macos/pf/*.sh; do sh -n "$f" && ok "$f" || bad "$f"; done
for f in macos/statusline/*.sh tests/run_all.sh; do bash -n "$f" && ok "$f" || bad "$f"; done
if command -v zsh >/dev/null; then zsh -n macos/shell/proxy.zsh && ok proxy.zsh || bad proxy.zsh; fi
bash -n macos/shell/proxy.zsh && ok "proxy.zsh (bash)" || bad "proxy.zsh (bash)"

step "json / plist"
for f in macos/claude/*.json; do python3 -m json.tool "$f" >/dev/null && ok "$f" || bad "$f"; done
if command -v plutil >/dev/null; then plutil -lint macos/pf/*.plist >/dev/null && ok plist || bad plist; fi

step "pf rules parse (macOS only; renders templates with uid 501 and a sample domestic list)"
if [ "$(uname -s)" = Darwin ]; then
  T=$(mktemp -d)
  printf '# sample\n198.51.100.0/24\n' > "$T/dom.txt"
  R=$(grep -v -E '^[[:space:]]*(#|$)' config/anthropic-ranges.txt | paste -sd, - | sed 's/,/, /g')
  sed -e "s#@ANTHROPIC_RANGES@#$R#" -e "s#@UID@#501#g" -e "s#@EXTRA_ALLOW4@#, 17.0.0.0/8#" \
      -e "s#@DOMESTIC_FILE@#$T/dom.txt#" macos/pf/rules.full.conf.tmpl > "$T/full.conf"
  sed -e "s#@ANTHROPIC_RANGES@#$R#" macos/pf/rules.anthropic-only.conf.tmpl > "$T/anth.conf"
  for c in full anth; do
    /sbin/pfctl -n -a com.apple/250.ClaudeEgressGuard -f "$T/$c.conf" >/dev/null 2>&1 && ok "$c.conf" || bad "$c.conf"
  done
  grep -q '@' "$T/full.conf" "$T/anth.conf" && bad "unrendered placeholder" || ok "no leftover placeholders"
  rm -rf "$T"
else
  echo "   skip (not macOS)"
fi

step "generated proxy snippets"
python3 tools/gen_proxy_rules.py --target all >/dev/null && ok gen_proxy_rules || bad gen_proxy_rules

step "executable bits (documented commands must run as ./script)"
for f in macos/pf/*.sh macos/statusline/*.sh tests/run_all.sh guard/*.py tools/*.py; do
  [ -x "$f" ] && ok "$f" || bad "$f not executable"
done

echo
[ $fail -eq 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit $fail
