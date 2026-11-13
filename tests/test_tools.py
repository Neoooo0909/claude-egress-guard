"""Unit tests for tools/*.py (offline)."""

import importlib.util
import ipaddress
import json
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_tool(name):
    """Import tools/<name>.py as a module."""
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "tools", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestGenProxyRules(unittest.TestCase):
    def setUp(self):
        self.t = load_tool("gen_proxy_rules")
        self.domains = self.t.load_domains(os.path.join(ROOT, "config", "claude-domains.txt"))

    def test_domain_list_basics(self):
        self.assertIn("anthropic.com", self.domains)
        self.assertIn("claude.ai", self.domains)
        self.assertEqual(len(self.domains), len(set(self.domains)))

    def test_load_domains_handles_comments_and_dupes(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# c\nA.com\n.b.com  # x\n\na.com\n")
        try:
            self.assertEqual(self.t.load_domains(f.name), ["a.com", "b.com"])
        finally:
            os.unlink(f.name)

    def test_every_target_contains_every_domain(self):
        for name, gen in self.t.GENERATORS.items():
            out = gen(self.domains, self.t.DEFAULT_POLICY[name])
            for d in self.domains:
                self.assertIn(d, out, "%s missing %s" % (name, d))
            code = [l for l in out.splitlines() if not l.lstrip().startswith(("#", "//"))]
            self.assertFalse([l for l in code if "DIRECT" in l], "%s routes something to DIRECT" % name)

    def test_json_targets_parse(self):
        for name in ("singbox", "xray"):
            out = self.t.GENERATORS[name](self.domains, "p")
            body = "\n".join(l for l in out.splitlines() if not l.startswith("//"))
            json.loads(body)


class TestGenCnIpv4(unittest.TestCase):
    def test_parse_delegated(self):
        t = load_tool("gen_cn_ipv4")
        lines = ["2|apnic|20000101|...",
                 "apnic|CN|ipv4|1.0.1.0|768|20110414|allocated",   # 768 = /24 + /23
                 "apnic|CN|ipv4|1.0.8.0|2048|20110412|assigned",
                 "apnic|JP|ipv4|1.0.16.0|4096|20110412|allocated",  # other country
                 "apnic|CN|ipv6|2001:250::|35|20000426|allocated",  # ipv6 ignored
                 "apnic|CN|ipv4|1.0.32.0|8192|20110412|reserved"]   # not allocated/assigned
        nets = t.parse_delegated(lines, "CN")
        self.assertEqual([str(n) for n in nets], ["1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/21"])
        self.assertEqual(sum(n.num_addresses for n in nets), 768 + 2048)
        self.assertTrue(all(isinstance(n, ipaddress.IPv4Network) for n in nets))


class TestAnthropicRanges(unittest.TestCase):
    """config/anthropic-ranges.txt and tools/update_anthropic_ranges.py (offline parts)."""

    def setUp(self):
        self.t = load_tool("update_anthropic_ranges")

        def no_network(*a, **k):
            raise AssertionError("test tried to use the network")
        self.t.fetch_json = no_network

    def test_nat64_mapping(self):
        n = self.t.nat64(ipaddress.ip_network("160.79.104.0/23"))
        self.assertEqual(str(n), "64:ff9b::a04f:6800/119")
        self.assertIn(ipaddress.ip_address("64:ff9b::160.79.104.10"), n)

    def test_config_contains_nat64_of_every_ipv4_prefix(self):
        with open(os.path.join(ROOT, "config", "anthropic-ranges.txt"), encoding="utf-8") as f:
            nets = [ipaddress.ip_network(l.strip()) for l in f if l.strip() and not l.startswith("#")]
        for n in (n for n in nets if n.version == 4):
            self.assertIn(self.t.nat64(n), nets)

    def test_refuses_without_proxy(self):
        saved = {k: os.environ.pop(k) for k in ("HTTPS_PROXY", "https_proxy") if k in os.environ}
        try:
            with self.assertRaises(SystemExit) as cm:
                with open(os.devnull, "w") as devnull:
                    import contextlib
                    with contextlib.redirect_stderr(devnull):
                        self.t.main([])
            self.assertEqual(cm.exception.code, 2)
        finally:
            os.environ.update(saved)

    def test_write_refuses_empty_or_shrinking_answer(self):
        tmp = tempfile.mkdtemp()
        out = os.path.join(tmp, "ranges.txt")
        with open(out, "w") as f:
            f.write("# header\n160.79.104.0/23\n2607:6bc0::/48\n")
        self.t.OUT = out
        self.t.resolve_a = lambda name: []
        saved_proxy = os.environ.get("HTTPS_PROXY")
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:9"  # never used: every lookup is stubbed
        try:
            for answer in ([], [ipaddress.ip_network("160.79.104.0/23")]):
                self.t.announced_prefixes = lambda asn, a=answer: a
                with open(os.devnull, "w") as devnull:
                    import contextlib
                    with contextlib.redirect_stdout(devnull):
                        self.assertEqual(self.t.main(["--write"]), 1)
                with open(out) as f:
                    self.assertIn("2607:6bc0::/48", f.read())
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
            if saved_proxy is None:
                os.environ.pop("HTTPS_PROXY", None)
            else:
                os.environ["HTTPS_PROXY"] = saved_proxy


if __name__ == "__main__":
    unittest.main()
