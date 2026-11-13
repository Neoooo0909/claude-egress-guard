"""Unit tests for guard/egress_guard.py — no network access: every network helper is patched."""

import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_guard(config_dir, cache_dir):
    """Import egress_guard with CEG_CONFIG_DIR / CEG_CACHE_DIR pointing at temp dirs."""
    os.environ["CEG_CONFIG_DIR"] = config_dir
    os.environ["CEG_CACHE_DIR"] = cache_dir
    spec = importlib.util.spec_from_file_location("egress_guard_under_test",
                                                  os.path.join(ROOT, "guard", "egress_guard.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class GuardTestCase(unittest.TestCase):
    """Fresh module + temp config/cache dirs per test."""

    PROXY_ENV = ("NO_PROXY", "no_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                 "CEG_GATE_FRESH")

    def setUp(self):
        self.saved_env = {k: os.environ.pop(k) for k in self.PROXY_ENV if k in os.environ}
        self.tmp = tempfile.mkdtemp()
        self.cfg = os.path.join(self.tmp, "cfg")
        self.cache = os.path.join(self.tmp, "cache")
        os.makedirs(self.cfg)
        self.g = load_guard(self.cfg, self.cache)

    def tearDown(self):
        for k in self.PROXY_ENV:
            os.environ.pop(k, None)
        os.environ.update(self.saved_env)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_cfg(self, name, text):
        """Write a file into the temp config dir."""
        with open(os.path.join(self.cfg, name), "w", encoding="utf-8") as f:
            f.write(text)

    def run_gate(self):
        """Run gate() and return its exit code; stderr is captured."""
        with mock.patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit) as cm:
            self.g.gate()
        return cm.exception.code


class TestHelpers(GuardTestCase):
    def test_parse_trace(self):
        ip, loc = self.g.parse_trace("fl=1\nh=api.anthropic.com\nip=203.0.113.10\nloc=US\n")
        self.assertEqual((ip, loc), ("203.0.113.10", "US"))

    def test_expected_ips_comments(self):
        self.write_cfg("expected-egress.txt", "# header\n203.0.113.10  # exit\n\n198.51.100.1\n")
        self.assertEqual(self.g.load_expected_ips(), {"203.0.113.10", "198.51.100.1"})

    def test_expected_ips_missing(self):
        self.assertEqual(self.g.load_expected_ips(), set())

    def test_is_local(self):
        for ip in ("127.0.0.1", "192.168.1.5", "100.100.100.100", "fe80::1", "::1", "10.2.3.4"):
            self.assertTrue(self.g.is_local(ip), ip)
        for ip in ("203.0.113.10", "8.8.8.8", "2001:db8::1", "not-an-ip"):
            self.assertFalse(self.g.is_local(ip), ip)

    def test_domestic_bisect_with_non_ascii_header(self):
        self.write_cfg("domestic-ipv4.txt", "# 国内 IPv4 header (non-ASCII on purpose)\n"
                                            "198.51.100.0/24\n192.0.2.0/25\n")
        self.assertTrue(self.g.ip_is_domestic("198.51.100.77"))
        self.assertTrue(self.g.ip_is_domestic("192.0.2.5"))
        self.assertFalse(self.g.ip_is_domestic("192.0.2.200"))
        self.assertFalse(self.g.ip_is_domestic("203.0.113.1"))
        self.assertIsNone(self.g.ip_is_domestic("2001:db8::1"))

    def test_domestic_missing_list_is_unknown(self):
        self.assertIsNone(self.g.ip_is_domestic("198.51.100.77"))

    def test_cache_path_is_per_proxy_and_host(self):
        a = self.g.cache_path("http://127.0.0.1:7890", "api.anthropic.com")
        b = self.g.cache_path("http://127.0.0.1:7890", "api.example.com")
        self.assertNotEqual(a, b)
        self.assertEqual(a, self.g.cache_path("http://127.0.0.1:7890", "api.anthropic.com"))

    def test_save_json_creates_directory(self):
        path = os.path.join(self.tmp, "new", "dir", "x.json")
        self.g.save_json(path, {"k": 1})
        self.assertEqual(self.g.load_json(path), {"k": 1})

    def test_proxy_url_gets_scheme(self):
        os.environ["HTTPS_PROXY"] = "127.0.0.1:7890"
        self.assertEqual(self.g.proxy_url(), "http://127.0.0.1:7890")

    def test_redact_credentials(self):
        self.assertEqual(self.g.redact("http://user:secret@127.0.0.1:7890"), "http://127.0.0.1:7890")
        self.assertEqual(self.g.redact("http://127.0.0.1:7890"), "http://127.0.0.1:7890")

    def test_bad_int_env_falls_back(self):
        os.environ["CEG_GATE_FRESH"] = "not-a-number"
        g = load_guard(self.cfg, self.cache)
        self.assertEqual(g.GATE_FRESH_SEC, 60)

    def test_forced_proxy_ignores_no_proxy(self):
        os.environ["NO_PROXY"] = "*"
        import urllib.request
        req = urllib.request.Request("https://api.anthropic.com/cdn-cgi/trace")
        handler = self.g._ForcedProxyHandler({"https": "http://127.0.0.1:9"})
        handler.proxy_open(req, "http://127.0.0.1:9", "https")
        # https through a proxy = CONNECT tunnel: urllib connects to the proxy, tunnels to the origin
        self.assertEqual(req.host, "127.0.0.1:9")
        self.assertEqual(getattr(req, "_tunnel_host", None), "api.anthropic.com")
        # the stock handler would have bypassed the proxy here and connected directly
        stock = urllib.request.Request("https://api.anthropic.com/cdn-cgi/trace")
        urllib.request.ProxyHandler({"https": "http://127.0.0.1:9"}).proxy_open(stock, "http://127.0.0.1:9", "https")
        self.assertEqual(stock.host, "api.anthropic.com")
        self.assertIsNone(getattr(stock, "_tunnel_host", None))

    def test_no_proxy_bypass_detection(self):
        cases = {"*": True, "localhost,*": True, "localhost, *": True, ".anthropic.com": True,
                 "*.anthropic.com": True, "anthropic.com": True, "api.anthropic.com:443": True,
                 "localhost,127.0.0.1,::1": False, "notanthropic.com": False, "192.168.0.0/16": False}
        for value, expected in cases.items():
            os.environ["no_proxy"] = value
            self.assertEqual(self.g.no_proxy_bypasses("api.anthropic.com"), expected, value)
        os.environ.pop("no_proxy")

    def test_valid_ip(self):
        self.assertEqual(self.g.valid_ip(" 203.0.113.10\n"), "203.0.113.10")
        self.assertEqual(self.g.valid_ip("2001:DB8::1"), "2001:db8::1")
        for bad in ("", None, "<html>blocked</html>", "203.0.113.999"):
            self.assertIsNone(self.g.valid_ip(bad))

    def test_parse_trace_rejects_non_ip(self):
        self.assertEqual(self.g.parse_trace("ip=not-an-ip\nloc=US\n"), (None, "US"))

    def test_domestic_skips_malformed_lines(self):
        self.write_cfg("domestic-ipv4.txt", "198.51.100.0/24\n999.1.1.1/8\n192.0.2.0/25\n")
        self.assertTrue(self.g.ip_is_domestic("192.0.2.5"))


class TestGate(GuardTestCase):
    PROXY = "http://127.0.0.1:7890"

    def patch_net(self, proxy=PROXY, alive=True, trace="ip=203.0.113.10\nloc=US\n", real="198.51.100.7"):
        """Patch proxy discovery and HTTP calls: trace URL → `trace` (or raise), echo → `real`."""
        def fake_get_text(opener, url, attempts=2, timeout=10):
            if url == self.g.TRACE_URL:
                if isinstance(trace, Exception):
                    raise trace
                return trace
            return real
        return [mock.patch.object(self.g, "proxy_url", return_value=proxy),
                mock.patch.object(self.g, "proxy_alive", return_value=alive),
                mock.patch.object(self.g, "get_text", side_effect=fake_get_text)]

    def gate_with(self, **kw):
        """Run gate() under patch_net(**kw)."""
        patches = self.patch_net(**kw)
        for p in patches:
            p.start()
        try:
            return self.run_gate()
        finally:
            for p in patches:
                p.stop()

    def test_no_proxy_blocks(self):
        self.assertEqual(self.gate_with(proxy=""), 2)

    def test_dead_proxy_blocks(self):
        self.assertEqual(self.gate_with(alive=False), 2)

    def test_unmeasurable_exit_blocks(self):
        self.write_cfg("expected-egress.txt", "203.0.113.10\n")
        self.assertEqual(self.gate_with(trace=OSError("timeout")), 2)

    def test_exit_equal_real_ip_blocks(self):
        self.assertEqual(self.gate_with(trace="ip=198.51.100.7\nloc=CN\n", real="198.51.100.7"), 2)

    def test_unexpected_exit_blocks(self):
        self.write_cfg("expected-egress.txt", "203.0.113.99\n")
        self.assertEqual(self.gate_with(), 2)

    def test_expected_exit_passes(self):
        self.write_cfg("expected-egress.txt", "203.0.113.10\n")
        self.assertEqual(self.gate_with(), 0)

    def test_no_expected_list_but_real_ip_differs_passes(self):
        self.assertEqual(self.gate_with(), 0)

    def test_disable_flag_passes_without_network(self):
        self.write_cfg("gate-off", "")
        self.assertEqual(self.gate_with(proxy=""), 0)

    def test_internal_error_fails_closed(self):
        with mock.patch.object(self.g, "current_api_host", side_effect=RuntimeError("boom")), \
                mock.patch.object(self.g, "proxy_url", return_value=self.PROXY), \
                mock.patch.object(self.g, "proxy_alive", return_value=True), \
                mock.patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit) as cm:
            self.g.main(["gate"])
        self.assertEqual(cm.exception.code, 2)

    def test_unknown_mode_fails_closed(self):
        with mock.patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit) as cm:
            self.g.main(["gaet"])
        self.assertEqual(cm.exception.code, 2)

    def test_no_proxy_bypassing_anthropic_blocks(self):
        os.environ["NO_PROXY"] = "localhost,*"
        self.assertEqual(self.gate_with(), 2)
        os.environ["NO_PROXY"] = "localhost,.anthropic.com"
        self.assertEqual(self.gate_with(), 2)

    def test_no_proxy_exempting_telemetry_blocks(self):
        for entry in (".datadoghq.com", "Growthbook.io", "mcp-proxy.anthropic.com", ".com"):
            os.environ["NO_PROXY"] = "localhost," + entry
            self.assertEqual(self.gate_with(), 2, entry)

    def test_non_ip_echo_is_not_a_real_ip_reading(self):
        # captive portal / error page instead of an IP, and no expected list → cannot judge
        self.assertEqual(self.gate_with(real="<html>login</html>"), 2)

    def test_family_mismatch_without_expected_list_blocks(self):
        self.assertEqual(self.gate_with(trace="ip=2001:db8::10\nloc=US\n"), 2)
        self.write_cfg("expected-egress.txt", "2001:db8::10\n")
        self.assertEqual(self.gate_with(trace="ip=2001:db8::10\nloc=US\n"), 0)

    def test_harmless_no_proxy_passes(self):
        os.environ["NO_PROXY"] = "localhost,127.0.0.1,::1,192.168.0.0/16"
        self.assertEqual(self.gate_with(), 0)

    def test_slow_measurement_hits_deadline(self):
        import time as _t

        def slow(*a, **k):
            _t.sleep(3)
            return "ip=203.0.113.10\nloc=US\n"
        with mock.patch.object(self.g, "GATE_DEADLINE_SEC", 2), \
                mock.patch.object(self.g, "proxy_url", return_value=self.PROXY), \
                mock.patch.object(self.g, "proxy_alive", return_value=True), \
                mock.patch.object(self.g, "get_text", side_effect=slow):
            started = _t.time()
            self.assertEqual(self.run_gate(), 2)
            self.assertLess(_t.time() - started, 2.5)

    def test_unreadable_expected_file_fails_closed(self):
        os.makedirs(os.path.join(self.cfg, "expected-egress.txt"))  # a directory: exists, unreadable as file
        patches = self.patch_net()
        for p in patches:
            p.start()
        try:
            with mock.patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit) as cm:
                self.g.main(["gate"])
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(cm.exception.code, 2)

    def test_fresh_cache_is_used_without_network(self):
        self.write_cfg("expected-egress.txt", "203.0.113.10\n")
        path = self.g.cache_path(self.PROXY, "api.anthropic.com")
        self.g.save_json(path, {"anthropic_ip": "203.0.113.10", "real_ip": "198.51.100.7",
                                "fetched_at": int(__import__("time").time())})
        with mock.patch.object(self.g, "proxy_url", return_value=self.PROXY), \
                mock.patch.object(self.g, "proxy_alive", return_value=True), \
                mock.patch.object(self.g, "get_text", side_effect=AssertionError("network used")):
            self.assertEqual(self.run_gate(), 0)


class TestStatusAndScan(GuardTestCase):
    def test_status_without_proxy_alerts(self):
        with mock.patch.object(self.g, "proxy_url", return_value=""), \
                mock.patch.object(self.g, "_spawn"):
            alert, text = self.g.status_text()
        self.assertTrue(alert)
        self.assertTrue(text.startswith("! no proxy"))

    def setUp(self):
        super().setUp()
        self.g.PF_STATS_PATH = os.path.join(self.tmp, "pf-stats.json")  # never the real system file

    def ok_cache(self, proxy):
        """Write a fresh, healthy probe cache for `proxy`."""
        now = int(__import__("time").time())
        self.g.save_json(self.g.cache_path(proxy, "api.anthropic.com"),
                         {"attempt_at": now, "fetched_at": now, "anthropic_ip": "203.0.113.10",
                          "anthropic_loc": "US", "real_ip": "198.51.100.7"})

    @unittest.skipUnless(sys.platform == "darwin", "pf status is macOS-only")
    def test_status_alerts_when_pf_kill_switch_inactive(self):
        proxy = "http://127.0.0.1:7890"
        self.ok_cache(proxy)
        now = int(__import__("time").time())
        with open(self.g.PF_STATS_PATH, "w") as f:
            json.dump({"blocked_total": 0, "anthropic_total": 0, "anchor_active": False, "updated_at": now}, f)
        with mock.patch.object(self.g, "proxy_url", return_value=proxy), \
                mock.patch.object(self.g, "proxy_alive", return_value=True), \
                mock.patch.object(self.g, "_spawn"):
            alert, text = self.g.status_text()
        self.assertTrue(alert)
        self.assertTrue(text.startswith("! pf kill switch inactive"), text)

    def test_status_ok(self):
        proxy = "http://127.0.0.1:7890"
        path = self.g.cache_path(proxy, "api.anthropic.com")
        now = int(__import__("time").time())
        self.g.save_json(path, {"attempt_at": now, "fetched_at": now, "anthropic_ip": "203.0.113.10",
                                "anthropic_loc": "US", "real_ip": "198.51.100.7"})
        with mock.patch.object(self.g, "proxy_url", return_value=proxy), \
                mock.patch.object(self.g, "proxy_alive", return_value=True), \
                mock.patch.object(self.g, "_spawn"):
            alert, text = self.g.status_text()
        self.assertFalse(alert)
        self.assertIn("exit 203.0.113.10 US", text)

    def test_scan_classification(self):
        self.write_cfg("domestic-ipv4.txt", "198.51.100.0/24\n")
        conns = [(10, "a", "203.0.113.5", "443", "TCP"),   # main → foreign: counted
                 (11, "b", "198.51.100.9", "443", "TCP"),  # child → domestic: logged only
                 (10, "c", "198.51.100.9", "80", "TCP"),   # main → domestic: counted
                 (11, "d", "127.0.0.1", "7890", "TCP")]    # proxy: ignored
        with mock.patch.object(self.g, "list_connections", return_value=conns):
            found = dict((e["remote"] + "/" + str(e["pid"]), e) for _, e in self.g.scan({10: "claude", 11: "curl"}, {10}))
        self.assertEqual(found["203.0.113.5:443/10"]["type"], "direct_foreign")
        self.assertEqual(found["198.51.100.9:443/11"]["type"], "direct_domestic_child")
        self.assertFalse(found["198.51.100.9:443/11"]["counted"])
        self.assertEqual(found["198.51.100.9:80/10"]["type"], "direct_main")
        self.assertEqual(len(found), 3)


if __name__ == "__main__":
    unittest.main()
