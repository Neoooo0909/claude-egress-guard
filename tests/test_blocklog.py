"""Offline tests for macos/pf/blocklog.py (parsing, attribution, merging, log writing) and
macos/pf/blocked.py (report). No tcpdump, lsof or network: lookups are stubbed."""
import importlib.util
import json
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name, rel):
    """Import a script by path under a unique module name."""
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = load("ceg_blocklog", "macos/pf/blocklog.py")
bd = load("ceg_blocked", "macos/pf/blocked.py")

PFLOG_TCP = ("2026-01-02 03:04:05.123456 rule 0.250.ClaudeEgres.8/0(match): block out on en0: "
             "192.168.1.20.50127 > 140.82.112.3.443: Flags [S], seq 1, win 65535, length 0")
PFLOG_UDP = ("2026-01-02 03:04:05.300000 rule 0.250.ClaudeEgres.9/0(match): block out on en0: "
             "192.168.1.20.59674 > 8.8.8.8.443: quic, protected [|quic]")
PFLOG_ANTH = ("2026-01-02 03:04:06.000001 rule 0.250.ClaudeEgres.0/0(match): block out on en0: "
              "192.168.1.20.51111 > 160.79.104.10.443: Flags [S], seq 1, length 0")
NOISE = "2026-01-02 03:04:05.000000 rule 4294967295/8(ip-option): pass in on en0: 192.168.1.1 > 224.0.0.1: igmp query v2"
OTHER_ANCHOR = PFLOG_TCP.replace("0.250.ClaudeEgres.8/0", "0.300.SomeVPNKill.2/0")


class BlocklogTest(unittest.TestCase):
    def setUp(self):
        for d in (bl.pending, bl.ip_names, bl.dns_txids, bl.rst_procs, bl.port_procs):
            d.clear()
        while not bl.lsof_queue.empty():
            bl.lsof_queue.get_nowait()
        self.tmp = tempfile.mkdtemp()
        self.log = os.path.join(self.tmp, "blocked.jsonl")
        self._saved = (bl.LOG_PATH, bl.executable, bl.LOG_MAX_BYTES, bl.PENDING_MAX)
        bl.LOG_PATH = self.log
        bl.executable = lambda proc: "/usr/bin/" + proc.split(":")[0]

    def tearDown(self):
        bl.LOG_PATH, bl.executable, bl.LOG_MAX_BYTES, bl.PENDING_MAX = self._saved

    def records(self):
        with open(self.log, encoding="utf-8") as f:
            return [json.loads(x) for x in f]

    def test_pflog_parsing_and_kinds(self):
        self.assertEqual(bl.ANCHOR_TAG, ".250.ClaudeEgres.")  # pflog truncates the name to 15 chars
        for line in (PFLOG_TCP, PFLOG_UDP, PFLOG_ANTH, NOISE, OTHER_ANCHOR, "garbage"):
            bl.handle_pflog_line(line)
        self.assertEqual(set(bl.pending), {("direct", "tcp", "140.82.112.3", 443),
                                           ("direct", "udp", "8.8.8.8", 443),
                                           ("anthropic", "tcp", "160.79.104.10", 443)})
        self.assertEqual(bl.lsof_queue.qsize(), 1)  # lsof only for UDP (TCP is attributed by the RST)

    def test_flood_is_merged(self):
        bl.PENDING_MAX = 2
        for port in range(10):
            bl.handle_pflog_line(PFLOG_ANTH.replace(".10.443:", f".10.{1000 + port}:"))
        self.assertEqual(len(bl.pending), 3)
        self.assertEqual(bl.pending[("anthropic", "tcp", "*", 0)]["n"], 8)

    def test_dns_answers_only_for_seen_queries(self):
        bl.handle_pktap_line("2026-01-02 03:04:04.1 (en0, proc mDNSResponder:1, eproc curl:9, svc BE, out) "
                             "IP 192.168.1.20.5000 > 192.168.1.1.53: 4242+ [1au] A? github.com. (39)")
        bl.handle_pktap_line("2026-01-02 03:04:04.2 (en0, svc BE, in) "
                             "IP 192.168.1.1.53 > 192.168.1.20.5000: 4242 2/0/1 CNAME gh.example., A 140.82.112.3 (55)")
        bl.handle_pktap_line("2026-01-02 03:04:04.3 (utun4, svc BE, in) IP6 fd7a::53.53 > fd7a::2.6000: "
                             "777 2/0/0 CNAME edge.example.net., AAAA 2001:db8::1 (90)")   # no matching query
        bl.handle_pktap_line("2026-01-02 03:04:04.4 (en0, svc BE, in) "                  # same txid, other port
                             "IP 192.168.1.1.53 > 192.168.1.20.5001: 4242 1/0/0 A 198.51.100.7 (40)")
        self.assertEqual(bl.ip_names["140.82.112.3"][:2], ("github.com", "dns"))
        self.assertNotIn("2001:db8::1", bl.ip_names)
        self.assertNotIn("198.51.100.7", bl.ip_names)

    def test_rst_attribution_inbound_only(self):
        bl.handle_pktap_line("2026-01-02 03:04:05.2 (lo0, svc BE, out) IP 140.82.112.3.443 > "
                             "192.168.1.20.50127: Flags [R.], seq 0, ack 1, win 0, length 0")
        self.assertEqual(bl.rst_procs, {})
        bl.handle_pktap_line("2026-01-02 03:04:05.2 (lo0, proc curl:777, svc BE, in, so) IP 140.82.112.3.443 > "
                             "192.168.1.20.50127: Flags [R.], seq 0, ack 1, win 0, length 0")
        self.assertEqual(bl.rst_procs[("50127", "140.82.112.3", "443")][0], "curl:777")
        self.assertEqual(bl.parse_meta("en0, proc a:1, eproc b:2, svc BE, out"), ("b:2", "out"))
        self.assertEqual(bl.parse_meta("lo0, proc :0, eproc :0, svc BE, out"), (None, "out"))
        # a process name containing ")" still parses
        bl.handle_pktap_line("2026-01-02 03:04:05.3 (lo0, proc odd)name:5, svc BE, in, so) IP 140.82.112.3.443 > "
                             "192.168.1.20.50130: Flags [R.], seq 0, ack 1, win 0, length 0")
        self.assertEqual(bl.rst_procs[("50130", "140.82.112.3", "443")][0], "odd)name:5")

    def test_flush_records_with_attribution_and_merge(self):
        bl.ip_names["140.82.112.3"] = ("github.com", "dns", 0)
        bl.rst_procs[("50127", "140.82.112.3", "443")] = ("curl:777", 0)
        bl.port_procs[("udp", "59674")] = ("Python:888", 0)
        for line in (PFLOG_TCP, PFLOG_UDP, PFLOG_ANTH, PFLOG_ANTH.replace(".51111 >", ".51112 >")):
            bl.handle_pflog_line(line)
        bl.flush_due(force=True)
        recs = {r["dst"]: r for r in self.records()}
        self.assertEqual((recs["140.82.112.3"]["domain"], recs["140.82.112.3"]["proc"],
                          recs["140.82.112.3"]["proc_src"]), ("github.com", "curl:777", "rst"))
        self.assertEqual(recs["140.82.112.3"]["exe"], "/usr/bin/curl")
        self.assertEqual((recs["8.8.8.8"]["domain"], recs["8.8.8.8"]["proc_src"]), (None, "lsof"))  # no PTR
        a = recs["160.79.104.10"]
        self.assertEqual((a["kind"], a["n"], a["domain"]), ("anthropic", 2, None))  # merged, never PTR'd
        self.assertNotIn("cmd", a)
        # a later packet starts a new window whose ts is that packet's time
        bl.handle_pflog_line(PFLOG_TCP.replace("03:04:05.123456", "03:05:30.000000"))
        bl.flush_due(force=True)
        last = self.records()[-1]
        self.assertEqual((last["ts"], last["n"]), ("2026-01-02 03:05:30", 1))
        # keys without new packets are dropped at their next due time
        bl.flush_due(force=True)
        self.assertEqual(len(bl.pending), 0)

    def test_write_rotation(self):
        bl.LOG_MAX_BYTES = 5            # the first line (9 bytes) already exceeds it
        bl.write_records([{"a": 1}])
        bl.write_records([{"b": 2}])
        self.assertTrue(os.path.exists(self.log + ".1"))
        self.assertEqual(self.records(), [{"b": 2}])
        self.assertEqual(oct(os.stat(self.log).st_mode & 0o777), "0o640")

    def test_ranges_from_rules_file(self):
        p = os.path.join(self.tmp, "rules.conf")
        with open(p, "w") as f:
            f.write("table <ceg_anthropic> const { 198.51.100.0/24, 2001:db8::/32 }\nblock return out log quick ...\n")
        self.assertEqual([str(n) for n in bl.load_anthropic_nets(p)], ["198.51.100.0/24", "2001:db8::/32"])
        self.assertEqual(len(bl.load_anthropic_nets(os.path.join(self.tmp, "missing"))), 3)


class BlockedReportTest(unittest.TestCase):
    def test_summary(self):
        recs = [
            {"ts": "2026-01-02 03:04:05", "last": "2026-01-02 03:04:05", "n": 3, "kind": "direct", "proto": "udp",
             "dst": "8.8.8.8", "port": 443, "domain": "dns.google", "proc": None},
            {"ts": "2026-01-02 03:04:06", "last": "2026-01-02 03:04:09", "n": 2, "kind": "anthropic", "proto": "tcp",
             "dst": "160.79.104.10", "port": 443, "domain": None, "proc": "node:12", "exe": "/usr/local/bin/node"},
        ]
        out = "\n".join(bd.summarize(recs))
        self.assertIn("5 packets blocked (Anthropic 2, direct 3)", out)
        self.assertIn("160.79.104.10 [tcp/443] | node | 2 | 01-02 03:04:09  ! Anthropic", out)
        self.assertIn("3 packets have no process", out)
        self.assertNotIn("last 0 records", "\n".join(bd.summarize(recs, tail=0)))
        self.assertFalse([l for l in bd.summarize(recs, tail=0) if " x3" in l or " x2" in l])  # no records
        recs[0]["domain"] = "evil\x1b[2Jname"
        self.assertNotIn("\x1b", "\n".join(bd.summarize(recs)))

    def test_load_filters_by_date_and_reads_rotated(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "blocked.jsonl")
        with open(p + ".1", "w") as f:
            f.write(json.dumps({"ts": "2026-01-01 23:59:59", "n": 1}) + "\n")
            f.write(json.dumps({"ts": "2026-01-02 00:00:01", "n": 1}) + "\n")
        with open(p, "w") as f:
            f.write("not json\n" + json.dumps({"ts": "2026-01-02 08:00:00", "n": 1}) + "\n")
        self.assertEqual([r["ts"] for r in bd.load("2026-01-02", p)], ["2026-01-02 00:00:01", "2026-01-02 08:00:00"])


if __name__ == "__main__":
    unittest.main()
