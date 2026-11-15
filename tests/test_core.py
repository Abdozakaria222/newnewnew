"""Automated tests (stdlib unittest — run with:  python -m unittest discover -s tests -v)."""
import json
import os
import random
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("NETOPT_DATA_DIR", tempfile.mkdtemp(prefix="netopt-test-"))

from netoptimizer.core import (apply, compare, dns_bench, dnswire, icmp, monitor, mtu,  # noqa: E402
                               netinfo, stats)
from netoptimizer.core.backup import BackupStore  # noqa: E402
from netoptimizer.core.icmp import Probe  # noqa: E402
from netoptimizer.core.jobs import Cancelled, JobManager  # noqa: E402
from netoptimizer.core.profiles import ProfileStore  # noqa: E402
from netoptimizer.core.providers import Provider, ProviderDB, ProviderError  # noqa: E402
from netoptimizer.core.settings import Settings, defaults  # noqa: E402


# ------------------------------------------------------------------ fake DNS server
class FakeDNS:
    """Real UDP DNS server on 127.0.0.1 used to test the wire protocol."""

    def __init__(self, delay=0.0, rcode=0, drop=False, spoof_first=False):
        self.delay, self.rcode, self.drop, self.spoof_first = delay, rcode, drop, spoof_first
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.received = 0
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(2048)
            except OSError:
                return
            self.received += 1
            if self.drop:
                continue
            time.sleep(self.delay)
            txid, q = data[:2], data[12:]
            qtype = struct.unpack(">H", q[q.index(b"\x00") + 1:q.index(b"\x00") + 3])[0]
            if self.spoof_first:
                bad = bytes([txid[0] ^ 0xFF, txid[1]]) + data[2:]
                self.sock.sendto(bad, addr)
            if qtype == dnswire.TYPE_AAAA:
                rr = b"\xc0\x0c" + struct.pack(">HHIH", 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
            elif qtype == dnswire.TYPE_TXT:
                rr = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, 8) + b"\x071.2.3.4"
            else:
                rr = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
            an = 0 if self.rcode else 1
            resp = txid + struct.pack(">HHHHH", 0x8180 | self.rcode, 1, an, 0, 0) + q + (b"" if self.rcode else rr)
            self.sock.sendto(resp, addr)

    def close(self):
        self.sock.close()


class TestDnsWire(unittest.TestCase):
    def test_real_query_a_aaaa_txt(self):
        srv = FakeDNS(delay=0.01)
        r = dnswire.query("127.0.0.1", "example.com", dnswire.TYPE_A, 2, port=srv.port)
        self.assertTrue(r.ok)
        self.assertEqual(r.answers, ["93.184.216.34"])
        self.assertGreaterEqual(r.latency_ms, 9)
        r6 = dnswire.query("127.0.0.1", "example.com", dnswire.TYPE_AAAA, 2, port=srv.port)
        self.assertEqual(r6.answers, ["2001:db8::1"])
        rt = dnswire.query("127.0.0.1", "x.example", dnswire.TYPE_TXT, 2, port=srv.port)
        self.assertEqual(rt.answers, ["1.2.3.4"])
        srv.close()

    def test_timeout(self):
        srv = FakeDNS(drop=True)
        r = dnswire.query("127.0.0.1", "example.com", dnswire.TYPE_A, 0.3, port=srv.port)
        self.assertFalse(r.ok)
        self.assertTrue(r.timeout)
        srv.close()

    def test_nxdomain_is_success_servfail_is_not(self):
        srv = FakeDNS(rcode=3)
        self.assertTrue(dnswire.query("127.0.0.1", "nope.example", 1, 2, port=srv.port).ok)
        srv.close()
        srv = FakeDNS(rcode=2)
        r = dnswire.query("127.0.0.1", "x.example", 1, 2, port=srv.port)
        self.assertFalse(r.ok)
        self.assertEqual(r.error, "SERVFAIL")
        srv.close()

    def test_spoofed_reply_ignored(self):
        srv = FakeDNS(spoof_first=True)
        r = dnswire.query("127.0.0.1", "example.com", 1, 2, port=srv.port)
        self.assertTrue(r.ok)
        srv.close()

    def test_bad_name(self):
        with self.assertRaises(ValueError):
            dnswire.encode_name("a" * 64 + ".com")


class TestStats(unittest.TestCase):
    def test_percentiles(self):
        xs = list(range(1, 101))
        self.assertAlmostEqual(stats.median(xs), 50.5)
        self.assertAlmostEqual(stats.percentile(xs, 95), 95.05)
        self.assertIsNone(stats.median([]))

    def test_mann_whitney(self):
        rng = random.Random(1)
        a = [rng.gauss(20, 2) for _ in range(40)]
        b = [rng.gauss(30, 2) for _ in range(40)]
        self.assertLess(stats.mann_whitney_p(a, b), 0.001)
        c = [rng.gauss(20, 2) for _ in range(40)]
        self.assertGreater(stats.mann_whitney_p(a, c), 0.05)

    def test_two_proportion(self):
        self.assertLess(stats.two_proportion_p(100, 100, 70, 100), 0.001)
        self.assertGreater(stats.two_proportion_p(99, 100, 98, 100), 0.05)


def make_query_fn(latency: dict, fail_rate: dict = None, seed=3):
    rng = random.Random(seed)
    fail_rate = fail_rate or {}

    def q(server, name, qtype, timeout):
        if rng.random() < fail_rate.get(server, 0):
            return dnswire.DnsResult(server, name, qtype, False, None, error="timeout")
        base = latency[server] * (3 if name.count(".") >= 2 and len(name.split(".")[0]) == 12 else 1)
        return dnswire.DnsResult(server, name, qtype, True, base * rng.uniform(0.9, 1.2), 0, [])
    return q


class TestDnsBench(unittest.TestCase):
    def setUp(self):
        self.provs = [Provider("a", "A", ["10.0.0.1", "10.0.0.2"]), Provider("b", "B", ["10.0.1.1", "10.0.1.2"]),
                      Provider("c", "C", ["10.0.2.1"]), Provider("system", "Current", ["10.0.3.1"], source="system")]
        self.cfg = defaults()

    def test_picks_fastest_and_documents_reason(self):
        lat = {"10.0.0.1": 40, "10.0.0.2": 41, "10.0.1.1": 15, "10.0.1.2": 16, "10.0.2.1": 25, "10.0.3.1": 60}
        r = dns_bench.run_benchmark(self.provs, "ipv4", self.cfg, query_fn=make_query_fn(lat))
        self.assertEqual(r["recommendation"]["provider"], "b")
        self.assertFalse(r["recommendation"]["keep_current"])
        self.assertTrue(any("Faster than your current DNS" in x for x in r["recommendation"]["reasons"]))
        b = next(p for p in r["providers"] if p["provider"] == "b")
        self.assertGreater(b["metrics"]["uncached"]["median"], b["metrics"]["cached"]["median"])
        self.assertEqual(set(b["score_parts"]), set(dns_bench.WEIGHTS))

    def test_not_always_same_provider(self):
        """The winner follows the measurements, not a fixed preference."""
        lat = {"10.0.0.1": 12, "10.0.0.2": 13, "10.0.1.1": 50, "10.0.1.2": 50, "10.0.2.1": 25, "10.0.3.1": 60}
        r = dns_bench.run_benchmark(self.provs, "ipv4", self.cfg, query_fn=make_query_fn(lat))
        self.assertEqual(r["recommendation"]["provider"], "a")

    def test_unreliable_provider_excluded(self):
        lat = {"10.0.0.1": 40, "10.0.0.2": 41, "10.0.1.1": 5, "10.0.1.2": 5, "10.0.2.1": 25, "10.0.3.1": 60}
        r = dns_bench.run_benchmark(self.provs, "ipv4", self.cfg,
                                    query_fn=make_query_fn(lat, {"10.0.1.1": 0.3}))
        self.assertNotEqual(r["recommendation"]["provider"], "b")
        self.assertFalse(next(p for p in r["providers"] if p["provider"] == "b")["eligible"])

    def test_bad_secondary_replaced(self):
        lat = {"10.0.0.1": 40, "10.0.0.2": 41, "10.0.1.1": 10, "10.0.1.2": 10, "10.0.2.1": 25, "10.0.3.1": 60}
        r = dns_bench.run_benchmark(self.provs, "ipv4", self.cfg,
                                    query_fn=make_query_fn(lat, {"10.0.1.2": 0.5}))
        rec = r["recommendation"]
        self.assertEqual(rec["provider"], "b")
        self.assertEqual(rec["secondary"], "10.0.2.1")

    def test_keep_current_when_within_noise(self):
        lat = {"10.0.0.1": 40, "10.0.0.2": 41, "10.0.1.1": 20, "10.0.1.2": 20, "10.0.2.1": 25, "10.0.3.1": 20.2}
        r = dns_bench.run_benchmark(self.provs, "ipv4", self.cfg, query_fn=make_query_fn(lat))
        self.assertTrue(r["recommendation"]["keep_current"])

    def test_ipv6_family_separate(self):
        provs = [Provider("a", "A", ["10.0.0.1"], ["2001:db8::1"]), Provider("b", "B", ["10.0.1.1"])]
        lat = {"10.0.0.1": 10, "10.0.1.1": 5, "2001:db8::1": 30}
        r = dns_bench.run_benchmark(provs, "ipv6", self.cfg, query_fn=make_query_fn(lat))
        self.assertEqual([s["server"] for s in r["servers"]], ["2001:db8::1"])

    def test_cancellation(self):
        jm = JobManager()
        lat = {"10.0.0.1": 1, "10.0.0.2": 1, "10.0.1.1": 1, "10.0.1.2": 1, "10.0.2.1": 1, "10.0.3.1": 1}
        slow = make_query_fn(lat)

        def q(*a):
            time.sleep(0.01)
            return slow(*a)
        job = jm.start("dns", lambda ctx: dns_bench.run_benchmark(self.provs, "ipv4", self.cfg, ctx, q))
        time.sleep(0.1)
        jm.cancel(job.id)
        for _ in range(100):
            if job.state != "running":
                break
            time.sleep(0.05)
        self.assertEqual(job.state, "cancelled")

    def test_only_one_heavy_job(self):
        jm = JobManager()
        ev = threading.Event()
        jm.start("dns", lambda ctx: ev.wait(2))
        with self.assertRaises(RuntimeError):
            jm.start("mtu", lambda ctx: None)
        ev.set()


def path_prober(path_mtu: dict, silent=False, lossy=None, overhead=28):
    """Simulated network path. path_mtu: dest -> max MTU (None = ICMP filtered)."""
    rng = random.Random(5)
    lossy = lossy or {}

    def probe(dest, payload, df, timeout):
        limit = path_mtu.get(dest)
        if limit is None:
            return Probe("timeout")
        if rng.random() < lossy.get(dest, 0):
            return Probe("timeout")
        size = payload + (48 if ":" in dest else overhead)
        if size <= limit:
            return Probe("ok", 10.0)
        return Probe("timeout") if silent else Probe("frag_needed")
    return probe


class TestMtu(unittest.TestCase):
    def setUp(self):
        self.cfg = defaults()
        self.dests = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    def test_pppoe_1492(self):
        r = mtu.run_mtu(path_prober({d: 1492 for d in self.dests}), self.cfg, "ipv4", self.dests, 1500)
        self.assertEqual(r["path_mtu"], 1492)
        self.assertEqual(r["decision"], "lower")
        self.assertEqual(r["recommended"], 1492)
        self.assertGreaterEqual(r["confidence"], 90)
        self.assertTrue(any("PPPoE" in x for x in r["reasons"]))

    def test_never_lower_when_path_ok(self):
        r = mtu.run_mtu(path_prober({d: 1500 for d in self.dests}), self.cfg, "ipv4", self.dests, 1500)
        self.assertEqual(r["decision"], "keep")
        self.assertEqual(r["recommended"], 1500)

    def test_binary_search_is_efficient(self):
        r = mtu.run_mtu(path_prober({d: 1437 for d in self.dests}), self.cfg, "ipv4", self.dests, 1500)
        self.assertEqual(r["path_mtu"], 1437)
        searches = [s["tests"] for s in r["destinations"].values()]
        self.assertTrue(all(t <= 12 for t in searches), searches)   # log2(220) ~ 8 + endpoints

    def test_icmp_filtered(self):
        r = mtu.run_mtu(path_prober({}), self.cfg, "ipv4", self.dests, 1500)
        self.assertIsNone(r["recommended"])
        self.assertEqual(r["decision"], "no_data")
        self.assertTrue(any("filtered" in x for x in r["reasons"]))

    def test_single_destination_does_not_lower(self):
        r = mtu.run_mtu(path_prober({"1.1.1.1": 1400}), self.cfg, "ipv4", self.dests, 1500)
        self.assertEqual(r["decision"], "keep")
        self.assertEqual(r["recommended"], 1500)
        self.assertLess(r["confidence"], 70)

    def test_destination_specific_outlier_ignored(self):
        r = mtu.run_mtu(path_prober({"1.1.1.1": 1500, "8.8.8.8": 1500, "9.9.9.9": 1400}),
                        self.cfg, "ipv4", self.dests, 1500)
        self.assertEqual(r["path_mtu"], 1500)
        self.assertTrue(any("Destination-specific" in n for n in r["notes"]))

    def test_silent_drop_vs_explicit_fragmentation(self):
        r = mtu.run_mtu(path_prober({d: 1480 for d in self.dests}, silent=True), self.cfg, "ipv4", self.dests, 1500)
        self.assertEqual(r["path_mtu"], 1480)
        self.assertGreater(r["evidence"]["silent_drop"], 0)
        self.assertEqual(r["evidence"]["explicit_frag"], 0)
        r2 = mtu.run_mtu(path_prober({d: 1480 for d in self.dests}), self.cfg, "ipv4", self.dests, 1500)
        self.assertGreater(r2["evidence"]["explicit_frag"], 0)

    def test_unreliable_destination_excluded(self):
        r = mtu.run_mtu(path_prober({d: 1500 for d in self.dests}, lossy={"9.9.9.9": 0.5}),
                        self.cfg, "ipv4", self.dests, 1500)
        self.assertNotIn("9.9.9.9", r["destinations"])

    def test_ipv6_overhead_and_floor(self):
        d6 = ["2001:db8::1", "2001:db8::2"]
        r = mtu.run_mtu(path_prober({d: 1480 for d in d6}), self.cfg, "ipv6", d6, 1500)
        self.assertEqual(r["path_mtu"], 1480)
        self.assertGreaterEqual(r["range"][0], 1280)

    def test_tunnel_interpretation(self):
        r = mtu.run_mtu(path_prober({d: 1420 for d in self.dests}), self.cfg, "ipv4", self.dests, 1500,
                        {"is_vpn": True})
        self.assertTrue(any("WireGuard" in x for x in r["reasons"]))

    def test_final_verification_sizes(self):
        r = mtu.run_mtu(path_prober({d: 1492 for d in self.dests}), self.cfg, "ipv4", self.dests, 1500)
        v = r["verification"]
        self.assertEqual(v["large"]["mtu"], 1492)
        self.assertLess(v["small"]["mtu"], v["medium"]["mtu"])
        self.assertEqual(v["loss_rate"], 0)


class TestIcmpParsing(unittest.TestCase):
    def test_destination_cache(self):
        text = ("Interface 12: Wi-Fi\n\nPMTU Destination Address                           Next Hop Address\n"
                "---- --------------------------------------------- -------------------------\n"
                "1480 2606:4700:4700::1111                          fe80::1\n"
                "1500 2001:4860:4860::8888                          fe80::1\n")
        self.assertEqual(icmp.parse_destination_cache(text, "2606:4700:4700::1111"), 1480)
        self.assertIsNone(icmp.parse_destination_cache(text, "2620:fe::fe"))

    def test_status_map(self):
        self.assertEqual(icmp._map_status(0), "ok")
        self.assertEqual(icmp._map_status(11009), "frag_needed")
        self.assertEqual(icmp._map_status(11010), "timeout")


class TestNetinfo(unittest.TestCase):
    RAW = [
        {"index": 12, "alias": "Wi-Fi", "description": "Intel(R) Wi-Fi 6 AX201", "iftype": 71, "status": "Up",
         "mac": "AA-BB-CC-DD-EE-FF", "ipv4": ["192.168.1.5/24"], "gw4": ["192.168.1.1"], "dns4": ["192.168.1.1"],
         "dhcp4": "Enabled", "mtu4": 1500, "mtu6": 4294967295, "metric4": 35, "guid": "{G1}"},
        {"index": 20, "alias": "Ethernet", "description": "Realtek PCIe GbE", "iftype": 6, "status": "Disconnected",
         "media": "802.3", "mac": "11-22-33-44-55-66", "dns4_static": "1.1.1.1,1.0.0.1", "dhcp4": "Disabled", "mtu4": 1500},
        {"index": 30, "alias": "MyISP", "description": "WAN Miniport (PPPOE)", "status": "Connected",
         "conn4": "Connected", "ipv4": ["41.1.2.3/32"], "gw4": ["0.0.0.0"], "mtu4": 1480, "metric4": 5},
        {"index": 40, "alias": "wg0", "description": "WireGuard Tunnel", "iftype": 131, "status": "Up",
         "ipv4": ["10.8.0.2/24"], "gw4": ["10.8.0.1"], "mtu4": 1420, "metric4": 1},
        {"index": 50, "alias": "vEthernet (Default Switch)", "description": "Hyper-V Virtual Ethernet Adapter",
         "iftype": 6, "virtual": True, "status": "Up", "ipv4": ["172.20.0.1/20"]},
    ]

    def test_classification(self):
        a = [netinfo.classify(r, "HomeWiFi") for r in self.RAW]
        self.assertEqual([x["kind"] for x in a], ["wifi", "ethernet", "pppoe", "vpn", "virtual"])
        self.assertEqual(a[0]["ssid"], "HomeWiFi")
        self.assertIsNone(a[0]["mtu6"])
        self.assertEqual(a[1]["dns4_source"], "static")
        self.assertEqual(a[1]["ip4_source"], "static")
        self.assertFalse(a[1]["up"])

    def test_primary_prefers_physical_over_vpn(self):
        a = [netinfo.classify(r) for r in self.RAW]
        p = netinfo.pick_primary(a)
        self.assertEqual(p["alias"], "MyISP")      # lowest metric non-VPN

    def test_ssid_parse(self):
        out = "    Name : Wi-Fi\n    BSSID : aa:bb\n    SSID                   : My Home 5G\n"
        self.assertEqual(netinfo.parse_ssid(out), "My Home 5G")

    def test_fingerprint_stable_and_distinct(self):
        a = netinfo.classify(self.RAW[0], "Net1")
        b = netinfo.classify(self.RAW[0], "Net2")
        self.assertEqual(netinfo.fingerprint(a), netinfo.fingerprint(netinfo.classify(self.RAW[0], "Net1")))
        self.assertNotEqual(netinfo.fingerprint(a), netinfo.fingerprint(b))

    def test_mask_mac(self):
        self.assertEqual(netinfo.mask_mac("AA-BB-CC-DD-EE-FF"), "AA-BB-CC-XX-XX-XX")


def _snap(ssid="Home", gw="192.168.1.1", vpn_up=False, eth_up=True, dns="192.168.1.1"):
    raws = [dict(TestNetinfo.RAW[0], gw4=[gw], dns4=[dns]),
            dict(TestNetinfo.RAW[1], status="Up" if eth_up else "Disconnected"),
            dict(TestNetinfo.RAW[3], status="Up" if vpn_up else "Disconnected")]
    ad = [netinfo.classify(r, ssid) for r in raws]
    p = ad[0]
    return {"adapters": ad, "primary": p, "fingerprint": netinfo.fingerprint(p)}


class TestMonitor(unittest.TestCase):
    def types(self, a, b):
        return {e["type"] for e in monitor.diff_snapshots(a, b)}

    def test_events(self):
        self.assertIn("wifi_changed", self.types(_snap(), _snap(ssid="Office")))
        self.assertIn("network_profile_changed", self.types(_snap(), _snap(ssid="Office")))
        self.assertIn("gateway_changed", self.types(_snap(), _snap(gw="10.0.0.1")))
        self.assertIn("vpn_connected", self.types(_snap(), _snap(vpn_up=True)))
        self.assertIn("vpn_disconnected", self.types(_snap(vpn_up=True), _snap()))
        self.assertIn("ethernet_reconnected", self.types(_snap(eth_up=False), _snap()))
        self.assertIn("ip_config_changed", self.types(_snap(), _snap(dns="8.8.8.8")))
        self.assertEqual(self.types(_snap(), _snap()), set())

    def test_monitor_only_snapshots_on_signature_change(self):
        calls = {"snap": 0}
        sigs = iter(["a", "a", "a", "b"])

        def snap_fn():
            calls["snap"] += 1
            return _snap(ssid="Office")
        m = monitor.Monitor(lambda: 1, lambda s, e: None, snapshot_fn=snap_fn, signature_fn=lambda: next(sigs))
        m.last_snapshot = _snap()
        m._sig = next(sigs)
        self.assertEqual(m.check_once(), [])
        self.assertEqual(m.check_once(), [])
        ev = m.check_once()
        self.assertEqual(calls["snap"], 1)
        self.assertIn("wifi_changed", {e["type"] for e in ev})
        self.assertIn("dns", ev[0]["rerun"])


class TestProviders(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = ProviderDB(os.path.join(self.dir, "custom.json"))

    def test_builtin_valid(self):
        b = self.db.builtin()
        self.assertGreaterEqual(len(b), 15)
        self.assertEqual(len({p.id for p in b}), len(b))

    def test_custom_add_remove_and_reserved(self):
        self.db.add_custom({"id": "mine", "name": "Mine", "ipv4": ["5.5.5.5", "5.5.5.6"]})
        self.assertIn("mine", {p.id for p in self.db.all()})
        with self.assertRaises(ProviderError):
            self.db.add_custom({"id": "google", "name": "x", "ipv4": ["1.2.3.4"]})
        with self.assertRaises(ProviderError):
            self.db.add_custom({"id": "bad", "name": "x", "ipv4": ["1.2.3"]})
        with self.assertRaises(ProviderError):
            self.db.add_custom({"id": "v6wrong", "name": "x", "ipv6": ["1.2.3.4"]})
        self.assertTrue(self.db.remove_custom("mine"))

    def test_export_import_roundtrip(self):
        self.db.add_custom({"id": "mine", "name": "Mine", "ipv4": ["5.5.5.5"]})
        out = os.path.join(self.dir, "exp.json")
        n = self.db.export(out)
        db2 = ProviderDB(os.path.join(self.dir, "c2.json"))
        res = db2.import_file(out)
        self.assertEqual(res["added"], ["mine"])
        self.assertEqual(len(res["skipped"]), n - 1)       # built-ins never overwritten

    def test_system_dns_appears(self):
        ids = {p.id for p in self.db.all(["192.168.1.1", "fe80::1"])}
        self.assertIn("system", ids)

    def test_corrupt_custom_file_ignored(self):
        with open(self.db.user_path, "w") as f:
            f.write("{broken")
        self.assertGreater(len(self.db.all()), 10)


class TestBackupAndProfiles(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.adapter = netinfo.classify(TestNetinfo.RAW[0], "Home")

    def test_original_never_overwritten(self):
        bs = BackupStore(os.path.join(self.dir, "b"))
        bs.create(self.adapter, "first")
        changed = dict(self.adapter, dns4=["9.9.9.9"])
        bs.create(changed, "second")
        bs.create(changed, "third")
        orig = bs.original_for(self.adapter)
        self.assertEqual(orig["adapter"]["dns4"], ["192.168.1.1"])
        files = [b["file"] for b in bs.list()]
        self.assertEqual(len(files), 4)                 # 1 original + 3 backups, none overwritten
        self.assertEqual(len(set(files)), 4)

    def test_backup_get_rejects_traversal(self):
        bs = BackupStore(os.path.join(self.dir, "b"))
        self.assertIsNone(bs.get("../settings.json"))

    def test_profile_recognition_and_original(self):
        ps = ProfileStore(os.path.join(self.dir, "p.json"))
        s = _snap()
        p, known = ps.observe(s)
        self.assertFalse(known)
        ps.record_mtu(p["key"], "ipv4", {"recommended": 1492, "decision": "lower", "confidence": 90})
        s2 = _snap(dns="8.8.8.8")          # same network, DNS changed later
        p2, known2 = ps.observe(s2)
        self.assertTrue(known2)
        self.assertEqual(p2["original"]["dns4"], ["192.168.1.1"])   # original preserved
        self.assertEqual(ps.get(p["key"])["best"]["mtu_ipv4"]["mtu"], 1492)
        _, known3 = ps.observe(_snap(ssid="Cafe"))
        self.assertFalse(known3)


class TestApply(unittest.TestCase):
    A = {"index": 12, "alias": "Wi-Fi"}

    def test_validation(self):
        with self.assertRaises(apply.ApplyError):
            apply.op_dns(self.A, "ipv4", ["1.1.1.1 & del"])
        with self.assertRaises(apply.ApplyError):
            apply.op_dns(self.A, "ipv4", ["2606:4700::1111"])
        with self.assertRaises(apply.ApplyError):
            apply.op_mtu(self.A, "ipv6", 1200)
        self.assertEqual(apply.op_dns(self.A, "ipv4", None)["op"], "dns_dhcp")
        self.assertEqual(apply.op_dns(self.A, "ipv4", ["1.1.1.1", "1.0.0.1", "8.8.8.8"])["servers"],
                         ["1.1.1.1", "1.0.0.1"])

    def test_restore_ip_safely(self):
        ops = apply.ops_restore_ip(self.A, {"ip4_source": "static", "ipv4": ["192.168.1.5/24"],
                                            "gateway4": ["192.168.1.1"]})
        self.assertEqual(ops[0]["mask"], "255.255.255.0")
        with self.assertRaises(apply.ApplyError):
            apply.ops_restore_ip(self.A, {"ip4_source": "static", "ipv4": ["1.1.1.1/24", "2.2.2.2/24"]})

    def test_ps_script_has_no_user_text(self):
        # values only ever reach PowerShell as base64 JSON data
        self.assertIn("FromBase64String('__OPS__')", apply.PS_APPLY)

    def test_verify(self):
        snap = _snap()
        ops = [apply.op_dns(snap["primary"], "ipv4", ["192.168.1.1"]), apply.op_mtu(snap["primary"], "ipv4", 1492)]
        checks = apply.verify(snap, snap["primary"]["index"], ops)
        self.assertTrue(checks[0]["ok"])
        self.assertFalse(checks[1]["ok"])       # MTU still 1500 -> honestly reported


class TestCompare(unittest.TestCase):
    def _measure(self, dns_ms, ping_ms, loss=0.0, seed=1):
        rng = random.Random(seed)
        plan = compare.make_plan(defaults(), ["10.0.0.1"], ["1.1.1.1"])

        def q(server, name, qtype, timeout):
            return dnswire.DnsResult(server, name, qtype, True, dns_ms * rng.uniform(0.85, 1.25), 0, [])

        def probe(dest, payload, df, t):
            return Probe("timeout") if rng.random() < loss else Probe("ok", ping_ms * rng.uniform(0.9, 1.2))
        r = compare.measure(plan, ["10.0.0.1"], probe, 1500, query_fn=q)
        r["plan_id"] = "x"
        return r

    def test_no_fake_improvement(self):
        c = compare.compare(self._measure(30, 20, seed=1), self._measure(30, 20, seed=2))
        self.assertEqual(c["verdict"], "no_change")
        self.assertIn("No measurable improvement", c["summary"])

    def test_real_improvement_detected(self):
        c = compare.compare(self._measure(40, 20, seed=1), self._measure(15, 20, seed=2))
        self.assertEqual(c["verdict"], "improved")
        row = c["rows"][0]
        self.assertTrue(row["significant"])
        self.assertGreater(row["improvement_pct"], 40)
        self.assertLess(row["diff_ms"], -15)

    def test_regression_reported(self):
        c = compare.compare(self._measure(15, 20, seed=1), self._measure(40, 20, seed=2))
        self.assertEqual(c["verdict"], "worse")


class TestSettings(unittest.TestCase):
    def test_bounds_and_persistence(self):
        f = os.path.join(tempfile.mkdtemp(), "s.json")
        s = Settings(f)
        s.update({"dns_rounds": 99, "language": "fr", "test_ipv6": "false", "unknown": 1})
        self.assertEqual(s["dns_rounds"], 10)
        self.assertEqual(s["language"], "ar")
        self.assertFalse(s["test_ipv6"])
        self.assertEqual(Settings(f)["dns_rounds"], 10)
        with open(f) as fh:
            self.assertNotIn("unknown", json.load(fh))


if __name__ == "__main__":
    unittest.main(verbosity=2)
