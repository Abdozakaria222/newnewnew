"""End-to-end test of the App + local HTTP API with a simulated network."""
import http.client
import json
import os
import random
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["NETOPT_DATA_DIR"] = tempfile.mkdtemp(prefix="netopt-srv-")

from netoptimizer.core import dnswire, netinfo  # noqa: E402
from netoptimizer.core.icmp import Probe  # noqa: E402
from tests import test_core  # noqa: E402

SESSION_KEY = "unit-test-session"


def snap():
    a = netinfo.classify(dict(test_core.TestNetinfo.RAW[0]), "Home")
    return {"adapters": [a], "primary": a, "vpn_active": False, "vpn_adapters": [],
            "fingerprint": netinfo.fingerprint(a), "platform": "win32"}


def qfn(server, name, qtype, timeout):
    base = 10 if server.startswith("1.1.1") else 30
    return dnswire.DnsResult(server, name, qtype, True, base * random.uniform(0.9, 1.2), 0, [])


def probe(dest, payload, df, t):
    return Probe("ok", 10.0) if payload + 28 <= 1492 or not df else Probe("frag_needed")


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from netoptimizer.app import App
        from netoptimizer.ui.server import free_port, serve
        cls.applied = []
        cls.app = App(snapshot_fn=snap, probe=probe, query_fn=qfn,
                      apply_runner=lambda ops: cls.applied.extend(ops) or [{"ok": True} for _ in ops])
        cls.app.settings.update({"test_ipv6": False, "dns_rounds": 2, "monitor_enabled": False})
        cls.port = free_port(18900)
        cls.httpd, _ = serve(cls.app, cls.port, False, token=SESSION_KEY)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.app.monitor.stop()
        cls.httpd.shutdown()

    def req(self, method, path, body=None, token=SESSION_KEY, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Content-Type": "application/json", "Host": host or f"127.0.0.1:{self.port}"}
        if token:
            h["X-Token"] = token
        c.request(method, path, json.dumps(body) if body is not None else None, h)
        r = c.getresponse()
        data = r.read()
        try:
            return r.status, json.loads(data)
        except ValueError:
            return r.status, data

    def wait(self, job_id):
        for _ in range(300):
            _, j = self.req("GET", f"/api/job/{job_id}")
            if j["job"]["state"] != "running":
                return j["job"]
            time.sleep(0.1)
        self.fail("job did not finish")

    def test_security(self):
        self.assertEqual(self.req("GET", "/api/state", token=None)[0], 401)
        self.assertEqual(self.req("GET", "/api/state", token="wrong")[0], 401)
        self.assertEqual(self.req("GET", "/api/state", host="evil.example:80")[0], 403)
        self.assertEqual(self.req("GET", "/../netoptimizer/app.py", token=None)[0], 404)
        self.assertEqual(self.req("GET", "/index.html", token=None)[0], 200)

    def test_workflow_dns_before_mtu_then_apply(self):
        _, r = self.req("POST", "/api/workflow/start", {})
        job = self.wait(r["job"]["id"])
        self.assertEqual(job["state"], "done", job["error"])
        self.assertEqual(job["result"]["order"], ["dns", "mtu"])
        _, st = self.req("GET", "/api/state")
        self.assertEqual(st["recommendations"]["ipv4"]["mtu"]["recommended"], 1492)
        self.assertTrue(st["recommendations"]["ipv4"]["dns"]["primary"].startswith("1.1.1"))
        code, res = self.req("POST", "/api/apply", {"dns4": ["1.1.1.1", "1.0.0.1"], "mtu4": 1492})
        self.assertEqual(code, 200)
        self.assertTrue(res["backup"].startswith("backup-"))
        self.assertEqual(self.req("POST", "/api/apply", {"dns4": ["x;y"]})[0], 400)

    def test_independent_dns_and_mtu(self):
        _, r = self.req("POST", "/api/mtu/start", {})
        self.assertEqual(self.wait(r["job"]["id"])["state"], "done")
        _, r = self.req("POST", "/api/dns/start", {})
        self.assertEqual(self.wait(r["job"]["id"])["state"], "done")


if __name__ == "__main__":
    unittest.main(verbosity=2)
