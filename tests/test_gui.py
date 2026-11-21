"""View-model tests (pure) + a smoke test of the Tk window using a fake tkinter."""
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("NETOPT_DATA_DIR", tempfile.mkdtemp(prefix="netopt-gui-"))

from netoptimizer.gui import viewmodel as vm  # noqa: E402


def row(provider, name, median, ok=0.99, primary="1.1.1.1", secondary="1.0.0.1"):
    return {"provider": provider, "name": name, "primary": primary, "secondary": secondary, "score": 90,
            "eligible": True, "secondary_compatible": True,
            "metrics": {"median": median, "success_rate": ok, "p95": median * 2, "timeout_rate": 0}}


def dns_result(best_keep=False, with_gain=True):
    rows = [row("cf", "Cloudflare", 12.0), row("system", "ISP", 40.0 if with_gain else 12.5)]
    rec = {"provider": "cf", "name": "Cloudflare", "primary": "1.1.1.1", "secondary": "1.0.0.1",
           "score": 90, "keep_current": best_keep, "ties": [], "reasons": ["r1"]}
    return {"family": "ipv4", "providers": rows, "recommendation": rec}


class TestViewModel(unittest.TestCase):
    def test_dns_change(self):
        v = vm.dns_verdict(dns_result(), ["192.168.1.1"])
        self.assertEqual(v["level"], "change")
        self.assertEqual(v["apply"], ["1.1.1.1", "1.0.0.1"])
        self.assertIn("Cloudflare", v["title"])
        self.assertIn("28", v["detail"])           # 40 - 12 ms gain
        self.assertTrue(v["rows"][0]["is_best"])

    def test_dns_keep_current(self):
        v = vm.dns_verdict(dns_result(best_keep=True, with_gain=False), ["192.168.1.1"])
        self.assertEqual(v["level"], "ok")
        self.assertIsNone(v["apply"])

    def test_dns_no_provider_and_none(self):
        v = vm.dns_verdict({"providers": [], "recommendation": {"provider": None, "reasons": ["x"]}}, [])
        self.assertEqual(v["level"], "unsure")
        self.assertIsNone(v["apply"])
        self.assertEqual(vm.dns_verdict(None, [])["level"], "none")
        self.assertEqual(vm.dns_verdict({"skipped": "no v6"}, [])["level"], "none")

    def test_mtu_cases(self):
        r = {"decision": "lower", "recommended": 1400, "path_mtu": 1400, "confidence": 90, "reasons": []}
        v = vm.mtu_verdict(r, 1500)
        self.assertEqual((v["level"], v["apply"]), ("change", 1400))
        self.assertIn("ثقة عالية", v["detail"])
        v = vm.mtu_verdict({"decision": "keep", "recommended": 1500, "path_mtu": 1500, "confidence": 85}, 1500)
        self.assertEqual((v["level"], v["apply"]), ("ok", None))
        v = vm.mtu_verdict({"decision": "no_data", "path_mtu": None}, 1500)
        self.assertEqual((v["level"], v["apply"]), ("unsure", None))
        self.assertEqual(vm.mtu_verdict(None, 1500)["level"], "none")

    def test_summarize_plan(self):
        state = {"primary": {"alias": "Wi-Fi", "kind": "wifi", "ssid": "Home", "dns4": ["192.168.1.1"], "mtu4": 1500}}
        res = {"dns": {"ipv4": dns_result()},
               "mtu": {"ipv4": {"decision": "lower", "recommended": 1472, "path_mtu": 1472, "confidence": 80}}}
        s = vm.summarize(state, res)
        self.assertEqual(s["plan"], {"dns4": ["1.1.1.1", "1.0.0.1"], "mtu4": 1472})
        self.assertIn("Home", s["network"])
        self.assertEqual(vm.summarize({}, {})["plan"], {})


class FakeWidget:
    def __init__(self, *a, **k):
        self.opts = dict(k)
        self.children = []

    def __getattr__(self, name):
        def f(*a, **k):
            if name in ("config", "configure"):
                self.opts.update(k)
            return None
        return f

    def __setitem__(self, k, v):
        self.opts[k] = v


class FakeTk(FakeWidget):
    def after(self, ms, fn=None, *a):
        return None


def fake_tk_modules():
    tk = types.ModuleType("tkinter")
    for n in ("Frame", "Label", "Button", "Text"):
        setattr(tk, n, FakeWidget)
    tk.Tk = FakeTk
    ttk = types.ModuleType("tkinter.ttk")
    ttk.Progressbar = FakeWidget
    mb = types.ModuleType("tkinter.messagebox")
    mb.calls = []
    for n in ("showinfo", "showerror", "showwarning"):
        setattr(mb, n, lambda *a, _n=n, **k: mb.calls.append(_n))
    mb.askyesno = lambda *a, **k: True
    tk.ttk, tk.messagebox = ttk, mb
    return {"tkinter": tk, "tkinter.ttk": ttk, "tkinter.messagebox": mb}, mb


class TestWindowSmoke(unittest.TestCase):
    def test_window_runs_a_full_scan_and_apply(self):
        import random
        from netoptimizer.core import dnswire, netinfo
        from netoptimizer.core.icmp import Probe
        from tests import test_core

        mods, mb = fake_tk_modules()
        saved = {k: sys.modules.get(k) for k in list(mods) + ["netoptimizer.gui.window"]}
        sys.modules.update(mods)
        sys.modules.pop("netoptimizer.gui.window", None)
        try:
            from netoptimizer.app import App
            from netoptimizer.gui.window import Window
            a = netinfo.classify(dict(test_core.TestNetinfo.RAW[0]), "Home")
            snap = {"adapters": [a], "primary": a, "vpn_active": False, "vpn_adapters": [],
                    "fingerprint": netinfo.fingerprint(a), "platform": "win32"}
            applied = []
            app = App(snapshot_fn=lambda: snap,
                      probe=lambda d, p, df, t: Probe("ok", 10.0) if p + 28 <= 1492 or not df else Probe("frag_needed"),
                      query_fn=lambda s, n, q, t: dnswire.DnsResult(
                          s, n, q, True, (10 if s.startswith("1.1.1") else 30) * random.uniform(0.9, 1.2), 0, []),
                      apply_runner=lambda ops: applied.extend(ops) or [{"ok": True} for _ in ops])
            app.settings.update({"test_ipv6": False, "dns_rounds": 2, "monitor_enabled": False})
            w = Window(app, root=FakeTk())
            w.start()
            import time
            while w.job.state == "running":
                time.sleep(0.1)
            w.poll()
            self.assertEqual(w.job.state, "done", w.job.error)
            self.assertEqual(w.vm["dns"]["level"], "change")
            self.assertEqual(w.vm["mtu"]["apply"], 1492)
            proof = w.vm["mtu"]["proof"]
            self.assertTrue(proof[0].startswith("ping ") and "-f -l 1464" in proof[0], proof)
            self.assertIn("Reply from", proof[0])
            self.assertIn("-f -l 1465", proof[1])
            self.assertIn("needs to be fragmented", proof[1])
            self.assertIn("MTU 1492", proof[2])
            self.assertEqual(w.apply_btn.opts.get("state"), "normal")
            w.apply()
            time.sleep(0.2)
            w._run_bg  # worker thread finishes quickly
            for _ in range(50):
                if applied:
                    break
                time.sleep(0.05)
            self.assertTrue(any(o["op"] == "mtu" for o in applied))
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v


if __name__ == "__main__":
    unittest.main()
