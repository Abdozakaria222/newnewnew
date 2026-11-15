"""Application service layer: holds state and orchestrates the engines.
The HTTP server (ui/server.py) is a thin JSON wrapper around this class."""
from __future__ import annotations

import csv
import json
import logging
import os
import sys
import threading
import time
import uuid

from .core import apply as applymod
from .core import compare as comparemod
from .core import diagnostics, dns_bench, mtu, netinfo, settings
from .core.backup import BackupStore
from .core.icmp import SystemIcmp
from .core.jobs import JobManager
from .core.monitor import Monitor
from .core.profiles import ProfileStore
from .core.providers import ProviderDB

log = logging.getLogger("netopt.app")


class App:
    def __init__(self, snapshot_fn=netinfo.snapshot, probe=None, query_fn=None, apply_runner=None):
        self.log_file = settings.setup_logging()
        self.settings = settings.Settings()
        self.providers = ProviderDB(settings.path("custom_dns_providers.json"))
        self.profiles = ProfileStore(settings.path("profiles.json"))
        self.backups = BackupStore(os.path.join(settings.data_dir(), "backups"))
        self.jobs = JobManager()
        self.snapshot_fn = snapshot_fn
        self.icmp = SystemIcmp() if probe is None else None
        self.probe = probe or self.icmp.probe
        self.query_fn = query_fn or dns_bench.dnswire.query
        self.apply_runner = apply_runner
        self._lock = threading.RLock()
        self.snapshot = None
        self.profile = None
        self.profile_known = False
        self.results = {"dns": {}, "mtu": {}}
        self.compare_state = {"before": None, "after": None, "result": None, "plan": None}
        self.last_apply = None
        self.refresh()
        self.monitor = Monitor(lambda: self.settings["monitor_interval_s"], self._on_change,
                               snapshot_fn=self.snapshot_fn)
        if self.settings["monitor_enabled"]:
            self.monitor.start(self.snapshot)

    # ------------------------------------------------------------ state
    def refresh(self) -> dict:
        snap = self.snapshot_fn()
        with self._lock:
            self.snapshot = snap
            if self.settings["auto_profile"]:
                self.profile, self.profile_known = self.profiles.observe(snap)
            else:
                self.profile, self.profile_known = None, False
        return snap

    def _on_change(self, snap: dict, events: list) -> None:
        with self._lock:
            self.snapshot = snap
            if self.settings["auto_profile"]:
                self.profile, self.profile_known = self.profiles.observe(snap)
        for e in events:
            log.info("network event: %s", e["message"])

    @property
    def primary(self):
        return (self.snapshot or {}).get("primary")

    def state(self) -> dict:
        p = self.primary
        prof = self.profiles.get(self.profile["key"]) if self.profile else None
        rec = {}
        for fam in ("ipv4", "ipv6"):
            d = self.results["dns"].get(fam)
            m = self.results["mtu"].get(fam)
            rec[fam] = {
                "dns": d.get("recommendation") if d else None,
                "dns_date": d.get("date") if d else None,
                "mtu": {k: m.get(k) for k in ("recommended", "decision", "confidence", "path_mtu", "reasons")} if m else None,
                "mtu_date": m.get("date") if m else None,
            }
        running = self.jobs.busy_heavy()
        return {
            "version": settings.APP_VERSION, "platform": sys.platform,
            "admin": applymod.is_admin(), "primary": p,
            "adapters": (self.snapshot or {}).get("adapters", []),
            "vpn_active": (self.snapshot or {}).get("vpn_active"),
            "vpn_adapters": (self.snapshot or {}).get("vpn_adapters", []),
            "fingerprint": (self.snapshot or {}).get("fingerprint"),
            "profile": prof, "profile_known": self.profile_known,
            "recommendations": rec,
            "last_benchmark": max([x for f in rec.values() for x in (f["dns_date"], f["mtu_date"]) if x] or [None],
                                  key=lambda x: x or ""),
            "optimization_status": self._opt_status(prof),
            "compare": self.compare_state.get("result"),
            "compare_has_before": self.compare_state.get("before") is not None,
            "running_job": running.to_dict() if running else None,
            "settings": self.settings.values,
            "last_apply": self.last_apply,
        }

    def _opt_status(self, prof) -> str:
        if not prof:
            return "unknown"
        if prof.get("applied"):
            return "optimized"
        if prof.get("best"):
            return "tested"
        return "not_tested"

    # ------------------------------------------------------------ tests
    def _families(self, req) -> list:
        fams = []
        if self.settings["test_ipv4"] and (not req or "ipv4" in req):
            fams.append("ipv4")
        if self.settings["test_ipv6"] and (not req or "ipv6" in req):
            fams.append("ipv6")
        return fams

    def _ipv6_available(self) -> bool:
        p = self.primary or {}
        return bool(p.get("ipv6") and p.get("gateway6")) or diagnostics.tcp_check(
            "2606:4700:4700::1111", 443, 2)["ok"]

    def _dns_job(self, ctx, families, base=0.0, span=1.0):
        out = {}
        system = (self.primary or {}).get("dns4", []) + (self.primary or {}).get("dns6", [])
        provs = self.providers.all(system)
        fams = [f for f in families if f != "ipv6" or self._ipv6_available()]
        skipped = [f for f in families if f not in fams]
        for i, fam in enumerate(fams):
            def prog(f, m, i=i):
                ctx.progress(base + span * (i + f) / max(1, len(fams)), m)
            r = dns_bench.run_benchmark(provs, fam, self.settings.values, ctx, self.query_fn, prog)
            r["date"] = time.strftime("%Y-%m-%d %H:%M:%S")
            self.results["dns"][fam] = r
            out[fam] = r
            if self.profile:
                self.profiles.record_dns(self.profile["key"], fam, r)
            self._log_csv("dns", fam, r)
        for f in skipped:
            out[f] = {"family": f, "skipped": "IPv6 connectivity not available on this network"}
            self.results["dns"][f] = out[f]
        return out

    def _mtu_job(self, ctx, families, base=0.0, span=1.0):
        out = {}
        p = self.primary or {}
        fams = [f for f in families if f != "ipv6" or self._ipv6_available()]
        for i, fam in enumerate(fams):
            dests = self.settings.list("mtu_destinations" if fam == "ipv4" else "mtu_destinations_v6")
            cur = p.get("mtu4" if fam == "ipv4" else "mtu6")

            def prog(f, m, i=i):
                ctx.progress(base + span * (i + f) / max(1, len(fams)), m)
            r = mtu.run_mtu(self.probe, self.settings.values, fam, dests, cur, p, ctx, prog)
            r["date"] = time.strftime("%Y-%m-%d %H:%M:%S")
            r["adapter"] = p.get("alias")
            self.results["mtu"][fam] = r
            out[fam] = r
            if self.profile:
                self.profiles.record_mtu(self.profile["key"], fam, r)
            self._log_csv("mtu", fam, r)
        for f in families:
            if f not in fams:
                out[f] = {"family": f, "skipped": "IPv6 connectivity not available on this network"}
                self.results["mtu"][f] = out[f]
        return out

    def start_dns(self, families=None):
        fams = self._families(families)
        return self.jobs.start("dns", lambda ctx: self._dns_job(ctx, fams))

    def start_mtu(self, families=None):
        fams = self._families(families)
        return self.jobs.start("mtu", lambda ctx: self._mtu_job(ctx, fams))

    def start_workflow(self, families=None):
        """Default workflow: DNS first, then MTU."""
        fams = self._families(families)

        def run(ctx):
            d = self._dns_job(ctx, fams, 0.0, 0.5)
            m = self._mtu_job(ctx, fams, 0.5, 0.5)
            return {"order": ["dns", "mtu"], "dns": d, "mtu": m}
        return self.jobs.start("workflow", run)

    def _log_csv(self, kind: str, fam: str, r: dict) -> None:
        if not self.settings["benchmark_logging"]:
            return
        try:
            f = settings.path("logs", f"{kind}_benchmarks.csv")
            new = not os.path.exists(f)
            with open(f, "a", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                if kind == "dns":
                    if new:
                        w.writerow(["date", "family", "provider", "server", "role", "median_ms", "p90_ms",
                                    "p95_ms", "success_rate", "timeout_rate", "variability", "score"])
                    for s in r.get("servers", []):
                        m = s["metrics"]
                        w.writerow([r["date"], fam, s["name"], s["server"], s["role"], _r(m["median"]),
                                    _r(m["p90"]), _r(m["p95"]), _r(m["success_rate"], 4),
                                    _r(m["timeout_rate"], 4), _r(m["variability"], 3), s["score"]])
                else:
                    if new:
                        w.writerow(["date", "family", "adapter", "current_mtu", "path_mtu", "recommended",
                                    "decision", "confidence", "probes"])
                    w.writerow([r["date"], fam, r.get("adapter"), r.get("current_mtu"), r.get("path_mtu"),
                                r.get("recommended"), r.get("decision"), r.get("confidence"), r.get("probes_sent")])
        except OSError as e:
            log.warning("csv logging failed: %s", e)

    # ------------------------------------------------------------ compare
    def _ping_targets(self):
        p = self.primary or {}
        return [x for x in ((p.get("gateway4") or [None])[0], "1.1.1.1", "8.8.8.8") if x]

    def _current_dns(self):
        self.refresh()
        p = self.primary or {}
        return p.get("dns4") or p.get("dns6") or []

    def start_compare(self, phase: str):
        if phase == "before":
            def run(ctx):
                dns = self._current_dns()
                plan = comparemod.make_plan(self.settings.values, dns, self._ping_targets())
                plan["id"] = uuid.uuid4().hex[:8]
                res = comparemod.measure(plan, dns, self.probe, (self.primary or {}).get("mtu4"),
                                         ctx, self.query_fn, ctx.progress)
                res["plan_id"] = plan["id"]
                self.compare_state = {"before": res, "after": None, "result": None, "plan": plan}
                return {"before": _strip(res)}
            return self.jobs.start("compare_before", run)
        if not self.compare_state.get("before"):
            raise RuntimeError("Run the 'before' measurement first.")

        def run_after(ctx):
            plan = self.compare_state["plan"]
            dns = self._current_dns()
            res = comparemod.measure(plan, dns, self.probe, (self.primary or {}).get("mtu4"),
                                     ctx, self.query_fn, ctx.progress)
            res["plan_id"] = plan["id"]
            cmp = comparemod.compare(self.compare_state["before"], res)
            cmp["before"], cmp["after"] = _strip(self.compare_state["before"]), _strip(res)
            cmp["before_samples"] = self.compare_state["before"]["dns_samples"]
            cmp["after_samples"] = res["dns_samples"]
            self.compare_state.update(after=res, result=cmp)
            if self.profile:
                self.profiles.record_comparison(self.profile["key"], cmp)
            return cmp
        return self.jobs.start("compare_after", run_after)

    # ------------------------------------------------------------ apply / restore
    def _adapter_by_index(self, index):
        self.refresh()
        for a in self.snapshot["adapters"]:
            if a["index"] == index:
                return a
        raise applymod.ApplyError("adapter not found — refresh and try again")

    def apply(self, body: dict) -> dict:
        idx = body.get("adapter_index") or (self.primary or {}).get("index")
        if idx is None:
            raise applymod.ApplyError("no active adapter")
        a = self._adapter_by_index(int(idx))
        ops = []
        for fam, key in (("ipv4", "dns4"), ("ipv6", "dns6")):
            if key in body and body[key] is not None:
                ops.append(applymod.op_dns(a, fam, body[key] or None))
        for fam, key in (("ipv4", "mtu4"), ("ipv6", "mtu6")):
            if body.get(key):
                ops.append(applymod.op_mtu(a, fam, body[key]))
        if not ops:
            raise applymod.ApplyError("nothing to apply")
        prof_key = self.profile["key"] if self.profile else None
        prev_applied = (self.profiles.get(prof_key) or {}).get("applied") if prof_key else None
        bk = self.backups.create(a, "before apply", prof_key, prev_applied)
        results = applymod.run_ops(ops, self.apply_runner)
        snap = self.refresh()
        checks = applymod.verify(snap, a["index"], ops)
        if prof_key:
            self.profiles.record_applied(prof_key, {k: body.get(k) for k in ("dns4", "dns6", "mtu4", "mtu6")
                                                    if body.get(k) is not None})
        self.last_apply = {"time": time.strftime("%H:%M:%S"), "ops": ops, "results": results,
                           "checks": checks, "backup": bk["file"]}
        return self.last_apply

    def restore(self, body: dict) -> dict:
        name = body.get("backup")
        parts = set(body.get("parts") or ["dns", "mtu"])
        bk = self.backups.get(name) if name else None
        if not bk:
            raise applymod.ApplyError("backup not found")
        cfg = bk["adapter"]
        a = next((x for x in self.refresh()["adapters"]
                  if (cfg.get("guid") and x.get("guid") == cfg.get("guid")) or x["alias"] == cfg["alias"]), None)
        if not a:
            raise applymod.ApplyError(f"adapter {cfg['alias']} is not present now")
        ops = []
        if "dns" in parts:
            ops.append(applymod.op_dns(a, "ipv4", cfg["dns4"] if cfg.get("dns4_source") == "static" else None))
            if cfg.get("dns6") or cfg.get("dns6_source"):
                ops.append(applymod.op_dns(a, "ipv6", cfg["dns6"] if cfg.get("dns6_source") == "static" else None))
        if "mtu" in parts:
            if cfg.get("mtu4"):
                ops.append(applymod.op_mtu(a, "ipv4", cfg["mtu4"]))
            if cfg.get("mtu6"):
                ops.append(applymod.op_mtu(a, "ipv6", cfg["mtu6"]))
        if "ip" in parts:
            ops += applymod.ops_restore_ip(a, cfg)
        prof_key = self.profile["key"] if self.profile else None
        new_bk = self.backups.create(a, f"before restore of {name}", prof_key)
        results = applymod.run_ops(ops, self.apply_runner)
        snap = self.refresh()
        checks = applymod.verify(snap, a["index"], ops)
        self.last_apply = {"time": time.strftime("%H:%M:%S"), "ops": ops, "results": results,
                           "checks": checks, "backup": new_bk["file"], "restored_from": name}
        return self.last_apply

    def restore_previous_profile(self) -> dict:
        prof = self.profiles.get(self.profile["key"]) if self.profile else None
        prev = (prof or {}).get("previous_applied")
        if not prev:
            raise applymod.ApplyError("no previous optimization profile for this network")
        return self.apply({k: prev.get(k) for k in ("dns4", "dns6", "mtu4", "mtu6")})

    # ------------------------------------------------------------ tools
    def start_tool(self, name: str):
        p = self.primary or {}
        dns = (p.get("dns4") or []) + (p.get("dns6") or [])
        gw = (p.get("gateway4") or [None])[0]
        tools = {
            "connectivity": lambda ctx: diagnostics.connectivity(),
            "ipcheck": lambda ctx: diagnostics.ip_versions(),
            "publicip": lambda ctx: diagnostics.public_ip(self.query_fn),
            "leak": lambda ctx: diagnostics.dns_leak(dns, self.query_fn),
            "resolution": lambda ctx: diagnostics.dns_resolution(dns or ["1.1.1.1"], self.query_fn),
            "packet_loss": lambda ctx: diagnostics.packet_loss(self.probe, self._ping_targets(), 20, ctx),
            "gateway": lambda ctx: diagnostics.gateway_latency(self.probe, gw, 20, ctx),
            "adapters": lambda ctx: self.refresh()["adapters"],
        }
        if name not in tools:
            raise KeyError(name)
        kind = "packet_loss" if name in ("packet_loss", "gateway") else f"tool_{name}"
        return self.jobs.start(kind, tools[name])

    def report(self) -> dict:
        snap = json.loads(json.dumps(self.snapshot or {}))
        for a in snap.get("adapters", []):
            a["mac"] = netinfo.mask_mac(a.get("mac"))
            a["gateway_mac"] = netinfo.mask_mac(a.get("gateway_mac"))
        if snap.get("primary"):
            snap["primary"]["mac"] = netinfo.mask_mac(snap["primary"].get("mac"))
            snap["primary"]["gateway_mac"] = netinfo.mask_mac(snap["primary"].get("gateway_mac"))
        dns = {f: _strip_dns(r) for f, r in self.results["dns"].items()}
        mtu_r = {f: {k: v for k, v in r.items() if k != "probe_log"} for f, r in self.results["mtu"].items()}
        return {"app": "NetworkOptimizer", "version": settings.APP_VERSION,
                "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "platform": sys.platform,
                "network": snap, "dns_results": dns, "mtu_results": mtu_r,
                "comparison": self.compare_state.get("result"),
                "note": "MAC addresses are masked in this report. " + diagnostics.LEAK_DISCLAIMER}


def _r(v, n=1):
    return round(v, n) if isinstance(v, (int, float)) else v


def _strip(res: dict) -> dict:
    return {k: v for k, v in res.items() if not k.endswith("_samples")}


def _strip_dns(r: dict) -> dict:
    return r
