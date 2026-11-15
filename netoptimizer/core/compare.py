"""Before / after performance comparison.

The 'before' run stores its exact test plan (domains, random-name count,
ping targets, sample counts, timeout). The 'after' run replays the same plan
so both measurements are taken under identical conditions. Improvements are
reported only when they are statistically meaningful; otherwise the report
explicitly says there is no measurable improvement.
"""
from __future__ import annotations

import random
import time
from typing import Optional

from . import dnswire, stats
from .dns_bench import DOMAIN_CATEGORIES, UNCACHED_PARENTS

SIG_P = 0.05
MIN_MEANINGFUL_MS = 1.0


def make_plan(cfg: dict, dns_servers: list, ping_targets: list) -> dict:
    rng = random.Random()
    pool = [d for v in DOMAIN_CATEGORIES.values() for d in v]
    return {"domains": rng.sample(pool, min(8, len(pool))),
            "uncached": 4, "rounds": max(2, cfg["compare_samples"] // 8),
            "ping_targets": ping_targets[:3], "ping_count": cfg["compare_samples"],
            "timeout_ms": cfg["dns_timeout_ms"], "dns_servers_before": dns_servers}


def measure(plan: dict, dns_servers: list, probe, mtu: Optional[int], ctx=None,
            query_fn=dnswire.query, progress=None) -> dict:
    timeout = plan["timeout_ms"] / 1000.0
    dns_lat, sent, ok = [], 0, 0
    primary = dns_servers[0] if dns_servers else None
    steps = plan["rounds"] * (len(plan["domains"]) + plan["uncached"]) + \
        len(plan["ping_targets"]) * plan["ping_count"]
    done = 0

    def tick(msg):
        nonlocal done
        done += 1
        if progress and done % 5 == 0:
            progress(done / max(1, steps), msg)
        if ctx:
            ctx.check()

    if primary:
        qtype = dnswire.TYPE_AAAA if ":" in primary else dnswire.TYPE_A
        for d in plan["domains"][:2]:
            query_fn(primary, d, qtype, timeout)          # warm-up, same in both runs
        for _ in range(plan["rounds"]):
            names = plan["domains"] + [f"{dnswire.random_label()}.{UNCACHED_PARENTS[i % len(UNCACHED_PARENTS)]}"
                                       for i in range(plan["uncached"])]
            for n in names:
                r = query_fn(primary, n, qtype, timeout)
                sent += 1
                if r.ok:
                    ok += 1
                    dns_lat.append(r.latency_ms)
                tick("DNS")
    ping_lat, ping_sent, ping_ok = [], 0, 0
    for t in plan["ping_targets"]:
        for _ in range(plan["ping_count"]):
            p = probe(t, 32, False, 1000)
            ping_sent += 1
            if p.ok:
                ping_ok += 1
                if p.rtt_ms is not None:
                    ping_lat.append(p.rtt_ms)
            tick("ping")
    return {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "dns_server": primary,
            "dns_samples": dns_lat, "dns_sent": sent, "dns_ok": ok,
            "dns": stats.summarize(dns_lat), "dns_success_rate": ok / sent if sent else None,
            "ping_samples": ping_lat, "ping_sent": ping_sent, "ping_ok": ping_ok,
            "ping": stats.summarize(ping_lat),
            "packet_loss": 1 - ping_ok / ping_sent if ping_sent else None,
            "mtu": mtu, "connected": ping_ok > 0 or ok > 0}


def _pct(before, after) -> Optional[float]:
    if before in (None, 0) or after is None:
        return None
    return round((before - after) / before * 100.0, 1)     # positive = faster


def compare(before: dict, after: dict) -> dict:
    rows, meaningful = [], []

    def lat_row(key, label):
        b = before[key]["median"]
        a = after[key]["median"]
        p = stats.mann_whitney_p(before[f"{key}_samples"], after[f"{key}_samples"])
        ci = stats.bootstrap_median_diff_ci(before[f"{key}_samples"], after[f"{key}_samples"])
        diff = (a - b) if (a is not None and b is not None) else None
        sig = (p is not None and p < SIG_P and diff is not None and abs(diff) >= MIN_MEANINGFUL_MS
               and ci is not None and (ci[0] > 0 or ci[1] < 0))
        rows.append({"metric": label, "before": b, "after": a, "diff_ms": diff,
                     "improvement_pct": _pct(b, a), "p_value": p, "ci95_ms": ci,
                     "significant": sig, "better": sig and diff < 0, "worse": sig and diff > 0})
        if sig:
            meaningful.append(rows[-1])

    lat_row("dns", "DNS median resolution time")
    rows.append({"metric": "DNS P95", "before": before["dns"]["p95"], "after": after["dns"]["p95"],
                 "diff_ms": (after["dns"]["p95"] - before["dns"]["p95"])
                 if before["dns"]["p95"] is not None and after["dns"]["p95"] is not None else None,
                 "improvement_pct": _pct(before["dns"]["p95"], after["dns"]["p95"]),
                 "significant": None})
    p = stats.two_proportion_p(before["dns_ok"], before["dns_sent"], after["dns_ok"], after["dns_sent"])
    sig = p is not None and p < SIG_P
    rows.append({"metric": "DNS success rate", "before": before["dns_success_rate"],
                 "after": after["dns_success_rate"], "p_value": p, "significant": sig,
                 "better": sig and (after["dns_success_rate"] or 0) > (before["dns_success_rate"] or 0),
                 "worse": sig and (after["dns_success_rate"] or 0) < (before["dns_success_rate"] or 0)})
    if sig:
        meaningful.append(rows[-1])
    lat_row("ping", "Median latency (ping)")
    rows.append({"metric": "Average latency (ping)", "before": before["ping"]["mean"],
                 "after": after["ping"]["mean"],
                 "diff_ms": (after["ping"]["mean"] - before["ping"]["mean"])
                 if before["ping"]["mean"] is not None and after["ping"]["mean"] is not None else None,
                 "improvement_pct": _pct(before["ping"]["mean"], after["ping"]["mean"]),
                 "significant": None})
    pl = stats.two_proportion_p(before["ping_ok"], before["ping_sent"], after["ping_ok"], after["ping_sent"])
    sig = pl is not None and pl < SIG_P
    rows.append({"metric": "Packet loss", "before": before["packet_loss"], "after": after["packet_loss"],
                 "p_value": pl, "significant": sig,
                 "better": sig and (after["packet_loss"] or 0) < (before["packet_loss"] or 0),
                 "worse": sig and (after["packet_loss"] or 0) > (before["packet_loss"] or 0)})
    if sig:
        meaningful.append(rows[-1])
    rows.append({"metric": "MTU", "before": before["mtu"], "after": after["mtu"],
                 "significant": None, "changed": before["mtu"] != after["mtu"]})
    rows.append({"metric": "Connectivity", "before": before["connected"], "after": after["connected"],
                 "significant": None})

    better = [r for r in meaningful if r.get("better")]
    worse = [r for r in meaningful if r.get("worse")]
    if worse and not better:
        verdict = "worse"
        summary = "Performance got measurably worse: " + ", ".join(r["metric"] for r in worse) + \
                  ". Consider restoring your original settings."
    elif better and not worse:
        verdict = "improved"
        summary = "Statistically meaningful improvement in: " + ", ".join(r["metric"] for r in better) + "."
    elif better and worse:
        verdict = "mixed"
        summary = "Mixed result — better: " + ", ".join(r["metric"] for r in better) + \
                  "; worse: " + ", ".join(r["metric"] for r in worse) + "."
    else:
        verdict = "no_change"
        summary = ("No measurable improvement: all differences are within measurement noise "
                   f"(p ≥ {SIG_P} or < {MIN_MEANINGFUL_MS} ms).")
    same_plan = before.get("plan_id") == after.get("plan_id")
    return {"verdict": verdict, "summary": summary, "rows": rows, "identical_conditions": same_plan,
            "before_time": before["time"], "after_time": after["time"]}
