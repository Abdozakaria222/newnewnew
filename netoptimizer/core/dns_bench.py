"""DNS benchmark and recommendation engine.

Every number comes from real UDP DNS queries (see dnswire.query). Methodology:

* Independent rounds; provider order is shuffled every round so no provider
  is systematically measured at a "better" moment.
* Domain categories (popular, CDN, services, regional/international) give
  "cached" samples: after one un-counted warm-up query, repeated queries for
  popular names normally come from the resolver cache.
* "Uncached" samples: a random sub-domain (e.g. k3f9a1....example.com) that no
  resolver can have cached, forcing a full recursive lookup. NXDOMAIN is a
  valid, successful answer for these.
* IPv4 and IPv6 servers are measured separately.
* Primary and secondary addresses are both tested (compatibility check).

Scoring is documented in SCORING.md and in WEIGHTS below.
"""
from __future__ import annotations

import concurrent.futures as cf
import logging
import random
import time
from typing import Callable, Optional

from . import dnswire, stats
from .providers import Provider

log = logging.getLogger("netopt.dns")

DOMAIN_CATEGORIES = {
    "popular":  ["google.com", "youtube.com", "facebook.com", "whatsapp.net", "instagram.com"],
    "cdn":      ["cloudflare.com", "gstatic.com", "fbcdn.net", "akamai.net", "fastly.net"],
    "services": ["microsoft.com", "apple.com", "github.com", "amazon.com", "netflix.com"],
    "regional": ["wikipedia.org", "bbc.co.uk", "yahoo.co.jp", "baidu.com", "yandex.ru"],
}
UNCACHED_PARENTS = ["google.com", "cloudflare.com", "microsoft.com", "wikipedia.org", "amazon.com"]

# Documented scoring weights (sum = 100). See SCORING.md.
WEIGHTS = {"median": 40, "p95": 20, "success": 20, "timeout": 10, "consistency": 10}
MIN_SUCCESS_FOR_RECOMMENDATION = 0.95
TIE_ABS_MS = 2.0       # medians closer than this ...
TIE_REL = 0.05         # ... or within 5 % are treated as a tie unless significant
SIGNIFICANCE_P = 0.05


def pick_domains(n: int, rng: random.Random) -> list[tuple[str, str]]:
    """Choose n domains spread evenly across categories."""
    cats = list(DOMAIN_CATEGORIES)
    out, i = [], 0
    pools = {c: rng.sample(v, len(v)) for c, v in DOMAIN_CATEGORIES.items()}
    while len(out) < n and any(pools.values()):
        c = cats[i % len(cats)]
        if pools[c]:
            out.append((c, pools[c].pop()))
        i += 1
    return out


def _server_samples() -> dict:
    return {"cached": [], "uncached": [], "by_category": {}, "sent": 0, "ok": 0,
            "timeouts": 0, "errors": {}, "rounds": []}


def measure_server(server: str, domains: list, uncached_n: int, timeout: float,
                   qtype: int, query_fn=dnswire.query, ctx=None) -> dict:
    """One round against one server. Returns raw samples for that round."""
    s = _server_samples()
    # warm-up (not counted): makes the "cached" samples meaningful
    for _, d in domains[:2]:
        query_fn(server, d, qtype, timeout)
    round_lat = []

    def record(res, bucket, cat=None):
        s["sent"] += 1
        if res.ok:
            s["ok"] += 1
            s[bucket].append(res.latency_ms)
            round_lat.append(res.latency_ms)
            if cat:
                s["by_category"].setdefault(cat, []).append(res.latency_ms)
        else:
            if res.timeout:
                s["timeouts"] += 1
            s["errors"][res.error or "error"] = s["errors"].get(res.error or "error", 0) + 1

    for cat, d in domains:
        if ctx:
            ctx.check()
        record(query_fn(server, d, qtype, timeout), "cached", cat)
    parents = UNCACHED_PARENTS[:]
    random.shuffle(parents)
    for i in range(uncached_n):
        if ctx:
            ctx.check()
        name = f"{dnswire.random_label()}.{parents[i % len(parents)]}"
        record(query_fn(server, name, qtype, timeout), "uncached")
    s["rounds"].append(stats.median(round_lat))
    return s


def _merge(a: dict, b: dict) -> dict:
    a["cached"] += b["cached"]
    a["uncached"] += b["uncached"]
    for k, v in b["by_category"].items():
        a["by_category"].setdefault(k, []).extend(v)
    for k in ("sent", "ok", "timeouts"):
        a[k] += b[k]
    for k, v in b["errors"].items():
        a["errors"][k] = a["errors"].get(k, 0) + v
    a["rounds"] += b["rounds"]
    return a


def server_metrics(s: dict) -> dict:
    allv = s["cached"] + s["uncached"]
    m = stats.summarize(allv)
    sent = max(1, s["sent"])
    med = m["median"]
    m.update({
        "success_rate": s["ok"] / sent,
        "timeout_rate": s["timeouts"] / sent,
        "sent": s["sent"], "ok": s["ok"],
        "cached": stats.summarize(s["cached"]),
        "uncached": stats.summarize(s["uncached"]),
        "by_category": {k: stats.median(v) for k, v in s["by_category"].items()},
        "round_medians": s["rounds"],
        # consistency: relative robust spread (MAD / median); lower is better
        "variability": (m["mad"] / med) if med else None,
        "errors": s["errors"],
        "samples": allv,
    })
    return m


def score_servers(entries: list[dict]) -> None:
    """Adds 'score' and 'score_parts' to each entry (in place).
    Latency parts are relative to the best measured value in this run, so
    the score always reflects *this* network at *this* time."""
    valid = [e for e in entries if e["metrics"]["median"] is not None]
    if not valid:
        for e in entries:
            e["score"], e["score_parts"] = 0.0, {}
        return
    best_med = min(e["metrics"]["median"] for e in valid)
    best_p95 = min(e["metrics"]["p95"] for e in valid)
    for e in entries:
        m = e["metrics"]
        if m["median"] is None:
            e["score"], e["score_parts"] = 0.0, {k: 0.0 for k in WEIGHTS}
            continue
        parts = {
            "median": 100.0 * best_med / max(m["median"], 0.001),
            "p95": 100.0 * best_p95 / max(m["p95"], 0.001),
            "success": 100.0 * m["success_rate"],
            "timeout": 100.0 * (1 - m["timeout_rate"]),
            "consistency": 100.0 * max(0.0, 1.0 - (m["variability"] or 0.0)),
        }
        e["score_parts"] = {k: round(v, 1) for k, v in parts.items()}
        e["score"] = round(sum(parts[k] * WEIGHTS[k] for k in WEIGHTS) / 100.0, 1)


def run_benchmark(providers: list[Provider], family: str, cfg: dict,
                  ctx=None, query_fn=dnswire.query,
                  progress: Optional[Callable[[float, str], None]] = None) -> dict:
    """Benchmark all providers for one address family ('ipv4' / 'ipv6')."""
    qtype = dnswire.TYPE_A if family == "ipv4" else dnswire.TYPE_AAAA
    rng = random.Random()
    rounds = cfg["dns_rounds"]
    timeout = cfg["dns_timeout_ms"] / 1000.0
    domains = pick_domains(cfg["dns_domains"], rng)
    uncached_n = max(2, cfg["dns_domains"] // 3)
    test_secondary = cfg.get("dns_test_secondary", True)

    targets = []   # (provider, role, server)
    for p in providers:
        srv = p.servers(family)
        if not srv:
            continue
        targets.append((p, "primary", srv[0]))
        if test_secondary and len(srv) > 1:
            targets.append((p, "secondary", srv[1]))
    if not targets:
        return {"family": family, "servers": [], "providers": [], "skipped": "no servers for this family"}

    acc = {(t[0].id, t[1]): _server_samples() for t in targets}
    total = rounds * len(targets)
    done = 0
    started = time.time()
    for r in range(rounds):
        order = targets[:]
        rng.shuffle(order)
        with cf.ThreadPoolExecutor(max_workers=cfg.get("dns_concurrency", 4)) as ex:
            futs = {ex.submit(measure_server, t[2], domains, uncached_n, timeout,
                              qtype, query_fn, ctx): t for t in order}
            for f in cf.as_completed(futs):
                t = futs[f]
                _merge(acc[(t[0].id, t[1])], f.result())
                done += 1
                if progress:
                    progress(done / total, f"DNS {family} round {r + 1}/{rounds}: {t[0].name}")
                if ctx:
                    ctx.check()

    servers = []
    for p, role, srv in targets:
        servers.append({"provider": p.id, "name": p.name, "role": role, "server": srv,
                        "filtering": p.filtering, "source": p.source,
                        "metrics": server_metrics(acc[(p.id, role)])})
    score_servers(servers)

    # provider-level view: primary metrics + secondary compatibility
    prov_rows = []
    for p in providers:
        prim = next((s for s in servers if s["provider"] == p.id and s["role"] == "primary"), None)
        if not prim:
            continue
        sec = next((s for s in servers if s["provider"] == p.id and s["role"] == "secondary"), None)
        sec_ok = sec is None or sec["metrics"]["success_rate"] >= MIN_SUCCESS_FOR_RECOMMENDATION
        eligible = prim["metrics"]["success_rate"] >= MIN_SUCCESS_FOR_RECOMMENDATION
        prov_rows.append({
            "provider": p.id, "name": p.name, "filtering": p.filtering, "source": p.source,
            "primary": prim["server"], "secondary": sec["server"] if sec else None,
            "score": prim["score"], "score_parts": prim["score_parts"],
            "metrics": {k: v for k, v in prim["metrics"].items() if k != "samples"},
            "secondary_metrics": ({k: v for k, v in sec["metrics"].items() if k != "samples"}
                                  if sec else None),
            "secondary_compatible": sec_ok, "eligible": eligible,
        })
    prov_rows.sort(key=lambda x: (not x["eligible"], -x["score"]))
    samples = {s["provider"]: s["metrics"]["samples"] for s in servers if s["role"] == "primary"}
    rec = recommend(prov_rows, samples)
    for s in servers:
        s["metrics"].pop("samples", None)
    return {"family": family, "rounds": rounds, "domains": domains,
            "uncached_per_round": uncached_n, "duration_s": round(time.time() - started, 1),
            "servers": servers, "providers": prov_rows, "recommendation": rec,
            "weights": WEIGHTS}


def recommend(rows: list[dict], samples: dict) -> dict:
    eligible = [r for r in rows if r["eligible"]]
    if not eligible:
        return {"provider": None, "reasons": [
            "No provider reached the minimum reliability "
            f"({MIN_SUCCESS_FOR_RECOMMENDATION:.0%} successful queries). No change is recommended."]}
    best = eligible[0]
    reasons = [
        f"Highest score {best['score']} / 100 among {len(eligible)} reliable providers.",
        f"Median {best['metrics']['median']:.1f} ms, P95 {best['metrics']['p95']:.1f} ms, "
        f"success {best['metrics']['success_rate']:.1%}, timeouts {best['metrics']['timeout_rate']:.1%}.",
    ]
    tie_with = []
    for other in eligible[1:4]:
        a, b = samples.get(best["provider"], []), samples.get(other["provider"], [])
        diff = other["metrics"]["median"] - best["metrics"]["median"]
        p = stats.mann_whitney_p(a, b)
        close = diff < max(TIE_ABS_MS, TIE_REL * best["metrics"]["median"])
        if close and (p is None or p >= SIGNIFICANCE_P):
            tie_with.append(other["name"])
    if tie_with:
        reasons.append("Statistically indistinguishable from: " + ", ".join(tie_with) +
                       " (differences are within measurement noise).")
    secondary = best["secondary"]
    if best["secondary"] and not best["secondary_compatible"]:
        alt = next((r for r in eligible[1:] if r["provider"] != best["provider"]), None)
        secondary = alt["primary"] if alt else None
        reasons.append("This provider's secondary address was unreliable; secondary replaced by "
                       + (alt["name"] if alt else "none") + ".")
    system = next((r for r in rows if r["provider"] == "system"), None)
    keep_current = False
    if system and system["eligible"] and system["provider"] != best["provider"]:
        a, b = samples.get(best["provider"], []), samples.get(system["provider"], [])
        diff = system["metrics"]["median"] - best["metrics"]["median"]
        p = stats.mann_whitney_p(a, b)
        noise = diff < max(TIE_ABS_MS, TIE_REL * best["metrics"]["median"])
        if noise or p is None or p >= SIGNIFICANCE_P:
            keep_current = True
            ptxt = f"{p:.3g}" if p is not None else "n/a"
            reasons.append(f"Your current DNS is within noise of the best ({diff:+.1f} ms median, "
                           f"p={ptxt}): keeping the current DNS is reasonable.")
        else:
            reasons.append(f"Faster than your current DNS by {diff:.1f} ms median (p={p:.3g}, significant).")
    elif system and system["provider"] == best["provider"]:
        keep_current = True
        reasons.append("Your current DNS is already the best measured option.")
    return {"provider": best["provider"], "name": best["name"], "primary": best["primary"],
            "secondary": secondary, "score": best["score"], "keep_current": keep_current,
            "ties": tie_with, "reasons": reasons}
