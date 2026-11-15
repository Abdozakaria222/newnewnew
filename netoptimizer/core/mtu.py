"""MTU discovery engine (DF packet-size verification, binary search).

Pipeline per address family:
 1. Baseline: small probes to every destination -> detects ICMP filtering
    and unreliable (lossy) destinations, which are excluded.
 2. Binary search of the largest MTU that passes with DF set, per destination.
    A probe that times out is retried; a large-packet timeout while small
    packets still pass is classified as a "silent drop" (PMTU black hole),
    while timeouts of small packets too are classified as packet loss and
    make that measurement inconclusive (not "too big").
 3. Confirmation: the found value is re-tested N times, and value+1 must fail.
 4. Cross-destination agreement: at least two destinations must agree; a
    single destination with a lower limit than the others is flagged.
 5. Final verification at the recommended MTU with small/medium/large
    packets to all reliable destinations, repeated.

The engine never lowers the MTU unless the path *verifiably* cannot carry
the current MTU (confirmed, repeated, and on >= 2 destinations).
"""
from __future__ import annotations

import logging
from collections import Counter
from typing import Callable, Optional

from .icmp import Probe

log = logging.getLogger("netopt.mtu")

OVERHEAD = {"ipv4": 28, "ipv6": 48}     # IP header + ICMP header
PPPOE_OVERHEAD = 8
KNOWN_TUNNEL_MTUS = {1420: "WireGuard (typical)", 1400: "VPN/tunnel (common)",
                     1380: "IPsec/L2TP (typical)", 1440: "GRE/IPsec (typical)",
                     1450: "VXLAN/VPN (typical)", 1476: "GRE tunnel"}
IPV6_MIN_MTU = 1280
# Confidence weights (sum = 100). Documented in SCORING.md.
CONF_WEIGHTS = {"agreement": 40, "confirmation": 30, "boundary": 15, "verification": 15}
SINGLE_DESTINATION_CAP = 50

ProbeFn = Callable[[str, int, bool, int], Probe]


class MtuEngine:
    def __init__(self, probe: ProbeFn, cfg: dict, ctx=None,
                 progress: Optional[Callable[[float, str], None]] = None):
        self.probe_fn = probe
        self.cfg = cfg
        self.ctx = ctx
        self.progress = progress or (lambda f, m: None)
        self.log: list[dict] = []
        self.counts = Counter()

    # -- low level -------------------------------------------------------
    def _probe(self, dest: str, mtu: int, family: str) -> Probe:
        if self.ctx:
            self.ctx.check()
        payload = mtu - OVERHEAD[family]
        p = self.probe_fn(dest, payload, True, self.cfg["mtu_ping_timeout_ms"])
        self.counts[p.status] += 1
        self.log.append({"dest": dest, "mtu": mtu, "status": p.status, "rtt": p.rtt_ms})
        return p

    def _small_ok(self, dest: str, family: str) -> bool:
        return any(self._probe(dest, 100 + OVERHEAD[family], family).ok for _ in range(2))

    def fits(self, dest: str, mtu: int, family: str) -> Optional[bool]:
        """True = passes, False = too big (explicit or silent drop),
        None = inconclusive (general packet loss)."""
        for _ in range(3):
            p = self._probe(dest, mtu, family)
            if p.ok:
                return True
            if p.status == "frag_needed":
                self.counts["explicit_frag"] += 1
                return False
            if p.status in ("unreachable", "error"):
                return None
        # all attempts timed out: is it the size or the line?
        if self._small_ok(dest, family):
            self.counts["silent_drop"] += 1
            return False
        self.counts["loss_events"] += 1
        return None

    # -- stages ----------------------------------------------------------
    def baseline(self, dests: list, family: str) -> dict:
        out = {}
        for d in dests:
            res = [self._probe(d, 100 + OVERHEAD[family], family) for _ in range(4)]
            okn = sum(r.ok for r in res)
            if okn == 0:
                state = "icmp_filtered_or_unreachable"
            elif okn < 4:
                state = "unreliable"
            else:
                state = "ok"
            rtts = [r.rtt_ms for r in res if r.ok and r.rtt_ms is not None]
            out[d] = {"state": state, "replies": okn, "sent": 4,
                      "rtt_ms": (sum(rtts) / len(rtts)) if rtts else None}
        return out

    def search(self, dest: str, lo: int, hi: int, family: str) -> dict:
        tests = 0
        top = self.fits(dest, hi, family)
        tests += 1
        if top is True:
            return {"max": hi, "tests": tests, "inconclusive": 0, "limited_by_upper_bound": True}
        if self.fits(dest, lo, family) is not True:
            return {"max": None, "tests": tests + 1, "inconclusive": 1,
                    "error": f"even MTU {lo} did not pass"}
        tests += 1
        good, bad, inconclusive = lo, hi, 0
        while bad - good > 1:
            mid = (good + bad) // 2
            r = self.fits(dest, mid, family)
            tests += 1
            if r is True:
                good = mid
            elif r is False:
                bad = mid
            else:
                inconclusive += 1
                if inconclusive > 4:
                    return {"max": None, "tests": tests, "inconclusive": inconclusive,
                            "error": "too much packet loss for a reliable result"}
        return {"max": good, "tests": tests, "inconclusive": inconclusive,
                "limited_by_upper_bound": False}

    def confirm(self, dest: str, mtu: int, hi: int, family: str) -> dict:
        n = self.cfg["mtu_confirm_attempts"]
        passes = sum(1 for _ in range(n) if self._probe(dest, mtu, family).ok)
        boundary = None
        if mtu < hi:
            above = [self.fits(dest, mtu + 1, family) for _ in range(min(n, 2))]
            boundary = all(a is False for a in above)
        return {"passes": passes, "attempts": n, "boundary_fails": boundary}

    def verify(self, dests: list, mtu: int, family: str) -> dict:
        sizes = {"small": 64 + OVERHEAD[family], "medium": max(576, mtu // 2), "large": mtu}
        res = {}
        total = okn = 0
        reps = max(2, self.cfg["mtu_confirm_attempts"])
        for label, size in sizes.items():
            s = 0
            for d in dests:
                for _ in range(reps):
                    total += 1
                    if self._probe(d, size, family).ok:
                        s += 1
                        okn += 1
            res[label] = {"mtu": size, "ok": s, "sent": len(dests) * reps}
        res["loss_rate"] = 1 - okn / total if total else 1.0
        return res

    # -- orchestration ---------------------------------------------------
    def run(self, family: str, dests: list, current_mtu: Optional[int],
            adapter: Optional[dict] = None) -> dict:
        lo = max(self.cfg["mtu_min"], IPV6_MIN_MTU if family == "ipv6" else 576)
        hi = self.cfg["mtu_max"]
        notes = []
        if current_mtu:
            if current_mtu < hi:
                notes.append(f"Upper bound limited to the current interface MTU ({current_mtu}): "
                             "Windows will not send larger packets than the interface MTU.")
            hi = min(hi, current_mtu)
        hi = max(hi, lo)
        self.progress(0.02, f"MTU {family}: baseline")
        base = self.baseline(dests, family)
        usable = [d for d, b in base.items() if b["state"] == "ok"]
        filtered = [d for d, b in base.items() if b["state"] == "icmp_filtered_or_unreachable"]
        unreliable = [d for d, b in base.items() if b["state"] == "unreliable"]
        if filtered:
            notes.append("ICMP appears filtered or destination unreachable: " + ", ".join(filtered))
        if unreliable:
            notes.append("Unreliable (lossy) destinations excluded: " + ", ".join(unreliable))
        result = {"family": family, "range": [lo, hi], "current_mtu": current_mtu,
                  "baseline": base, "destinations": {}, "notes": notes}
        if not usable:
            result.update({"recommended": None, "confidence": 0, "decision": "no_data",
                           "reasons": ["No destination answered ICMP reliably — ICMP may be "
                                       "filtered on this network. No MTU change is recommended."]})
            return self._finish(result)

        for i, d in enumerate(usable):
            self.progress(0.1 + 0.6 * i / len(usable), f"MTU {family}: binary search via {d}")
            s = self.search(d, lo, hi, family)
            if s["max"] is not None:
                s["confirm"] = self.confirm(d, s["max"], hi, family)
            result["destinations"][d] = s

        found = {d: s["max"] for d, s in result["destinations"].items()
                 if s.get("max") and s["confirm"]["passes"] == s["confirm"]["attempts"]}
        if not found:
            result.update({"recommended": None, "confidence": 0, "decision": "no_data",
                           "reasons": ["No destination produced a confirmed result."]})
            return self._finish(result)

        values = sorted(found.values())
        common = Counter(values).most_common()
        top_value, top_count = common[0]
        # outlier: one destination lower than >=2 agreeing others -> destination-specific
        agreeing = [d for d, v in found.items() if v == top_value]
        outliers = {d: v for d, v in found.items() if v != top_value}
        if top_count >= 2 and outliers:
            notes.append("Destination-specific limits ignored (others agree on "
                         f"{top_value}): " + ", ".join(f"{d}={v}" for d, v in outliers.items()))
            path_mtu = top_value
        else:
            path_mtu = min(values)       # conservative when there is no majority
            agreeing = [d for d, v in found.items() if v == path_mtu]

        self.progress(0.8, f"MTU {family}: final verification at {path_mtu}")
        verify_dests = [d for d in usable if found.get(d, 0) >= path_mtu] or usable
        verification = self.verify(verify_dests, path_mtu, family)

        # decision
        reasons = []
        decision = "keep"
        recommended = current_mtu or path_mtu
        enough_agreement = len(agreeing) >= 2
        if current_mtu and path_mtu >= current_mtu:
            reasons.append(f"The path carries the current MTU {current_mtu} without fragmentation "
                           f"(verified on {len(agreeing)} destination(s)). No change needed.")
        elif current_mtu and path_mtu < current_mtu:
            if enough_agreement and verification["loss_rate"] <= 0.1:
                decision, recommended = "lower", path_mtu
                reasons.append(f"Packets above {path_mtu} are dropped or need fragmentation on "
                               f"{len(agreeing)} independent destinations; current MTU "
                               f"{current_mtu} is too large for this path.")
            else:
                reasons.append(f"A lower limit ({path_mtu}) was seen, but it is not confirmed on "
                               "at least two destinations with low loss — keeping current MTU "
                               "(never lower MTU without strong evidence).")
        else:
            decision, recommended = "set", path_mtu
            reasons.append(f"Largest verified MTU: {path_mtu}.")

        # interpretation
        interp = self.interpret(path_mtu, family, adapter)
        reasons += interp
        mechanism = ("explicit 'fragmentation needed' replies" if self.counts["explicit_frag"]
                     else "silent drops of large packets (possible PMTU black hole)"
                     if self.counts["silent_drop"] else "no oversize packets observed")
        reasons.append(f"Limit evidence: {mechanism}. Loss events (inconclusive probes): "
                       f"{self.counts['loss_events']}.")

        conf = self.confidence(found, agreeing, result["destinations"], verification)
        if not enough_agreement:
            reasons.append("Only one destination gave a confirmed result — confidence reduced.")
        result.update({"path_mtu": path_mtu, "recommended": recommended, "decision": decision,
                       "agreeing_destinations": agreeing, "verification": verification,
                       "confidence": conf["score"], "confidence_parts": conf["parts"],
                       "reasons": reasons,
                       "evidence": {"explicit_frag": self.counts["explicit_frag"],
                                    "silent_drop": self.counts["silent_drop"],
                                    "loss_events": self.counts["loss_events"]}})
        return self._finish(result)

    def _finish(self, result: dict) -> dict:
        result["probes_sent"] = len(self.log)
        result["probe_log"] = self.log[-400:]
        self.progress(1.0, "MTU done")
        return result

    @staticmethod
    def interpret(path_mtu: int, family: str, adapter: Optional[dict]) -> list:
        out = []
        base = 1500
        if path_mtu == base - PPPOE_OVERHEAD:
            out.append("1492 = 1500 - 8 bytes: consistent with PPPoE encapsulation on the path "
                       "(common on DSL/VDSL), but this is an inference, not proof.")
        elif path_mtu in KNOWN_TUNNEL_MTUS:
            out.append(f"{path_mtu} matches {KNOWN_TUNNEL_MTUS[path_mtu]} encapsulation.")
        if adapter:
            if adapter.get("is_pppoe"):
                out.append("The active adapter is a PPPoE connection on this PC.")
            if adapter.get("is_vpn"):
                out.append("A VPN/tunnel adapter is active: its MTU applies only to tunnelled traffic.")
        return out

    @staticmethod
    def confidence(found: dict, agreeing: list, dests: dict, verification: dict) -> dict:
        n = len(agreeing)
        agreement = {0: 0.0, 1: 0.25, 2: 0.8}.get(n, 1.0)
        conf_rates = [s["confirm"]["passes"] / s["confirm"]["attempts"]
                      for d, s in dests.items() if s.get("max") and d in agreeing]
        confirmation = sum(conf_rates) / len(conf_rates) if conf_rates else 0.0
        bounds = [s["confirm"]["boundary_fails"] for d, s in dests.items()
                  if d in agreeing and s.get("confirm")]
        known = [b for b in bounds if b is not None]
        # boundary None means we hit the upper bound (current MTU) -> fully consistent
        boundary = (sum(known) / len(known)) if known else 1.0
        ver = 1.0 - verification.get("loss_rate", 1.0)
        parts = {"agreement": agreement, "confirmation": confirmation,
                 "boundary": boundary, "verification": ver}
        score = sum(parts[k] * CONF_WEIGHTS[k] for k in CONF_WEIGHTS)
        if n < 2:
            score = min(score, SINGLE_DESTINATION_CAP)   # never trust a single destination
        return {"score": round(score), "parts": {k: round(v * 100) for k, v in parts.items()}}


def run_mtu(probe: ProbeFn, cfg: dict, family: str, dests: list,
            current_mtu: Optional[int], adapter: Optional[dict] = None, ctx=None,
            progress=None) -> dict:
    return MtuEngine(probe, cfg, ctx, progress).run(family, dests, current_mtu, adapter)
