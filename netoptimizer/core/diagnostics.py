"""Additional network tools. All are light-weight, on-demand tests."""
from __future__ import annotations

import http.client
import socket
import time
from typing import Optional

from . import dnswire, stats

LEAK_DISCLAIMER = ("This diagnostic shows which DNS resolvers answered your queries. It is NOT a "
                   "proof of privacy or anonymity: other traffic, apps, browsers (DNS-over-HTTPS), "
                   "and your ISP may still observe your activity.")


def tcp_check(host: str, port: int, timeout: float = 3.0) -> dict:
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.connect((host, port))
        return {"target": f"{host}:{port}", "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1)}
    except OSError as e:
        return {"target": f"{host}:{port}", "ok": False, "error": str(e)}
    finally:
        s.close()


def system_resolve(name: str, family=socket.AF_UNSPEC) -> dict:
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)
        addrs = sorted({i[4][0] for i in infos})
        return {"name": name, "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1), "addresses": addrs}
    except socket.gaierror as e:
        return {"name": name, "ok": False, "error": str(e)}


def connectivity() -> dict:
    checks = {
        "tcp_ipv4": tcp_check("1.1.1.1", 443),
        "tcp_ipv4_alt": tcp_check("8.8.8.8", 443),
        "system_dns": system_resolve("www.microsoft.com"),
    }
    try:
        t0 = time.perf_counter()
        c = http.client.HTTPConnection("www.msftconnecttest.com", 80, timeout=5)
        c.request("GET", "/connecttest.txt")
        r = c.getresponse()
        body = r.read(200).decode(errors="replace")
        checks["http"] = {"ok": r.status == 200 and "Microsoft Connect Test" in body,
                          "status": r.status, "ms": round((time.perf_counter() - t0) * 1000, 1),
                          "captive_portal_suspected": r.status == 200 and "Microsoft Connect Test" not in body}
    except OSError as e:
        checks["http"] = {"ok": False, "error": str(e)}
    online = checks["tcp_ipv4"]["ok"] or checks["tcp_ipv4_alt"]["ok"]
    return {"online": online, "dns_working": checks["system_dns"]["ok"],
            "http_working": checks["http"]["ok"], "checks": checks}


def ip_versions() -> dict:
    v4 = [tcp_check("1.1.1.1", 443), tcp_check("8.8.8.8", 443)]
    v6 = [tcp_check("2606:4700:4700::1111", 443), tcp_check("2001:4860:4860::8888", 443)]
    aaaa = system_resolve("www.google.com", socket.AF_INET6)
    return {"ipv4": any(x["ok"] for x in v4), "ipv6": any(x["ok"] for x in v6),
            "ipv6_dns_aaaa": aaaa["ok"], "details": {"ipv4": v4, "ipv6": v6, "aaaa": aaaa}}


def public_ip(query_fn=dnswire.query) -> dict:
    """Public IP via DNS (no web service needed)."""
    out = {}
    r = query_fn("208.67.222.222", "myip.opendns.com", dnswire.TYPE_A, 3)
    out["ipv4"] = r.answers[0] if r.ok and r.answers else None
    if not out["ipv4"]:
        r = query_fn("216.239.32.10", "o-o.myaddr.l.google.com", dnswire.TYPE_TXT, 3)
        out["ipv4"] = r.answers[0] if r.ok and r.answers else None
    r6 = query_fn("2620:119:35::35", "myip.opendns.com", dnswire.TYPE_AAAA, 3)
    out["ipv6"] = r6.answers[0] if r6.ok and r6.answers else None
    return out


def dns_leak(configured_dns: list, query_fn=dnswire.query) -> dict:
    """Which resolver egress addresses are seen by authoritative servers?"""
    seen = []
    via_system = system_resolve("whoami.akamai.net", socket.AF_INET)
    if via_system["ok"]:
        seen.append({"path": "system resolver", "resolver_egress_ip": via_system["addresses"]})
    for srv in configured_dns[:4]:
        r = query_fn(srv, "o-o.myaddr.l.google.com", dnswire.TYPE_TXT, 3)
        if r.ok:
            seen.append({"path": f"configured DNS {srv}", "resolver_egress_ip": r.answers})
        r2 = query_fn(srv, "whoami.akamai.net", dnswire.TYPE_A, 3)
        if r2.ok:
            seen.append({"path": f"configured DNS {srv} (akamai)", "resolver_egress_ip": r2.answers})
    egress = sorted({ip for s in seen for ip in s["resolver_egress_ip"] if not ip.startswith("edns0")})
    return {"configured_dns": configured_dns, "observations": seen, "distinct_resolvers": egress,
            "note": LEAK_DISCLAIMER}


def dns_resolution(servers: list, query_fn=dnswire.query) -> dict:
    names = ["www.google.com", "www.microsoft.com", "www.wikipedia.org", "github.com"]
    rows = []
    for srv in servers[:4]:
        qt4 = dnswire.TYPE_A
        for n in names:
            for qt in (qt4, dnswire.TYPE_AAAA):
                r = query_fn(srv, n, qt, 3)
                rows.append({"server": srv, "name": n, "type": "A" if qt == qt4 else "AAAA",
                             "ok": r.ok, "ms": round(r.latency_ms, 1) if r.latency_ms else None,
                             "rcode": dnswire.RCODE_NAMES.get(r.rcode, r.rcode) if r.rcode is not None else None,
                             "answers": r.answers or [], "error": r.error})
        bogus = f"{dnswire.random_label(16)}.com"
        r = query_fn(srv, bogus, qt4, 3)
        rows.append({"server": srv, "name": bogus, "type": "A (non-existent)", "ok": r.ok,
                     "ms": round(r.latency_ms, 1) if r.latency_ms else None,
                     "rcode": dnswire.RCODE_NAMES.get(r.rcode, r.rcode) if r.rcode is not None else None,
                     "answers": r.answers or [], "error": r.error,
                     "nxdomain_hijack": bool(r.ok and r.rcode == 0 and r.answers)})
    return {"rows": rows, "hijack_suspected": any(r.get("nxdomain_hijack") for r in rows)}


def ping_series(probe, target: str, count: int = 20, ctx=None) -> dict:
    lat, okn = [], 0
    for _ in range(count):
        if ctx:
            ctx.check()
        p = probe(target, 32, False, 1000)
        if p.ok:
            okn += 1
            if p.rtt_ms is not None:
                lat.append(p.rtt_ms)
        if ctx:
            ctx.sleep(0.2)
        else:
            time.sleep(0.2)
    s = stats.summarize(lat)
    jitter = stats.mean([abs(a - b) for a, b in zip(lat, lat[1:])]) if len(lat) > 1 else None
    return {"target": target, "sent": count, "received": okn,
            "loss": 1 - okn / count if count else None, "latency": s, "jitter_ms": jitter}


def packet_loss(probe, targets: list, count: int, ctx=None) -> dict:
    return {"targets": [ping_series(probe, t, count, ctx) for t in targets]}


def gateway_latency(probe, gateway: Optional[str], count: int = 20, ctx=None) -> dict:
    if not gateway:
        return {"error": "no default gateway"}
    return ping_series(probe, gateway, count, ctx)
