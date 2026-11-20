"""Turns the engines' detailed results into ONE simple, plain-language verdict
per topic (DNS / MTU). Pure functions - no GUI code - so they are unit-tested.

Verdict levels:  "change" (apply recommended)  |  "ok" (keep what you have)
                 |  "unsure" (not enough evidence)  |  "none" (not tested yet)
"""
from __future__ import annotations

from typing import Optional


def _ms(v) -> str:
    return f"{v:.0f}" if isinstance(v, (int, float)) and v >= 10 else (f"{v:.1f}" if isinstance(v, (int, float)) else "—")


def confidence_label(score) -> str:
    if score is None:
        return ""
    if score >= 80:
        return "ثقة عالية"
    if score >= 55:
        return "ثقة متوسطة"
    return "ثقة منخفضة"


def _row_for(result: dict, provider) -> Optional[dict]:
    for r in result.get("providers", []) or []:
        if r.get("provider") == provider:
            return r
    return None


def dns_verdict(result: Optional[dict], current_dns: list) -> dict:
    """result = one family's run_benchmark() output."""
    if not result:
        return {"level": "none", "title": "لم يتم الاختبار بعد", "detail": "", "apply": None,
                "rows": [], "reasons": []}
    if result.get("skipped"):
        return {"level": "none", "title": "غير متاح على شبكتك", "detail": result["skipped"],
                "apply": None, "rows": [], "reasons": []}
    rec = result.get("recommendation") or {}
    rows = []
    for r in (result.get("providers") or [])[:8]:
        m = r.get("metrics") or {}
        rows.append({"name": r.get("name"), "primary": r.get("primary"),
                     "score": r.get("score"), "median": m.get("median"),
                     "success": m.get("success_rate"), "eligible": r.get("eligible", True),
                     "is_best": r.get("provider") == rec.get("provider")})
    if not rec.get("provider"):
        return {"level": "unsure", "title": "مفيش DNS مناسب للتوصية",
                "detail": "ولا واحد من السيرفرات وصل لنسبة نجاح كافية. الأفضل متغيّرش حاجة.",
                "apply": None, "rows": rows, "reasons": rec.get("reasons", [])}
    best_row = _row_for(result, rec["provider"]) or {}
    m = best_row.get("metrics") or {}
    speed = f"متوسط الاستجابة {_ms(m.get('median'))} ms ونسبة نجاح {m.get('success_rate', 0):.0%}"
    if rec.get("keep_current"):
        sysrow = _row_for(result, "system")
        cur = f" ({', '.join(current_dns)})" if current_dns else ""
        extra = ""
        if sysrow and (sysrow.get("metrics") or {}).get("median") is not None:
            extra = f" — استجابته {_ms(sysrow['metrics']['median'])} ms"
        return {"level": "ok", "title": "الـ DNS الحالي كويس، متغيّرهوش",
                "detail": f"الـ DNS اللي شغال عندك{cur}{extra} قريب جدًا من الأفضل ({rec['name']})، "
                          "والفرق أقل من تذبذب القياس.",
                "apply": None, "best": rec, "rows": rows, "reasons": rec.get("reasons", [])}
    servers = [x for x in (rec.get("primary"), rec.get("secondary")) if x]
    gain = ""
    sysrow = _row_for(result, "system")
    if sysrow and (sysrow.get("metrics") or {}).get("median") and m.get("median"):
        d = sysrow["metrics"]["median"] - m["median"]
        if d > 0:
            gain = f" أسرع من الحالي بحوالي {_ms(d)} ms."
    return {"level": "change", "title": f"أفضل DNS: {rec['name']}",
            "detail": f"{speed}.{gain}", "apply": servers, "best": rec,
            "rows": rows, "reasons": rec.get("reasons", [])}


def mtu_verdict(result: Optional[dict], current_mtu) -> dict:
    if not result:
        return {"level": "none", "title": "لم يتم الاختبار بعد", "detail": "", "apply": None,
                "reasons": []}
    if result.get("skipped"):
        return {"level": "none", "title": "غير متاح على شبكتك", "detail": result["skipped"],
                "apply": None, "reasons": []}
    dec = result.get("decision")
    conf = result.get("confidence")
    label = confidence_label(conf)
    reasons = result.get("reasons", [])
    path = result.get("path_mtu")
    if dec == "no_data" or not path:
        return {"level": "unsure", "title": "مقدرناش نقيس الـ MTU",
                "detail": "الشبكة ما ردتش على اختبار الحزم الكبيرة (غالبًا ICMP محجوب أو لا يوجد اتصال). "
                          "متغيّرش حاجة.", "apply": None, "reasons": reasons}
    if dec == "keep":
        return {"level": "ok", "title": f"الـ MTU الحالي ({current_mtu}) مناسب",
                "detail": f"الشبكة بتمرّر الحزم لحد {path} من غير تقطيع. {label}.",
                "apply": None, "reasons": reasons}
    if dec in ("lower", "set"):
        word = "اخفضه" if dec == "lower" else "اضبطه"
        cur = f" (الحالي {current_mtu})" if current_mtu else ""
        return {"level": "change", "title": f"أفضل MTU: {result['recommended']}",
                "detail": f"{word} إلى {result['recommended']}{cur}. {label} ({conf}/100).",
                "apply": result["recommended"], "reasons": reasons}
    return {"level": "unsure", "title": "النتيجة غير مؤكدة",
            "detail": "الأدلة مش كافية. الأفضل متغيّرش حاجة.", "apply": None, "reasons": reasons}


def summarize(state: dict, results: dict, family: str = "ipv4") -> dict:
    """Everything the main screen needs, in one dict."""
    p = state.get("primary") or {}
    cur_dns = p.get("dns4" if family == "ipv4" else "dns6") or []
    cur_mtu = p.get("mtu4" if family == "ipv4" else "mtu6")
    dns = dns_verdict((results.get("dns") or {}).get(family), cur_dns)
    mtu = mtu_verdict((results.get("mtu") or {}).get(family), cur_mtu)
    plan = {}
    if dns["apply"]:
        plan["dns4" if family == "ipv4" else "dns6"] = dns["apply"]
    if mtu["apply"]:
        plan["mtu4" if family == "ipv4" else "mtu6"] = mtu["apply"]
    return {"network": network_line(p), "dns": dns, "mtu": mtu, "plan": plan,
            "current": {"dns": cur_dns, "mtu": cur_mtu}}


def network_line(p: dict) -> str:
    if not p:
        return "لا يوجد اتصال شبكة نشط"
    kind = {"wifi": "Wi-Fi", "ethernet": "Ethernet"}.get(p.get("kind"), p.get("kind") or "")
    return " · ".join(x for x in (p.get("alias"), kind, p.get("ssid")) if x)
