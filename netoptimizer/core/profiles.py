"""Smart network profiles: one local profile per detected network config.

Stored only on this PC (profiles.json in the app data folder). Original DNS
and MTU are recorded the first time a network is seen and never overwritten.
Old settings are never applied automatically — the UI only *offers* them.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Optional

MAX_HISTORY = 30


class ProfileStore:
    def __init__(self, file: str):
        self.file = file
        self._lock = threading.Lock()

    def _load(self) -> dict:
        try:
            with open(self.file, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    def _save(self, data: dict) -> None:
        tmp = self.file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.file)

    def all(self) -> dict:
        with self._lock:
            return self._load()

    def get(self, key: str) -> Optional[dict]:
        return self.all().get(key)

    def observe(self, snap: dict) -> tuple[Optional[dict], bool]:
        """Record that the network in `snap` is present.
        Returns (profile, is_known) where is_known means it was seen before."""
        a, key = snap.get("primary"), snap.get("fingerprint")
        if not a or not key:
            return None, False
        with self._lock:
            data = self._load()
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            known = key in data
            if not known:
                data[key] = {
                    "key": key, "created": now,
                    "label": a.get("ssid") or a.get("network_name") or a.get("alias"),
                    "adapter": {"alias": a["alias"], "description": a["description"],
                                "kind": a["kind"], "mac": a.get("mac"), "guid": a.get("guid")},
                    "gateway": (a.get("gateway4") or a.get("gateway6") or [None])[0],
                    "ssid": a.get("ssid"),
                    "original": {"dns4": a["dns4"], "dns6": a["dns6"],
                                 "dns4_source": a["dns4_source"], "dns6_source": a["dns6_source"],
                                 "mtu4": a["mtu4"], "mtu6": a["mtu6"],
                                 "ip4_source": a["ip4_source"], "recorded": now},
                    "best": {}, "history": [], "applied": None, "seen_count": 0,
                }
            p = data[key]
            p["last_seen"] = now
            p["seen_count"] = p.get("seen_count", 0) + 1
            self._save(data)
            return p, known

    def record_dns(self, key: str, family: str, result: dict) -> None:
        rec = result.get("recommendation") or {}
        self._record(key, {"type": "dns", "family": family,
                           "provider": rec.get("provider"), "name": rec.get("name"),
                           "primary": rec.get("primary"), "secondary": rec.get("secondary"),
                           "score": rec.get("score"),
                           "top": [{"name": r["name"], "score": r["score"],
                                    "median": r["metrics"]["median"],
                                    "p95": r["metrics"]["p95"],
                                    "success": r["metrics"]["success_rate"]}
                                   for r in result.get("providers", [])[:5]]},
                     best_key=f"dns_{family}" if rec.get("provider") else None,
                     best_val={"provider": rec.get("provider"), "name": rec.get("name"),
                               "primary": rec.get("primary"), "secondary": rec.get("secondary"),
                               "score": rec.get("score")})

    def record_mtu(self, key: str, family: str, result: dict) -> None:
        self._record(key, {"type": "mtu", "family": family,
                           "recommended": result.get("recommended"),
                           "path_mtu": result.get("path_mtu"),
                           "decision": result.get("decision"),
                           "confidence": result.get("confidence")},
                     best_key=f"mtu_{family}" if result.get("recommended") else None,
                     best_val={"mtu": result.get("recommended"),
                               "confidence": result.get("confidence")})

    def record_comparison(self, key: str, comparison: dict) -> None:
        self._record(key, {"type": "comparison", "verdict": comparison.get("verdict"),
                           "summary": comparison.get("summary")})

    def record_applied(self, key: str, applied: dict) -> None:
        with self._lock:
            data = self._load()
            if key in data:
                prev = data[key].get("applied")
                data[key]["previous_applied"] = prev
                data[key]["applied"] = dict(applied, at=time.strftime("%Y-%m-%d %H:%M:%S"))
                self._save(data)

    def _record(self, key: str, entry: dict, best_key=None, best_val=None) -> None:
        if not key:
            return
        with self._lock:
            data = self._load()
            if key not in data:
                return
            entry["date"] = time.strftime("%Y-%m-%d %H:%M:%S")
            p = data[key]
            p["history"] = (p.get("history", []) + [entry])[-MAX_HISTORY:]
            if best_key and best_val:
                p.setdefault("best", {})[best_key] = dict(best_val, date=entry["date"])
            p["last_test"] = entry["date"]
            self._save(data)

    def rename(self, key: str, label: str) -> bool:
        with self._lock:
            data = self._load()
            if key not in data:
                return False
            data[key]["label"] = str(label)[:60]
            self._save(data)
            return True

    def delete(self, key: str) -> bool:
        with self._lock:
            data = self._load()
            if data.pop(key, None) is None:
                return False
            self._save(data)
            return True
