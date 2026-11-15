"""Configuration backups. Rules:
* A new backup file is written before every change (timestamped, unique).
* The very first backup of each adapter is also kept as an 'original'
  backup that is never overwritten or rotated.
* Backups are never deleted automatically.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Optional

BACKUP_FIELDS = ("alias", "index", "guid", "description", "kind", "ipv4", "ipv6",
                 "gateway4", "gateway6", "ip4_source", "dns4", "dns6",
                 "dns4_source", "dns6_source", "mtu4", "mtu6")


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "_", s or "adapter")[:40]


class BackupStore:
    def __init__(self, folder: str):
        self.folder = folder
        os.makedirs(folder, exist_ok=True)

    def _write_new(self, name: str, obj: dict) -> str:
        """Create a file that does not exist yet (never overwrites)."""
        base, ext = os.path.splitext(name)
        for i in range(1000):
            candidate = os.path.join(self.folder, f"{base}{'' if i == 0 else f'-{i}'}{ext}")
            try:
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            except FileExistsError:
                continue
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
            return candidate
        raise RuntimeError("could not create a unique backup file")

    def create(self, adapter: dict, reason: str, profile_key: Optional[str] = None,
               applied_profile: Optional[dict] = None) -> dict:
        cfg = {k: adapter.get(k) for k in BACKUP_FIELDS}
        stamp = time.strftime("%Y%m%d-%H%M%S")
        obj = {"app": "NetworkOptimizer", "version": 1, "created": time.strftime("%Y-%m-%d %H:%M:%S"),
               "reason": reason, "profile_key": profile_key, "adapter": cfg,
               "applied_profile_before": applied_profile}
        original = os.path.join(self.folder, f"original-{_safe(adapter.get('guid') or adapter.get('alias'))}.json")
        if not os.path.exists(original):
            obj_o = dict(obj, kind="original")
            try:
                fd = os.open(original, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(obj_o, f, ensure_ascii=False, indent=2)
            except FileExistsError:
                pass
        path = self._write_new(f"backup-{stamp}-{_safe(adapter.get('alias'))}.json", dict(obj, kind="backup"))
        return {"file": os.path.basename(path), **obj}

    def list(self) -> list:
        out = []
        for name in sorted(os.listdir(self.folder), reverse=True):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.folder, name), encoding="utf-8") as f:
                    obj = json.load(f)
                obj["file"] = name
                out.append(obj)
            except (OSError, json.JSONDecodeError):
                continue
        # originals first, then newest
        out.sort(key=lambda b: (b.get("kind") != "original", b.get("created", "")), reverse=False)
        originals = [b for b in out if b.get("kind") == "original"]
        others = sorted([b for b in out if b.get("kind") != "original"],
                        key=lambda b: b.get("created", ""), reverse=True)
        return originals + others

    def get(self, name: str) -> Optional[dict]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.json", name or ""):
            return None
        p = os.path.join(self.folder, name)
        if not os.path.isfile(p):
            return None
        with open(p, encoding="utf-8") as f:
            obj = json.load(f)
        obj["file"] = name
        return obj

    def latest_for(self, alias: str) -> Optional[dict]:
        for b in self.list():
            if b.get("kind") != "original" and (b.get("adapter") or {}).get("alias") == alias:
                return b
        return None

    def original_for(self, adapter: dict) -> Optional[dict]:
        return self.get(f"original-{_safe(adapter.get('guid') or adapter.get('alias'))}.json")
