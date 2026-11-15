"""DNS provider database: built-in list, custom providers, safe import/export.

The built-in list ships read-only inside the package. User additions and
imported lists are stored separately in the user data folder, so a broken
import can never corrupt the built-in database.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Iterable

BUILTIN_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "dns_providers.json")
SCHEMA_VERSION = 1
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,47}$")


@dataclass
class Provider:
    id: str
    name: str
    ipv4: list = field(default_factory=list)   # [primary, secondary]
    ipv6: list = field(default_factory=list)
    filtering: str = "none"                    # none / malware / family / ads
    source: str = "builtin"                    # builtin / custom / imported / system

    def servers(self, family: str) -> list:
        return list(self.ipv4 if family == "ipv4" else self.ipv6)


class ProviderError(ValueError):
    pass


def _valid_ip(s: str, version: int) -> str:
    try:
        ip = ipaddress.ip_address(str(s).strip())
    except ValueError:
        raise ProviderError(f"invalid IP address: {s!r}")
    if ip.version != version:
        raise ProviderError(f"{s} is not an IPv{version} address")
    if ip.is_multicast or ip.is_unspecified:
        raise ProviderError(f"{s} cannot be a DNS server")
    return str(ip)


def validate(raw: dict, source: str) -> Provider:
    if not isinstance(raw, dict):
        raise ProviderError("provider entry must be an object")
    pid = str(raw.get("id", "")).strip().lower()
    name = str(raw.get("name", "")).strip()[:64]
    if not _ID_RE.match(pid):
        raise ProviderError(f"invalid provider id: {pid!r}")
    if not name:
        raise ProviderError(f"provider {pid} has no name")
    v4 = [_valid_ip(x, 4) for x in (raw.get("ipv4") or [])][:2]
    v6 = [_valid_ip(x, 6) for x in (raw.get("ipv6") or [])][:2]
    if not v4 and not v6:
        raise ProviderError(f"provider {pid} has no addresses")
    filt = str(raw.get("filtering", "none"))
    if filt not in ("none", "malware", "family", "ads"):
        filt = "none"
    return Provider(pid, name, v4, v6, filt, source)


def _atomic_write_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


class ProviderDB:
    def __init__(self, user_path: str, builtin_path: str = BUILTIN_PATH):
        self.user_path = user_path
        self.builtin_path = builtin_path

    def builtin(self) -> list[Provider]:
        with open(self.builtin_path, encoding="utf-8") as f:
            data = json.load(f)
        return [validate(p, "builtin") for p in data["providers"]]

    def custom(self) -> list[Provider]:
        if not os.path.exists(self.user_path):
            return []
        try:
            with open(self.user_path, encoding="utf-8") as f:
                data = json.load(f)
            out = []
            for p in data.get("providers", []):
                try:
                    out.append(validate(p, p.get("source", "custom")))
                except ProviderError:
                    continue
            return out
        except (OSError, json.JSONDecodeError):
            return []

    def all(self, system_dns: Iterable[str] = ()) -> list[Provider]:
        merged: dict[str, Provider] = {p.id: p for p in self.builtin()}
        for p in self.custom():
            merged[p.id] = p            # user entries override by id
        sys_v4 = [s for s in system_dns if ":" not in s][:2]
        sys_v6 = [s for s in system_dns if ":" in s and not s.lower().startswith("fec0")][:2]
        if sys_v4 or sys_v6:
            merged["system"] = Provider("system", "Current system DNS", sys_v4, sys_v6, "none", "system")
        return list(merged.values())

    def _save_custom(self, providers: list[Provider]) -> None:
        _atomic_write_json(self.user_path, {"schema": SCHEMA_VERSION,
                                            "providers": [asdict(p) for p in providers]})

    def add_custom(self, raw: dict) -> Provider:
        p = validate(raw, "custom")
        if p.id in {b.id for b in self.builtin()} or p.id == "system":
            raise ProviderError(f"id {p.id!r} is reserved by a built-in provider")
        current = [c for c in self.custom() if c.id != p.id]
        self._save_custom(current + [p])
        return p

    def remove_custom(self, pid: str) -> bool:
        current = self.custom()
        kept = [c for c in current if c.id != pid]
        if len(kept) == len(current):
            return False
        self._save_custom(kept)
        return True

    def export(self, path: str, include_builtin: bool = True) -> int:
        items = (self.builtin() if include_builtin else []) + self.custom()
        _atomic_write_json(path, {"schema": SCHEMA_VERSION, "app": "NetworkOptimizer",
                                  "providers": [asdict(p) for p in items]})
        return len(items)

    def import_file(self, path: str) -> dict:
        """Import is all-or-report: invalid entries are skipped and listed,
        built-in ids are never overwritten."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return self.import_data(data)

    def import_data(self, data) -> dict:
        if isinstance(data, dict):
            entries = data.get("providers", [])
        elif isinstance(data, list):
            entries = data
        else:
            raise ProviderError("unsupported file format")
        if len(entries) > 500:
            raise ProviderError("too many providers in file (max 500)")
        builtin_ids = {b.id for b in self.builtin()}
        current = {c.id: c for c in self.custom()}
        added, skipped = [], []
        for raw in entries:
            try:
                p = validate(raw, "imported")
            except ProviderError as e:
                skipped.append(str(e))
                continue
            if p.id in builtin_ids or p.id == "system":
                skipped.append(f"{p.id}: built-in id, not overwritten")
                continue
            current[p.id] = p
            added.append(p.id)
        self._save_custom(list(current.values()))
        return {"added": added, "skipped": skipped}
