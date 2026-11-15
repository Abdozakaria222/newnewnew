"""User settings with safe defaults, validation, and app data paths."""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys

APP_NAME = "NetworkOptimizer"
APP_VERSION = "2.0.0"


def data_dir() -> str:
    override = os.environ.get("NETOPT_DATA_DIR")
    if override:
        base = override
    elif sys.platform == "win32":
        base = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), APP_NAME)
    else:
        base = os.path.join(os.path.expanduser("~"), ".local", "share", APP_NAME)
    os.makedirs(base, exist_ok=True)
    return base


def path(*parts: str) -> str:
    p = os.path.join(data_dir(), *parts)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    return p


# name: (default, type, min, max / allowed values)
SCHEMA = {
    "dns_rounds":            (3, int, 1, 10),
    "dns_domains":           (8, int, 3, 20),
    "dns_timeout_ms":        (2000, int, 300, 10000),
    "dns_test_secondary":    (True, bool, None, None),
    "dns_concurrency":       (4, int, 1, 8),
    "mtu_min":               (1280, int, 576, 1500),
    "mtu_max":               (1500, int, 576, 9000),
    "mtu_confirm_attempts":  (3, int, 1, 10),
    "mtu_ping_timeout_ms":   (1000, int, 200, 5000),
    "mtu_destinations":      ("1.1.1.1,8.8.8.8,9.9.9.9", str, None, None),
    "mtu_destinations_v6":   ("2606:4700:4700::1111,2001:4860:4860::8888,2620:fe::fe", str, None, None),
    "test_ipv4":             (True, bool, None, None),
    "test_ipv6":             (True, bool, None, None),
    "auto_profile":          (True, bool, None, None),
    "benchmark_logging":     (True, bool, None, None),
    "monitor_enabled":       (True, bool, None, None),
    "monitor_interval_s":    (15, int, 5, 300),
    "compare_samples":       (20, int, 5, 100),
    "theme":                 ("dark", str, None, ("dark", "light")),
    "language":              ("ar", str, None, ("ar", "en")),
}


def defaults() -> dict:
    return {k: v[0] for k, v in SCHEMA.items()}


def coerce(key: str, value):
    if key not in SCHEMA:
        raise KeyError(key)
    default, typ, lo, hi = SCHEMA[key]
    if typ is bool:
        if isinstance(value, str):
            value = value.lower() in ("1", "true", "yes", "on")
        return bool(value)
    if typ is int:
        value = int(value)
        return max(lo, min(hi, value))
    value = str(value)
    if isinstance(hi, tuple) and value not in hi:
        return default
    return value[:500]


class Settings:
    def __init__(self, file: str | None = None):
        self.file = file or path("settings.json")
        self.values = defaults()
        self.load()

    def load(self) -> None:
        try:
            with open(self.file, encoding="utf-8") as f:
                stored = json.load(f)
            for k, v in stored.items():
                if k in SCHEMA:
                    try:
                        self.values[k] = coerce(k, v)
                    except (TypeError, ValueError):
                        pass
        except (OSError, json.JSONDecodeError):
            pass
        if self.values["mtu_max"] < self.values["mtu_min"]:
            self.values["mtu_max"] = self.values["mtu_min"]

    def update(self, changes: dict) -> dict:
        for k, v in changes.items():
            if k in SCHEMA:
                self.values[k] = coerce(k, v)
        if self.values["mtu_max"] < self.values["mtu_min"]:
            self.values["mtu_min"], self.values["mtu_max"] = self.values["mtu_max"], self.values["mtu_min"]
        self.save()
        return self.values

    def reset(self) -> dict:
        self.values = defaults()
        self.save()
        return self.values

    def save(self) -> None:
        tmp = self.file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.values, f, indent=2)
        os.replace(tmp, self.file)

    def __getitem__(self, k):
        return self.values[k]

    def list(self, key: str) -> list:
        return [x.strip() for x in str(self.values[key]).split(",") if x.strip()]


def setup_logging() -> str:
    log_file = path("logs", "netoptimizer.log")
    root = logging.getLogger("netopt")
    if not root.handlers:
        root.setLevel(logging.DEBUG)
        h = logging.handlers.RotatingFileHandler(log_file, maxBytes=2_000_000,
                                                 backupCount=5, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        root.addHandler(h)
        c = logging.StreamHandler()
        c.setLevel(logging.INFO)
        c.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        root.addHandler(c)
    return log_file
