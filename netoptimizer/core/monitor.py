"""Network change detection.

Every N seconds a *cheap* signature (ipconfig + netsh wlan output hash) is
computed. Only when it changes is a full snapshot taken and diffed to decide
what happened. No benchmarks run in the background — the UI only offers to
re-run tests.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Callable, Optional

from . import netinfo

log = logging.getLogger("netopt.monitor")


def diff_snapshots(old: dict, new: dict) -> list:
    """Classify the differences between two snapshots into user events."""
    ev = []
    oa = {a["alias"]: a for a in old.get("adapters", [])}
    na = {a["alias"]: a for a in new.get("adapters", [])}
    op, np_ = old.get("primary") or {}, new.get("primary") or {}

    for alias in na.keys() - oa.keys():
        ev.append(("adapter_added", f"New adapter: {alias}"))
    for alias in oa.keys() - na.keys():
        ev.append(("adapter_removed", f"Adapter removed: {alias}"))
    if op.get("alias") != np_.get("alias"):
        ev.append(("adapter_changed", f"Active adapter: {op.get('alias') or '-'} → {np_.get('alias') or '-'}"))

    for alias in na.keys() & oa.keys():
        a, b = oa[alias], na[alias]
        if a["is_wifi"] and a.get("ssid") != b.get("ssid"):
            ev.append(("wifi_changed", f"Wi-Fi network: {a.get('ssid') or '-'} → {b.get('ssid') or '-'}"))
        if b["is_ethernet"] and not a["up"] and b["up"]:
            ev.append(("ethernet_reconnected", f"Ethernet reconnected: {alias}"))
        if b["is_ethernet"] and a["up"] and not b["up"]:
            ev.append(("ethernet_disconnected", f"Ethernet disconnected: {alias}"))
        if a["is_vpn"] and a["up"] != b["up"]:
            ev.append(("vpn_connected" if b["up"] else "vpn_disconnected",
                       f"VPN {'connected' if b['up'] else 'disconnected'}: {alias}"))
        if a["gateway4"] != b["gateway4"] or a["gateway6"] != b["gateway6"]:
            ev.append(("gateway_changed", f"Default gateway on {alias}: "
                       f"{','.join(a['gateway4']) or '-'} → {','.join(b['gateway4']) or '-'}"))
        if a["ipv4"] != b["ipv4"] or a["ipv6"] != b["ipv6"] or a["dns4"] != b["dns4"] \
                or a["dns6"] != b["dns6"] or a["mtu4"] != b["mtu4"]:
            ev.append(("ip_config_changed", f"IP configuration changed on {alias}"))
    for alias in na.keys() - oa.keys():
        if na[alias]["is_vpn"] and na[alias]["up"]:
            ev.append(("vpn_connected", f"VPN connected: {alias}"))
    for alias in oa.keys() - na.keys():
        if oa[alias]["is_vpn"] and oa[alias]["up"]:
            ev.append(("vpn_disconnected", f"VPN disconnected: {alias}"))
    if old.get("fingerprint") != new.get("fingerprint"):
        ev.append(("network_profile_changed", "Network profile changed"))
    # de-duplicate while keeping order
    seen, out = set(), []
    for e in ev:
        if e not in seen:
            seen.add(e)
            out.append({"type": e[0], "message": e[1]})
    return out


RERUN_HINT = {
    "wifi_changed": ["dns", "mtu"], "ethernet_reconnected": ["dns", "mtu"],
    "adapter_changed": ["dns", "mtu"], "gateway_changed": ["dns", "mtu"],
    "vpn_connected": ["mtu", "dns"], "vpn_disconnected": ["mtu", "dns"],
    "network_profile_changed": ["dns", "mtu"], "ip_config_changed": ["dns"],
}


class Monitor:
    def __init__(self, interval_s: Callable[[], int], on_snapshot: Callable[[dict, list], None],
                 snapshot_fn=netinfo.snapshot, signature_fn=netinfo.light_signature):
        self.interval_s = interval_s
        self.on_snapshot = on_snapshot
        self.snapshot_fn = snapshot_fn
        self.signature_fn = signature_fn
        self.events: deque = deque(maxlen=100)
        self._seq = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_snapshot: Optional[dict] = None
        self._sig: Optional[str] = None

    def start(self, initial: Optional[dict] = None) -> None:
        self.last_snapshot = initial
        self._sig = self.signature_fn()
        self._thread = threading.Thread(target=self._loop, name="monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def check_once(self) -> list:
        sig = self.signature_fn()
        if sig == self._sig:
            return []
        self._sig = sig
        new = self.snapshot_fn()
        events = diff_snapshots(self.last_snapshot or {}, new) if self.last_snapshot else []
        self.last_snapshot = new
        stamped = []
        for e in events:
            self._seq += 1
            e.update(id=self._seq, time=time.strftime("%H:%M:%S"), rerun=RERUN_HINT.get(e["type"], []))
            self.events.append(e)
            stamped.append(e)
        self.on_snapshot(new, stamped)
        return stamped

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_s()):
            try:
                self.check_once()
            except Exception as e:
                log.warning("monitor check failed: %s", e)

    def since(self, last_id: int) -> list:
        return [e for e in self.events if e["id"] > last_id]
