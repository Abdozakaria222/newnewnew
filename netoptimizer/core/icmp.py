"""ICMP echo probes with the Don't-Fragment bit.

Windows IPv4: the native IcmpSendEcho API (iphlpapi.dll) with IP_FLAG_DF.
  This is locale-independent (no parsing of translated ping.exe output) and
  needs no administrator rights.
Windows IPv6: IPv6 routers never fragment; the source host may. We send the
  echo with ping.exe and then read the kernel's Path-MTU cache
  (netsh interface ipv6 show destinationcache) — the PMTU learnt from real
  "Packet Too Big" messages is the authoritative evidence.
Linux/macOS (development): ping -M do / -D.

Every probe returns one of: ok, frag_needed, timeout, unreachable, error.
"""
from __future__ import annotations

import ctypes
import ipaddress
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional

IP_SUCCESS = 0
IP_DEST_NET_UNREACHABLE = 11002
IP_DEST_HOST_UNREACHABLE = 11003
IP_PACKET_TOO_BIG = 11009
IP_REQ_TIMED_OUT = 11010
IP_TTL_EXPIRED_TRANSIT = 11013
IP_FLAG_DF = 0x02

CREATE_NO_WINDOW = 0x08000000


@dataclass
class Probe:
    status: str
    rtt_ms: Optional[float] = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def _run(cmd: list, timeout: float) -> subprocess.CompletedProcess:
    kw = {}
    if sys.platform == "win32":
        kw["creationflags"] = CREATE_NO_WINDOW
    return subprocess.run(cmd, capture_output=True, timeout=timeout, **kw)


class WindowsIcmp:
    def __init__(self):
        self.lib = ctypes.WinDLL("iphlpapi", use_last_error=True)

        class IP_OPTION_INFORMATION(ctypes.Structure):
            _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte),
                        ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte),
                        ("OptionsData", ctypes.c_void_p)]

        class ICMP_ECHO_REPLY(ctypes.Structure):
            _fields_ = [("Address", ctypes.c_ulong), ("Status", ctypes.c_ulong),
                        ("RoundTripTime", ctypes.c_ulong), ("DataSize", ctypes.c_ushort),
                        ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                        ("Options", IP_OPTION_INFORMATION)]

        self.OPT, self.REPLY = IP_OPTION_INFORMATION, ICMP_ECHO_REPLY
        self.lib.IcmpCreateFile.restype = ctypes.c_void_p
        self.lib.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        self.lib.IcmpSendEcho.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
                                          ctypes.c_ushort, ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_ulong, ctypes.c_ulong]
        self.lib.IcmpSendEcho.restype = ctypes.c_ulong

    def probe4(self, dest: str, payload: int, df: bool, timeout_ms: int) -> Probe:
        handle = self.lib.IcmpCreateFile()
        if not handle or handle == ctypes.c_void_p(-1).value:
            return Probe("error", detail="IcmpCreateFile failed")
        try:
            addr = int.from_bytes(socket.inet_aton(dest), "little")
            data = (ctypes.c_ubyte * max(payload, 1))(*([0x61] * max(payload, 1)))
            opts = self.OPT(128, 0, IP_FLAG_DF if df else 0, 0, None)
            size = ctypes.sizeof(self.REPLY) + payload + 64
            buf = ctypes.create_string_buffer(size)
            n = self.lib.IcmpSendEcho(handle, addr, data, payload, ctypes.byref(opts),
                                      buf, size, timeout_ms)
            if n == 0:
                status = ctypes.get_last_error()
                rtt = None
            else:
                reply = self.REPLY.from_buffer_copy(buf)
                status, rtt = reply.Status, float(reply.RoundTripTime)
            return Probe(_map_status(status), rtt, f"status={status}")
        finally:
            self.lib.IcmpCloseHandle(handle)


def _map_status(code: int) -> str:
    if code == IP_SUCCESS:
        return "ok"
    if code == IP_PACKET_TOO_BIG:
        return "frag_needed"
    if code == IP_REQ_TIMED_OUT:
        return "timeout"
    if code in (IP_DEST_NET_UNREACHABLE, IP_DEST_HOST_UNREACHABLE, IP_TTL_EXPIRED_TRANSIT, 11004, 11005):
        return "unreachable"
    return "error"


_PMTU_ROW = re.compile(r"^\s*(\d{3,5})\s+(\S+)")


def parse_destination_cache(text: str, address: str) -> Optional[int]:
    """Parse `netsh interface ipv6 show destinationcache` output (any locale:
    rows are 'PMTU  Destination  NextHop')."""
    try:
        target = ipaddress.ip_address(address)
    except ValueError:
        return None
    for line in text.splitlines():
        m = _PMTU_ROW.match(line)
        if not m:
            continue
        try:
            if ipaddress.ip_address(m.group(2)) == target:
                return int(m.group(1))
        except ValueError:
            continue
    return None


_LINUX_RTT = re.compile(r"time[=<]([\d.]+)")


class SystemIcmp:
    """Platform dispatcher used by the MTU engine."""

    def __init__(self):
        self.win = None
        if sys.platform == "win32":
            try:
                self.win = WindowsIcmp()
            except OSError:
                self.win = None

    def probe(self, dest: str, payload: int, df: bool = True, timeout_ms: int = 1000) -> Probe:
        v6 = ":" in dest
        try:
            if sys.platform == "win32":
                if not v6 and self.win:
                    return self.win.probe4(dest, payload, df, timeout_ms)
                return self._win_ping6(dest, payload, timeout_ms)
            return self._posix_ping(dest, payload, df, timeout_ms, v6)
        except (OSError, subprocess.SubprocessError) as e:
            return Probe("error", detail=str(e))

    def _win_ping6(self, dest: str, payload: int, timeout_ms: int) -> Probe:
        t0 = time.perf_counter()
        r = _run(["ping", "-6", "-n", "1", "-w", str(timeout_ms), "-l", str(payload), dest],
                 timeout_ms / 1000 + 5)
        rtt = (time.perf_counter() - t0) * 1000
        out = r.stdout.decode(errors="replace")
        cache = _run(["netsh", "interface", "ipv6", "show", "destinationcache",
                      f"address={dest}"], 10).stdout.decode(errors="replace")
        pmtu = parse_destination_cache(cache, dest)
        if pmtu is not None and pmtu < payload + 48:
            return Probe("frag_needed", None, f"kernel PMTU {pmtu}")
        if r.returncode == 0 and "=" in out:
            return Probe("ok", rtt, f"pmtu={pmtu}")
        return Probe("timeout", None, "no reply")

    def _posix_ping(self, dest: str, payload: int, df: bool, timeout_ms: int, v6: bool) -> Probe:
        cmd = ["ping", "-c", "1", "-s", str(payload)]
        if sys.platform == "darwin":
            cmd += ["-W", str(timeout_ms)] + (["-D"] if df and not v6 else [])
            if v6:
                cmd[0] = "ping6"
        else:
            cmd += ["-W", str(max(1, timeout_ms // 1000))]
            if df:
                cmd += ["-M", "do"]
            if v6:
                cmd.append("-6")
        r = _run(cmd + [dest], timeout_ms / 1000 + 5)
        out = (r.stdout + r.stderr).decode(errors="replace").lower()
        if "message too long" in out or "frag needed" in out or "packet too big" in out:
            return Probe("frag_needed", detail="frag needed")
        if r.returncode == 0:
            m = _LINUX_RTT.search(out)
            return Probe("ok", float(m.group(1)) if m else None)
        if "unreachable" in out:
            return Probe("unreachable")
        return Probe("timeout")
