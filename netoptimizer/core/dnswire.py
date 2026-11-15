"""Minimal, dependency-free DNS wire protocol (RFC 1035) over UDP.

Used for *real* DNS query measurements: every timing returned here is the
round-trip of an actual query packet sent to the resolver under test.
"""
from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional

TYPE_A = 1
TYPE_TXT = 16
TYPE_AAAA = 28

RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
               4: "NOTIMP", 5: "REFUSED"}


@dataclass
class DnsResult:
    server: str
    qname: str
    qtype: int
    ok: bool                 # a valid response matching our query arrived
    latency_ms: Optional[float]
    rcode: Optional[int] = None
    answers: list = None     # parsed A/AAAA/TXT data
    error: str = ""          # "timeout", "mismatch", "socket: ..." ...

    @property
    def timeout(self) -> bool:
        return self.error == "timeout"


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("idna") if label else b""
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid DNS label in {name!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(qname: str, qtype: int = TYPE_A, txid: Optional[int] = None,
                recursion: bool = True) -> tuple[int, bytes]:
    if txid is None:
        txid = struct.unpack(">H", os.urandom(2))[0]
    flags = 0x0100 if recursion else 0x0000
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    return txid, header + encode_name(qname) + struct.pack(">HH", qtype, 1)


def _read_name(msg: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    while True:
        if off >= len(msg) or depth > 20:
            raise ValueError("bad name")
        ln = msg[off]
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", msg[off:off + 2])[0] & 0x3FFF
            name, _ = _read_name(msg, ptr, depth + 1)
            labels.append(name)
            return ".".join(x for x in labels if x), off + 2
        if ln == 0:
            return ".".join(labels), off + 1
        labels.append(msg[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln


def parse_response(msg: bytes, txid: int, qname: str, qtype: int) -> tuple[int, list]:
    """Validate a response against our query. Returns (rcode, answers).
    Raises ValueError if it is not a response to our query (anti-spoof check)."""
    if len(msg) < 12:
        raise ValueError("short response")
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    if rid != txid or not flags & 0x8000:
        raise ValueError("id/qr mismatch")
    off = 12
    for _ in range(qd):
        name, off = _read_name(msg, off)
        rqtype, _ = struct.unpack(">HH", msg[off:off + 4])
        off += 4
        if name.lower().rstrip(".") != qname.lower().rstrip(".") or rqtype != qtype:
            raise ValueError("question mismatch")
    answers = []
    for _ in range(an):
        _, off = _read_name(msg, off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        off += rdlen
        if rtype == TYPE_A and rdlen == 4:
            answers.append(socket.inet_ntop(socket.AF_INET, rdata))
        elif rtype == TYPE_AAAA and rdlen == 16:
            answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rtype == TYPE_TXT:
            i, parts = 0, []
            while i < len(rdata):
                n = rdata[i]
                parts.append(rdata[i + 1:i + 1 + n].decode("utf-8", "replace"))
                i += 1 + n
            answers.append("".join(parts))
    return flags & 0x000F, answers


def query(server: str, qname: str, qtype: int = TYPE_A, timeout: float = 2.0,
          port: int = 53) -> DnsResult:
    """Send one real UDP DNS query and time it with a monotonic clock."""
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    try:
        txid, packet = build_query(qname, qtype)
    except ValueError as e:
        return DnsResult(server, qname, qtype, False, None, error=str(e))
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.connect((server, port))       # connected UDP: only this server's replies
        start = time.perf_counter()
        sock.send(packet)
        deadline = start + timeout
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return DnsResult(server, qname, qtype, False, None, error="timeout")
            sock.settimeout(remaining)
            try:
                data = sock.recv(4096)
            except socket.timeout:
                return DnsResult(server, qname, qtype, False, None, error="timeout")
            elapsed = (time.perf_counter() - start) * 1000.0
            try:
                rcode, answers = parse_response(data, txid, qname, qtype)
            except ValueError:
                continue   # stray / spoofed packet: keep waiting for ours
            # NOERROR and NXDOMAIN are both valid, successful resolver answers.
            ok = rcode in (0, 3)
            return DnsResult(server, qname, qtype, ok, elapsed, rcode, answers,
                             "" if ok else RCODE_NAMES.get(rcode, f"rcode{rcode}"))
    except OSError as e:
        return DnsResult(server, qname, qtype, False, None, error=f"socket: {e}")
    finally:
        sock.close()


def random_label(n: int = 12) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(alphabet[b % len(alphabet)] for b in os.urandom(n))
