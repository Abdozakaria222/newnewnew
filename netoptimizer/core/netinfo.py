"""Network adapter discovery (no administrator rights needed).

Windows: one PowerShell call (Get-NetIPConfiguration / Get-NetAdapter /
Get-NetIPInterface / Get-DnsClientServerAddress / registry for static DNS)
returning JSON. PPPoE connections are RAS interfaces that Get-NetAdapter does
not list, so enumeration is based on Get-NetIPInterface.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
import sys
from typing import Optional

log = logging.getLogger("netopt.netinfo")
CREATE_NO_WINDOW = 0x08000000

PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$res = @()
$idxs = @(Get-NetIPInterface | Select-Object -ExpandProperty InterfaceIndex -Unique)
foreach ($idx in $idxs) {
  $c  = Get-NetIPConfiguration -InterfaceIndex $idx -Detailed
  $na = Get-NetAdapter -InterfaceIndex $idx
  $i4 = Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4
  $i6 = Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv6
  $alias = if ($c) { $c.InterfaceAlias } elseif ($i4) { $i4.InterfaceAlias } else { $i6.InterfaceAlias }
  if ($alias -like 'Loopback*' -or $alias -like 'isatap*' -or $alias -like 'Teredo*') { continue }
  $guid = if ($na) { [string]$na.InterfaceGuid } else { $null }
  $st4 = $null; $st6 = $null
  if ($guid) {
    $st4 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid").NameServer
    $st6 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$guid").NameServer
  }
  $gw4 = @($c.IPv4DefaultGateway | ForEach-Object { $_.NextHop })
  $gwmac = $null
  if ($gw4.Count -gt 0) { $gwmac = (Get-NetNeighbor -IPAddress $gw4[0] -InterfaceIndex $idx).LinkLayerAddress }
  $prof = Get-NetConnectionProfile -InterfaceIndex $idx
  $res += [pscustomobject]@{
    index = $idx; alias = $alias; guid = $guid
    description = if ($na) { $na.InterfaceDescription } else { $c.InterfaceDescription }
    status = if ($na) { [string]$na.Status } elseif ($i4) { [string]$i4.ConnectionState } else { [string]$i6.ConnectionState }
    mac = if ($na) { $na.MacAddress } else { $null }
    media = if ($na) { [string]$na.PhysicalMediaType } else { $null }
    iftype = if ($na) { $na.InterfaceType } else { $null }
    virtual = if ($na) { [bool]$na.Virtual } else { $null }
    hidden = if ($na) { [bool]$na.Hidden } else { $null }
    link_speed = if ($na) { [string]$na.LinkSpeed } else { $null }
    ipv4 = @($c.IPv4Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
    ipv6 = @($c.IPv6Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
    ipv6_ll = @($c.IPv6LinkLocalAddress | ForEach-Object { "$($_.IPAddress)" })
    gw4 = $gw4
    gw6 = @($c.IPv6DefaultGateway | ForEach-Object { $_.NextHop })
    gw_mac = $gwmac
    dns4 = @((Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4).ServerAddresses)
    dns6 = @((Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv6).ServerAddresses)
    dns4_static = $st4; dns6_static = $st6
    dhcp4 = if ($i4) { [string]$i4.Dhcp } else { $null }
    mtu4 = if ($i4) { $i4.NlMtu } else { $null }
    mtu6 = if ($i6) { $i6.NlMtu } else { $null }
    metric4 = if ($i4) { $i4.InterfaceMetric } else { $null }
    conn4 = if ($i4) { [string]$i4.ConnectionState } else { $null }
    profile_name = if ($prof) { $prof.Name } else { $null }
    profile_category = if ($prof) { [string]$prof.NetworkCategory } else { $null }
  }
}
ConvertTo-Json -InputObject @($res) -Depth 4 -Compress
"""

VPN_PATTERNS = re.compile(
    r"tap-windows|wireguard|wintun|openvpn|\bvpn\b|anyconnect|fortinet|forticlient|zerotier|"
    r"tailscale|pangp|palo alto|nordlynx|juniper|sonicwall|wan miniport \((ikev2|l2tp|pptp|sstp)\)|"
    r"proton|expressvpn|surfshark|hamachi|softether|cloudflare warp", re.I)
VIRTUAL_PATTERNS = re.compile(r"hyper-v|vmware|virtualbox|vethernet|loopback|bluetooth|"
                              r"kernel debug|wi-fi direct|microsoft wi-fi direct", re.I)
PPPOE_PATTERNS = re.compile(r"pppoe|wan miniport \(pppoe\)|broadband|ppp adapter", re.I)


def _run(cmd: list, timeout: float = 30) -> str:
    kw = {"creationflags": CREATE_NO_WINDOW} if sys.platform == "win32" else {}
    r = subprocess.run(cmd, capture_output=True, timeout=timeout, **kw)
    return r.stdout.decode("utf-8", errors="replace")


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, str):
        return [x for x in re.split(r"[,\s]+", v) if x]
    return [x for x in v if x]


def classify(raw: dict, ssid: Optional[str] = None) -> dict:
    """Normalise one raw adapter record and classify it."""
    desc = raw.get("description") or ""
    alias = raw.get("alias") or ""
    text = f"{alias} {desc}"
    iftype = raw.get("iftype")
    media = (raw.get("media") or "").lower()
    is_wifi = iftype == 71 or "802.11" in media or "native 802.11" in media or \
        bool(re.search(r"wi-?fi|wireless|wlan", text, re.I))
    is_pppoe = iftype == 23 or bool(PPPOE_PATTERNS.search(text))
    is_vpn = bool(VPN_PATTERNS.search(text)) or iftype == 131 and not is_pppoe
    is_virtual = bool(raw.get("virtual")) or bool(VIRTUAL_PATTERNS.search(text))
    is_ethernet = (iftype == 6 or "802.3" in media) and not is_wifi and not is_vpn and not is_virtual
    kind = ("pppoe" if is_pppoe else "vpn" if is_vpn else "wifi" if is_wifi else
            "ethernet" if is_ethernet else "virtual" if is_virtual else "other")
    st = (raw.get("status") or "").lower()
    up = st in ("up", "connected") or (raw.get("conn4") or "").lower() == "connected"
    dns4_static = _as_list(raw.get("dns4_static"))
    dns6_static = _as_list(raw.get("dns6_static"))
    dhcp4 = (raw.get("dhcp4") or "").lower()
    a = {
        "index": raw.get("index"), "alias": alias, "description": desc, "guid": raw.get("guid"),
        "kind": kind, "is_wifi": is_wifi, "is_ethernet": is_ethernet, "is_pppoe": is_pppoe,
        "is_vpn": is_vpn, "is_virtual": is_virtual,
        "status": raw.get("status"), "up": up, "mac": raw.get("mac"),
        "link_speed": raw.get("link_speed"),
        "ipv4": _as_list(raw.get("ipv4")), "ipv6": _as_list(raw.get("ipv6")),
        "ipv6_link_local": _as_list(raw.get("ipv6_ll")),
        "gateway4": _as_list(raw.get("gw4")), "gateway6": _as_list(raw.get("gw6")),
        "gateway_mac": raw.get("gw_mac"),
        "dns4": _as_list(raw.get("dns4")), "dns6": _as_list(raw.get("dns6")),
        "dns4_source": "static" if dns4_static else "dhcp",
        "dns6_source": "static" if dns6_static else "dhcp",
        "ip4_source": "dhcp" if dhcp4 == "enabled" else "static" if dhcp4 == "disabled" else "unknown",
        "mtu4": raw.get("mtu4"), "mtu6": raw.get("mtu6"), "metric4": raw.get("metric4"),
        "network_name": raw.get("profile_name"), "network_category": raw.get("profile_category"),
        "ssid": ssid if is_wifi else None,
    }
    # 4294967295 = "not present" in NlMtu
    for k in ("mtu4", "mtu6"):
        if a[k] in (None, 0) or (isinstance(a[k], int) and a[k] > 65535):
            a[k] = None
    a["has_gateway"] = bool(a["gateway4"] or a["gateway6"])
    return a


def pick_primary(adapters: list) -> Optional[dict]:
    """Active internet adapter: up, has a default gateway, lowest metric.
    A VPN with a gateway is reported separately and not preferred."""
    cands = [a for a in adapters if a["up"] and a["has_gateway"] and not a["is_virtual"]]
    physical = [a for a in cands if not a["is_vpn"]] or cands
    if not physical:
        return None
    return sorted(physical, key=lambda a: (a["metric4"] if a["metric4"] is not None else 9999))[0]


def parse_ssid(netsh_out: str) -> Optional[str]:
    for line in netsh_out.splitlines():
        m = re.match(r"^\s*SSID\s*:\s*(.+?)\s*$", line)   # not BSSID (anchored)
        if m:
            return m.group(1)
    return None


def fingerprint(a: Optional[dict]) -> Optional[str]:
    """Stable id for 'this network on this adapter'. Uses the local adapter
    MAC, the SSID (Wi-Fi), the gateway IP and gateway MAC; never leaves the PC."""
    if not a:
        return None
    parts = [a.get("kind") or "", (a.get("mac") or a.get("alias") or "").upper(),
             a.get("ssid") or "", ",".join(a.get("gateway4") or a.get("gateway6") or []),
             (a.get("gateway_mac") or "").upper()]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _linux_snapshot() -> list:
    out = []
    try:
        addrs = json.loads(_run(["ip", "-j", "addr"]))
        routes = json.loads(_run(["ip", "-j", "route", "show", "default"]))
    except Exception:
        return out
    dns = []
    try:
        with open("/etc/resolv.conf") as f:
            dns = [l.split()[1] for l in f if l.startswith("nameserver")]
    except OSError:
        pass
    for i in addrs:
        if i.get("ifname") == "lo":
            continue
        gw = [r["gateway"] for r in routes if r.get("dev") == i["ifname"] and r.get("gateway")]
        raw = {"index": i.get("ifindex"), "alias": i.get("ifname"), "description": i.get("ifname"),
               "status": "Up" if i.get("operstate") in ("UP", "UNKNOWN") else "Down",
               "mac": i.get("address"), "iftype": 6,
               "ipv4": [f"{a['local']}/{a['prefixlen']}" for a in i.get("addr_info", []) if a.get("family") == "inet"],
               "ipv6": [f"{a['local']}/{a['prefixlen']}" for a in i.get("addr_info", [])
                        if a.get("family") == "inet6" and a.get("scope") == "global"],
               "gw4": gw, "dns4": [d for d in dns if ":" not in d], "dns6": [d for d in dns if ":" in d],
               "mtu4": i.get("mtu"), "mtu6": i.get("mtu"), "dhcp4": "Enabled", "metric4": 100}
        out.append(classify(raw))
    return out


def snapshot() -> dict:
    """Full snapshot of all adapters + primary adapter + fingerprint."""
    adapters = []
    if sys.platform == "win32":
        try:
            ssid = parse_ssid(_run(["netsh", "wlan", "show", "interfaces"], 10))
        except Exception:
            ssid = None
        try:
            out = _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-Command", PS_SCRIPT], 60).strip()
            data = json.loads(out) if out else []
            if isinstance(data, dict):
                data = [data]
            adapters = [classify(r, ssid) for r in data]
        except Exception as e:
            log.error("adapter discovery failed: %s", e)
    else:
        adapters = _linux_snapshot()
    primary = pick_primary(adapters)
    vpns = [a for a in adapters if a["is_vpn"] and a["up"]]
    return {"adapters": adapters, "primary": primary, "vpn_active": bool(vpns),
            "vpn_adapters": [a["alias"] for a in vpns],
            "fingerprint": fingerprint(primary), "platform": sys.platform}


def light_signature() -> str:
    """Cheap change-detection signature (used by the monitor every few
    seconds instead of the full PowerShell snapshot)."""
    try:
        if sys.platform == "win32":
            text = _run(["ipconfig"], 10) + _run(["netsh", "wlan", "show", "interfaces"], 10)
            # drop volatile lines (signal %, rates) from the wlan output
            text = "\n".join(l for l in text.splitlines()
                             if not re.search(r"signal|rate|rssi|%|receive|transmit", l, re.I))
        else:
            text = _run(["ip", "-o", "addr"], 10) + _run(["ip", "route"], 10)
    except Exception as e:
        text = f"error {e}"
    return hashlib.sha256(text.encode()).hexdigest()


def mask_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return mac
    parts = re.split(r"[-:]", mac)
    return "-".join(parts[:3] + ["XX"] * max(0, len(parts) - 3))
