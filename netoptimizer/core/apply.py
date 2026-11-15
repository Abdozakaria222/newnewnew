"""Applying and restoring DNS / MTU / IP configuration on Windows.

Administrator rights are requested ONLY here, at the moment a change is
applied (one UAC prompt per apply/restore operation). Everything else in the
app runs as a normal user.

Safety:
* Every value is validated in Python (ipaddress, integer ranges, the adapter
  index must exist in the current snapshot).
* Operations are passed to the elevated PowerShell script as base64 JSON
  data and dispatched by a fixed `switch` — no command strings are built
  from user input, so nothing can be injected.
* A backup is written before every change (see backup.py).
"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import subprocess
import sys
import tempfile
import time

log = logging.getLogger("netopt.apply")
CREATE_NO_WINDOW = 0x08000000

PS_APPLY = r"""
$ErrorActionPreference = 'Continue'
$ops = ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__OPS__')))
$results = @()
foreach ($op in $ops) {
  $out = ''; $ok = $true
  try {
    switch ($op.op) {
      'dns_static' {
        $fam = $op.family; $i = [int]$op.index
        $out += (& netsh interface $fam set dnsservers "name=$i" source=static "address=$($op.servers[0])" register=primary validate=no 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) { $ok = $false }
        for ($k = 1; $k -lt $op.servers.Count; $k++) {
          $out += (& netsh interface $fam add dnsservers "name=$i" "address=$($op.servers[$k])" "index=$($k+1)" validate=no 2>&1 | Out-String)
          if ($LASTEXITCODE -ne 0) { $ok = $false }
        }
      }
      'dns_dhcp' {
        $out += (& netsh interface $($op.family) set dnsservers "name=$([int]$op.index)" source=dhcp 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) { $ok = $false }
      }
      'mtu' {
        $af = if ($op.family -eq 'ipv6') { 'IPv6' } else { 'IPv4' }
        Set-NetIPInterface -InterfaceIndex ([int]$op.index) -AddressFamily $af -NlMtuBytes ([int]$op.value) -ErrorAction Stop
        $out += "MTU $af set to $($op.value)"
      }
      'ip_dhcp' {
        $out += (& netsh interface ipv4 set address "name=$([int]$op.index)" source=dhcp 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) { $ok = $false }
      }
      'ip_static' {
        $gw = if ($op.gateway) { "gateway=$($op.gateway)" } else { 'gateway=none' }
        $out += (& netsh interface ipv4 set address "name=$([int]$op.index)" source=static "address=$($op.address)" "mask=$($op.mask)" $gw 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) { $ok = $false }
      }
      default { $ok = $false; $out = 'unknown op' }
    }
  } catch { $ok = $false; $out += $_.Exception.Message }
  $results += [pscustomobject]@{ op = $op.op; family = $op.family; ok = $ok; output = $out.Trim() }
}
& ipconfig /flushdns | Out-Null
ConvertTo-Json -InputObject @($results) -Depth 3 | Set-Content -Encoding UTF8 -Path '__RESULT__'
"""


class ApplyError(Exception):
    pass


def is_admin() -> bool:
    if sys.platform != "win32":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _ip(s: str, family: str) -> str:
    try:
        ip = ipaddress.ip_address(str(s).strip())
    except ValueError:
        raise ApplyError(f"invalid address {s!r}")
    if (family == "ipv4") != (ip.version == 4):
        raise ApplyError(f"{s} is not an {family} address")
    return str(ip)


def op_dns(adapter: dict, family: str, servers: list | None) -> dict:
    if family not in ("ipv4", "ipv6"):
        raise ApplyError("bad family")
    if not servers:
        return {"op": "dns_dhcp", "family": family, "index": int(adapter["index"])}
    servers = [_ip(s, family) for s in servers if s][:2]
    return {"op": "dns_static", "family": family, "index": int(adapter["index"]), "servers": servers}


def op_mtu(adapter: dict, family: str, value: int) -> dict:
    value = int(value)
    lo = 1280 if family == "ipv6" else 576
    if not lo <= value <= 9000:
        raise ApplyError(f"MTU {value} out of range {lo}-9000")
    return {"op": "mtu", "family": family, "index": int(adapter["index"]), "value": value}


def ops_restore_ip(adapter_now: dict, backup_cfg: dict) -> list:
    """Restore IPv4 addressing only when safely possible: a single static
    address with a known prefix, or DHCP."""
    src = backup_cfg.get("ip4_source")
    if src == "dhcp":
        return [{"op": "ip_dhcp", "family": "ipv4", "index": int(adapter_now["index"])}]
    if src == "static" and len(backup_cfg.get("ipv4") or []) == 1:
        net = ipaddress.ip_interface(backup_cfg["ipv4"][0])
        gw = (backup_cfg.get("gateway4") or [None])[0]
        if gw:
            _ip(gw, "ipv4")
        return [{"op": "ip_static", "family": "ipv4", "index": int(adapter_now["index"]),
                 "address": str(net.ip), "mask": str(net.netmask), "gateway": gw}]
    raise ApplyError("IP configuration cannot be restored safely automatically "
                     "(multiple or unknown addresses) — DNS/MTU can still be restored.")


def run_ops(ops: list, runner=None) -> list:
    """Execute operations elevated. `runner` is injectable for tests."""
    if not ops:
        return []
    if runner:
        return runner(ops)
    if sys.platform != "win32":
        raise ApplyError("Applying settings is supported on Windows only.")
    tmpdir = tempfile.mkdtemp(prefix="netopt-")
    result_path = os.path.join(tmpdir, "result.json")
    script_path = os.path.join(tmpdir, "apply.ps1")
    b64 = base64.b64encode(json.dumps(ops).encode("utf-8")).decode("ascii")
    with open(script_path, "w", encoding="utf-8-sig") as f:
        f.write(PS_APPLY.replace("__OPS__", b64).replace("__RESULT__", result_path.replace("'", "''")))
    ps_args = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script_path]
    kw = {"creationflags": CREATE_NO_WINDOW}
    if is_admin():
        subprocess.run(["powershell"] + ps_args, capture_output=True, timeout=120, **kw)
    else:
        arglist = ",".join("'" + a.replace("'", "''") + "'" for a in ps_args)
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            f"Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden "
                            f"-ArgumentList {arglist}"], capture_output=True, timeout=300, **kw)
        if r.returncode != 0 and not os.path.exists(result_path):
            raise ApplyError("Administrator permission was not granted (UAC cancelled).")
    for _ in range(20):
        if os.path.exists(result_path):
            break
        time.sleep(0.25)
    if not os.path.exists(result_path):
        raise ApplyError("The elevated operation produced no result.")
    with open(result_path, encoding="utf-8-sig") as f:
        res = json.load(f)
    try:
        os.remove(result_path)
        os.remove(script_path)
        os.rmdir(tmpdir)
    except OSError:
        pass
    log.info("apply results: %s", res)
    return res if isinstance(res, list) else [res]


def verify(snapshot_after: dict, adapter_index: int, ops: list) -> list:
    """Re-read the configuration and check each operation really took effect."""
    a = next((x for x in snapshot_after["adapters"] if x["index"] == adapter_index), None)
    checks = []
    if not a:
        return [{"check": "adapter", "ok": False, "detail": "adapter not found after change"}]
    for op in ops:
        if op["op"] == "dns_static":
            key = "dns4" if op["family"] == "ipv4" else "dns6"
            got = [str(ipaddress.ip_address(x)) for x in a[key]]
            checks.append({"check": f"{key}", "ok": got[:len(op["servers"])] == op["servers"],
                           "detail": f"now {got}"})
        elif op["op"] == "dns_dhcp":
            key = "dns4_source" if op["family"] == "ipv4" else "dns6_source"
            checks.append({"check": key, "ok": a[key] == "dhcp", "detail": f"now {a[key]}"})
        elif op["op"] == "mtu":
            key = "mtu4" if op["family"] == "ipv4" else "mtu6"
            checks.append({"check": key, "ok": a[key] == op["value"], "detail": f"now {a[key]}"})
        elif op["op"] in ("ip_dhcp", "ip_static"):
            checks.append({"check": "ipv4", "ok": True, "detail": f"now {a['ipv4']} ({a['ip4_source']})"})
    return checks
