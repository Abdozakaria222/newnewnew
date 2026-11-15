# Final implementation checklist

Legend — **Implemented**: code exists. **Tested here**: verified by automated tests
(60 tests) and/or an end-to-end run of the real app + API + UI in headless Chrome,
with a *simulated* network (Linux build machine). **Windows**: needs to be
confirmed on a real Windows 10/11 PC — this could NOT be done here.

## Acceptance tests (section 13)

| # | Requirement | Implemented | Tested here | Needs Windows check |
|---|---|---|---|---|
| 1 | DNS testing works independently | ✅ | ✅ API + unit tests | ✅ real resolvers |
| 2 | MTU testing works independently | ✅ | ✅ API + unit tests | ✅ real ICMP |
| 3 | Default workflow runs DNS before MTU | ✅ | ✅ (`order == ["dns","mtu"]`) | — |
| 4 | Public DNS providers populate automatically | ✅ 18 built-in + current system DNS | ✅ | — |
| 5 | DNS results from real DNS queries | ✅ raw UDP RFC 1035 | ✅ against a real local DNS server (A/AAAA/TXT, timeout, NXDOMAIN, SERVFAIL, spoofed reply) | ✅ internet resolvers |
| 6 | MTU from actual packet-size verification | ✅ IcmpSendEcho + DF (IPv4), PMTU cache (IPv6) | ⚠️ engine logic only, simulated paths | ✅ **required** |
| 7 | Network profiles saved and recognized | ✅ | ✅ | ✅ fingerprint on real adapters |
| 8 | Original settings can be restored | ✅ | ⚠️ restore operations generated & validated; elevated execution simulated | ✅ **required** |
| 9 | Before/after comparison works | ✅ | ✅ (no-change, improvement, regression cases) | — |
| 10 | Admin rights only when necessary | ✅ app runs as user; UAC only on apply/restore | ⚠️ logic only | ✅ **required** |
| 11 | All BAT files work | ✅ 5 files | ❌ cannot run cmd.exe here | ✅ **required** |
| 12 | GitHub upload does not expose credentials | ✅ no tokens in scripts, secret scanner, .gitignore | ✅ scanner tested (blocks tokens, logs, profiles) | ✅ push itself |
| 13 | Project compiles | ✅ | ✅ all modules compile, JS syntax-checked | — |
| 14 | Works on Windows 10 and 11 | ✅ written for both (PowerShell 5.1, netsh, iphlpapi) | ❌ | ✅ **required** |

## Feature sections

| Section | Status |
|---|---|
| 1 Smart network profile | Implemented & tested (simulated adapters). Adapter type/MAC/IPv4/IPv6/gateway/DNS/MTU/DHCP/PPPoE/VPN/status detected via PowerShell — PowerShell part needs Windows check. |
| 2 Advanced DNS intelligence | Implemented & tested. Median/P90/P95/success/timeout/consistency/categories/cached vs uncached/IPv4 vs IPv6/primary+secondary/custom providers/import/export. |
| 3 Advanced MTU intelligence | Implemented & tested on simulated paths: binary search, confirmation, ICMP filtering, loss vs fragmentation, silent drop, unreliable destinations, multi-destination agreement, small/medium/large verification, confidence. |
| 4 Before/after comparison | Implemented & tested. Identical test plan replayed; significance tests; "no measurable improvement" reported honestly. |
| 5 Network change detection | Implemented & tested (event classification). Uses a cheap signature every 15 s; no background benchmarks. |
| 6 Smart restore & backup | Implemented & tested (never overwrites, original kept). Elevated execution needs Windows check. |
| 7 Scoring engine | Implemented & documented in SCORING.md; score parts shown in UI. |
| 8 Dashboard | Implemented; charts with hover, sortable tables; screenshot-verified in Arabic/English, dark/light. |
| 9 Additional tools | Implemented: connectivity, DNS leak diagnostic (with disclaimer), DNS resolution + NXDOMAIN-hijack check, packet loss, gateway latency, public IP (via DNS), adapter info, IPv4/IPv6 check, report export (MACs masked). |
| 10 VDSL/PPPoE | PPPoE adapter detection + 1492 interpretation. No ISP/technology is assumed. |
| 11 Settings | All listed options + safe defaults + validation. |
| 12 Quality | Background jobs, cancellation, one heavy test at a time, rotating log file, modular packages, 60 automated tests. |

## Partially implemented
* **Engine explanations** ("Why this recommendation?") are in English even when the UI is in Arabic; all UI labels are translated.
* **PPPoE + DNS:** on a PPPoE (RAS) connection, DNS set with netsh may only last until the connection is redialled; the permanent setting lives in the connection's properties.
* **IPv6 MTU on Windows:** Windows `ping` cannot set DF for IPv6; the engine reads the kernel's Path-MTU cache instead. This is solid evidence but slightly less direct than IPv4.
* **Full IP restore** is offered only for DHCP or a single static IPv4 address; anything more complex is refused (DNS/MTU restore still work).

## Known technical limitations
* MTU above the current interface MTU cannot be tested (Windows will not send larger packets), so the app can confirm or lower an MTU but not discover a higher one.
* Destinations that block ICMP give no MTU data; they are reported and excluded.
* DNS-over-HTTPS in browsers bypasses system DNS; the DNS leak diagnostic is **not** proof of privacy or anonymity.
* Results reflect the network at test time; the app never assumes the same provider is always fastest.
