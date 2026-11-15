# Scoring methodology (transparent, documented weights)

Every recommendation in NetworkOptimizer comes from measurements taken on
**your** network at test time. Nothing is ranked by reputation or list order.
The UI shows, for every recommendation, the exact reasons and the score parts.

## 1. DNS score (0–100) — `netoptimizer/core/dns_bench.py`

### How samples are collected
* Real UDP DNS queries (RFC 1035) sent directly to each resolver, timed with a monotonic clock.
* `dns_rounds` independent rounds (default 3). Provider order is **shuffled every round**.
* Domains are spread over 4 categories (popular, CDN, services, regional/international).
* **Cached** samples: real domains, after one uncounted warm-up query.
* **Uncached** samples: a random sub-domain (`k3f9…​.example.com`) that cannot be in any cache,
  forcing a full recursive lookup. NXDOMAIN is a valid, successful answer.
* IPv4 (A queries to IPv4 resolver addresses) and IPv6 (AAAA queries to IPv6 addresses) are separate runs.
* Primary **and** secondary addresses are both tested.

### Metrics
| Metric | Definition |
|---|---|
| Median | 50th percentile of all successful query times |
| P90 / P95 | 90th / 95th percentile (tail latency) |
| Success rate | answered queries / sent queries (NOERROR or NXDOMAIN) |
| Timeout rate | queries with no answer within `dns_timeout_ms` / sent |
| Variability | MAD / median (median absolute deviation, relative). Lower = more consistent |

### Weights
| Part | Weight | Part score (0–100) |
|---|---|---|
| Median latency | **40** | `100 × best_median_in_this_run / median` |
| P95 latency | **20** | `100 × best_p95_in_this_run / p95` |
| Success rate | **20** | `100 × success_rate` |
| Timeouts | **10** | `100 × (1 − timeout_rate)` |
| Consistency | **10** | `100 × max(0, 1 − variability)` |

`score = Σ part × weight / 100`

### Rules applied after scoring
* **Eligibility:** a provider needs ≥ 95 % successful queries to be recommended.
* **Ties:** if another provider's median is within max(2 ms, 5 %) **and** the Mann-Whitney U test gives p ≥ 0.05,
  the two are reported as statistically indistinguishable.
* **Secondary compatibility:** if the provider's secondary address is below 95 % success, the secondary is replaced
  by the primary address of the next-best reliable provider (and the reason is shown).
* **Keep current DNS:** if your current DNS is within noise of the winner (same tie test), the app says that keeping
  your current DNS is reasonable and does **not** pre-select a change.

## 2. MTU decision and confidence — `netoptimizer/core/mtu.py`

### Procedure
1. **Baseline:** 4 small probes per destination. 0 replies → *ICMP filtered / unreachable*; 1–3 → *unreliable (lossy)*.
   Both are excluded.
2. **Binary search** between `mtu_min` and min(`mtu_max`, current interface MTU) with the Don't-Fragment bit.
   Each size is tried up to 3 times.
   * Explicit "fragmentation needed / packet too big" → *too big*.
   * All attempts time out but small packets still pass → *silent drop* (PMTU black hole) → *too big*.
   * Small packets also fail → *packet loss* → inconclusive (re-tested, never counted as "too big").
3. **Confirmation:** the found value is re-sent `mtu_confirm_attempts` times; all must pass. `value + 1` must fail.
4. **Agreement:** destinations that agree on the same value are counted. A single destination that is lower than ≥ 2
   agreeing others is treated as destination-specific and ignored.
5. **Final verification** at the result with small (≈92), medium (MTU/2, ≥ 576) and large (= MTU) packets,
   repeated to every reliable destination.

Packet size → MTU: IPv4 adds 28 bytes (20 IP + 8 ICMP), IPv6 adds 48 bytes (40 + 8).

### Decision
* Path carries the current MTU → **keep** (MTU is never lowered unnecessarily).
* Path is smaller than the current MTU → **lower** only if ≥ 2 destinations agree **and** final-verification loss ≤ 10 %.
  Otherwise **keep** and explain why.

### Confidence (0–100)
| Part | Weight | Value |
|---|---|---|
| Destination agreement | **40** | 1 dest = 0.25, 2 = 0.8, ≥ 3 = 1.0 |
| Confirmation | **30** | passed confirmation probes / attempts |
| Boundary | **15** | share of destinations where `value + 1` failed (1.0 when the limit is the current MTU) |
| Verification | **15** | 1 − final verification loss rate |

**Cap:** with only one agreeing destination, confidence is capped at **50**.

### Interpretation hints (inferences, not proof)
* 1492 = 1500 − 8 → consistent with PPPoE (DSL/VDSL).
* 1420 WireGuard, 1400 common VPN, 1380 IPsec/L2TP, 1440/1476 GRE, 1450 VXLAN.

## 3. Before / after comparison — `netoptimizer/core/compare.py`
* The *before* run stores its test plan (domains, number of random names, rounds, ping targets, counts, timeout);
  the *after* run replays exactly the same plan.
* Latency: Mann-Whitney U test + 95 % bootstrap confidence interval of the median difference.
  A change counts only if p < 0.05, |difference| ≥ 1 ms and the CI excludes 0.
* Success rate and packet loss: two-proportion z-test, p < 0.05.
* If nothing is significant the report says **"No measurable improvement"**. Percentages are shown as measured,
  including negative ones.
