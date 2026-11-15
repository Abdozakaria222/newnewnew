"""Small statistics toolkit (no numpy) used by benchmarks and comparisons."""
from __future__ import annotations

import math
import random
from typing import Optional, Sequence


def mean(xs: Sequence[float]) -> Optional[float]:
    return sum(xs) / len(xs) if xs else None


def percentile(xs: Sequence[float], p: float) -> Optional[float]:
    """Linear-interpolation percentile (same as numpy's default)."""
    if not xs:
        return None
    s = sorted(xs)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * p / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def median(xs: Sequence[float]) -> Optional[float]:
    return percentile(xs, 50)


def stdev(xs: Sequence[float]) -> Optional[float]:
    if len(xs) < 2:
        return 0.0 if xs else None
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))


def mad(xs: Sequence[float]) -> Optional[float]:
    """Median absolute deviation — robust jitter/consistency measure."""
    if not xs:
        return None
    m = median(xs)
    return median([abs(x - m) for x in xs])


def summarize(xs: Sequence[float]) -> dict:
    return {
        "n": len(xs),
        "mean": mean(xs), "median": median(xs),
        "p90": percentile(xs, 90), "p95": percentile(xs, 95),
        "min": min(xs) if xs else None, "max": max(xs) if xs else None,
        "stdev": stdev(xs), "mad": mad(xs),
    }


def mann_whitney_p(a: Sequence[float], b: Sequence[float]) -> Optional[float]:
    """Two-sided Mann-Whitney U test p-value (normal approximation with tie
    correction). Non-parametric: suitable for skewed latency data."""
    n1, n2 = len(a), len(b)
    if n1 < 3 or n2 < 3:
        return None
    combined = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    ranks = [0.0] * len(combined)
    i, tie_term = 0, 0.0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        r = (i + j) / 2.0 + 1
        for k in range(i, j + 1):
            ranks[k] = r
        t = j - i + 1
        tie_term += t ** 3 - t
        i = j + 1
    r1 = sum(r for r, (_, g) in zip(ranks, combined) if g == 0)
    u1 = r1 - n1 * (n1 + 1) / 2.0
    mu = n1 * n2 / 2.0
    n = n1 + n2
    var = n1 * n2 / 12.0 * ((n + 1) - tie_term / (n * (n - 1)))
    if var <= 0:
        return 1.0
    z = (abs(u1 - mu) - 0.5) / math.sqrt(var)   # continuity correction
    return max(0.0, min(1.0, math.erfc(max(z, 0) / math.sqrt(2))))


def bootstrap_median_diff_ci(a: Sequence[float], b: Sequence[float],
                             iters: int = 2000, seed: int = 7) -> Optional[tuple]:
    """95% CI of median(b) - median(a) via bootstrap resampling."""
    if len(a) < 3 or len(b) < 3:
        return None
    rng = random.Random(seed)
    diffs = []
    for _ in range(iters):
        ra = [rng.choice(a) for _ in a]
        rb = [rng.choice(b) for _ in b]
        diffs.append(median(rb) - median(ra))
    return percentile(diffs, 2.5), percentile(diffs, 97.5)


def two_proportion_p(succ_a: int, n_a: int, succ_b: int, n_b: int) -> Optional[float]:
    """Two-sided z-test for a difference between two success rates."""
    if n_a == 0 or n_b == 0:
        return None
    p = (succ_a + succ_b) / (n_a + n_b)
    if p in (0.0, 1.0):
        return 1.0
    se = math.sqrt(p * (1 - p) * (1 / n_a + 1 / n_b))
    z = abs(succ_a / n_a - succ_b / n_b) / se
    return math.erfc(z / math.sqrt(2))
