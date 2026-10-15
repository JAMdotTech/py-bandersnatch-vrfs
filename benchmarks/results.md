# Prepared ring benchmark: baseline versus candidate

Baseline: main `bec3f19ab21ece765aa42e3245e8d783a72d0473` (0.6.3,
PyO3 0.26.0, ark-vrf 0.2.2). Candidate: the working tree based on that commit,
with lazy per-context proving-key preparation, native constructor work detached
from Python, and PyO3 0.30.1 with `gil_used=true` explicitly preserving the module's
GIL requirement. ark-vrf remains 0.2.2 in this measurement.

Both were release wheels on the same macOS 26.6 ARM64 machine, CPython 3.12.11,
10 reported logical CPUs, with `RAYON_NUM_THREADS=1`. The machine was otherwise
idle during each run. Each cell below is the median of three samples; warm
signing and verification samples each contain three operations. Fixtures,
commands, wheel/native-binary hashes and raw samples are in
[baseline.json](baseline.json) and [candidate.json](candidate.json).
The runs took 27.38 s and 24.13 s respectively.

## Repeated signing improves after preparation

| Ring (members/capacity) | Repeated sign before | Repeated sign after | Latency reduction | Throughput ratio |
| --- | ---: | ---: | ---: | ---: |
| Tiny (6/6) | 152.99 ms | 118.58 ms | 22.5% | 1.29× |
| Full (1023/1023) | 481.53 ms | 370.90 ms | 23.0% | 1.30× |
| Resized Full (6/1023) | 499.84 ms | 375.08 ms | 25.0% | 1.33× |

Preparation is lazy. The first signature on a fresh context still pays for it;
there is no corresponding first-signature speedup. The benefit comes from
reusing the same context for subsequent signatures.

| Ring | Warm constructor before → after | First sign before → after | Constructor + first sign before → after | Verify before → after |
| --- | ---: | ---: | ---: | ---: |
| Tiny | 36.50 → 37.00 ms | 152.61 → 153.90 ms | 189.11 → 190.74 ms | 4.20 → 4.26 ms |
| Full | 132.69 → 133.82 ms | 484.44 → 485.27 ms | 617.36 → 619.09 ms | 4.16 → 4.01 ms |
| Resized Full | 115.07 → 114.08 ms | 483.16 → 487.22 ms | 598.22 → 601.30 ms | 4.21 → 4.19 ms |

Constructor and first-signature differences are within roughly 1.5%; verification
varied by up to 3.6%. These short runs do not establish a material change in those
operations. Fresh-process constructor results were also similar: Tiny
37.55 → 37.61 ms, Full 132.53 → 134.25 ms, resized Full 113.89 → 114.19 ms.

## Construction permits other Python work

During a constructor call, a Python-only background counter advanced at these
fractions of its idle rate:

| Ring | Before | After | Four-worker constructor throughput / one-worker throughput, before → after |
| --- | ---: | ---: | ---: |
| Tiny | 3.4% | 98.5% | 0.99× → 1.06× |
| Full | 1.0% | 99.7% | 0.99× → 1.15× |
| Resized Full | 1.2% | 99.2% | 0.94× → 1.03× |

The counter measurement directly demonstrates Python scheduling opportunities
while native construction runs. Its deliberately competing workload is separate
from the constructor latency samples. Releasing the GIL does not by itself
reduce single-constructor latency. Four-thread construction improved only
modestly here; the shared one-worker Rayon pool can constrain native concurrent
work. These ratios apply to the recorded configuration and do not establish
general scaling at other Rayon worker counts.

Every timed proof verified to its independently computed VRF output. All three
ring commitments were byte-identical across wheels; fresh-process and threaded
constructors also agreed. This is a performance measurement, not a substitute
for protocol compatibility tests. Memory use was not measured.
