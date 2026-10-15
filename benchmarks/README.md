# Ring performance measurements

Run against an installed release wheel, in an otherwise idle machine. Use the
same interpreter, script, options and Rayon setting for both wheels. For example:

```sh
RAYON_NUM_THREADS=1 .venv/bin/python benchmarks/benchmark_ring.py \
  --label baseline --source-revision bec3f19 \
  --wheel baseline-dist/<baseline-wheel>.whl --output benchmarks/baseline.json

# Install the candidate wheel, then repeat using its revision and wheel path.
RAYON_NUM_THREADS=1 .venv/bin/python benchmarks/benchmark_ring.py \
  --label candidate --source-revision <candidate-revision> \
  --wheel candidate-dist/<candidate-wheel>.whl --output benchmarks/candidate.json
```

`RAYON_NUM_THREADS=1` fixes the native worker count for reproducibility. The
shared global Rayon pool can constrain concurrent callers, so this setting does
not establish general Python executor scaling. A separate run with the
application's Rayon setting can measure that configuration; do not compare
runs with different settings. The default
three median samples, three signatures per sample and four constructor jobs per
sample keep the run short. Increase these counts for less noisy measurements.
There are no performance pass/fail thresholds.

The script measures Tiny (6 members, capacity 6), Full (1023 members, capacity
1023), and resized Full (6 members, capacity 1023). Each profile includes:

- First construction in fresh child processes, excluding fixture creation and
  Python startup; warm-process construction after native initialization.
- First signing on a fresh context, construction plus first signing, repeated
  signing on one context and signer index, and proof verification. This exposes
  both preparation cost and its amortization across repeated signatures.
- One-worker versus four-worker executor throughput, with identical work and
  pre-created executors. This includes executor dispatch overhead.
- Python counter progress during native construction, divided by its idle rate.
  A Python-only background thread runs while the caller constructs a context;
  snapshots immediately before and after the native call exclude progress
  between calls. Near-zero progress indicates the GIL was held. This deliberately
  competing workload is measured separately from the latency benchmark; the
  counter rate is evidence of scheduling opportunities, not a speedup estimate.

Seeds, signer indices, VRF inputs and auxiliary data are deterministic. Proofs
are verified outside signing timings, verification outputs are checked, and
fresh/concurrent constructor commitments are compared. Ring proof bytes need
not be deterministic. The JSON stores all samples, medians, machine/interpreter,
full command, SRS and wheel/native-binary hashes, revision, and Rayon settings.

The benchmark covers this workload on this machine. Warm signing measures the
same signer index; it does not establish memory usage or the preparation cost
of signing at many different indices. Constructor thread throughput depends on
core count, native parallelism and contention; GIL release does not guarantee
lower single-call latency.
