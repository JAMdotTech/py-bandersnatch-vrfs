# py-bandersnatch-vrfs
Python Bandersnatch VRFs library utilizing the RUST [ark-ec-vrfs](https://github.com/davxy/ark-ecvrf) cryptographic library

## Ring capacity

```python
from bandersnatch_vrfs import RingContext

# Existing behavior: choose the proof domain from the number of supplied keys.
context = RingContext(ring_data, public_keys)

# Keep the same proof domain as the member list grows or shrinks.
context = RingContext(ring_data, public_keys, ring_capacity=1023)
```

`ring_capacity` is an optional, keyword-only, non-negative integer. Omitting it
or passing `None` uses `len(public_keys)`, preserving the existing behavior.
It must be at least the number of supplied keys and fit the supplied structured
reference string (`ring_data`); otherwise construction raises `ValueError`.
Malformed `ring_data` also raises `ValueError`. Negative or out-of-range integers
raise `OverflowError` during argument conversion.

The capacity selects the native proof domain, which rounds up to a supported
size. Different capacities can therefore select the same domain. Unused
positions are filled internally with the native library's padding point;
callers do not need to construct a padded key list or hard-code a curve point.
The commitment still depends on the supplied keys and their order.

Signing indices refer only to the supplied `public_keys`. An index at or beyond
`len(public_keys)` raises `ValueError`, even if it fits the requested capacity.
Proofs made for a ring require verification with the same keys, order, and proof
domain. In particular, a larger capacity may change the domain and commitment.

Applications choose the required capacity and enforce their own membership
rules. For example, a JAM client can pass its profile's maximum validator count
while supplying only the current validator keys. The binding does not select a
JAM profile or treat padding positions as validators.

## Reusing ring contexts

Construct a context once for an ordered ring and capacity, and reuse it for
subsequent signatures and verification. Native construction releases Python's
GIL. The first signature prepares and caches a native proving key; subsequent
signatures reuse that preparation while creating independent provers and
transcripts for each signer index and message. Cache initialization also runs
without the GIL, so concurrent first signers can wait safely.

The cache belongs to the context and contains public proving material, not
secret keys or proofs. Verification-only contexts do not allocate the extra
cached proving key. Changing the keys, their order, capacity, or SRS requires a
new context. The cached key lives until its context is released.

See [measured before/after results](benchmarks/results.md) and the
[dependency compatibility assessment](docs/compatibility.md). PyO3 is pinned
to 0.30.1; the JAM-compatible `ark-vrf` protocol backend remains pinned to
0.2.2. Building from source requires Rust 1.85 or newer. PyO3 0.30.1 supports
CPython 3.9 or newer and PyPy with Python 3.11 or newer; older PyPy runtimes
cannot use this dependency version.

## Installation

### Compile for local development

```
pip install -r requirements.txt
maturin develop
```
### Build wheels
```
pip install -r requirements.txt

# Build local OS wheel
maturin build --release

# Build manylinux1 wheel
docker run --rm -v $(pwd):/io ghcr.io/pyo3/maturin build --release

```
