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
