# Dependency and protocol compatibility

This change upgrades the Python binding runtime to exact `pyo3 = 0.30.1`
while retaining exact `ark-vrf = 0.2.2`. It preserves the existing Python API,
ordered-ring commitments, VRF outputs, 96-byte IETF signatures, and 784-byte
ring signatures used by current PyJAMaz Graypaper 0.8.0 clients.

PyO3 0.30.1 requires Rust 1.85, CPython 3.9 or newer, or PyPy with Python 3.11
or newer. The PyPy minimum is higher than with the previous PyO3 dependency;
the current PyJAMaz CPython 3.13 runtime is within the supported range.

Construction detaches the native SRS decoding, key conversion, domain setup,
and ring indexing from Python. Signing lazily stores one immutable proving key
per context in a Rust `OnceLock`. Initialization and waiting occur inside
`Python::detach`; every call still creates its own signer-index-specific prover
and transcript. The implementation caches no secret scalars, witnesses,
signatures, or mutable prover transcript state. It introduces no global cache
that could mix rings, capacities, or SRS data.

The cache consumes additional domain-sized memory only after a context signs.
The first signature still performs preparation; the performance benefit applies
to subsequent signatures on that context. A native key clone remains necessary
for each independent prover. The module explicitly declares `gil_used = true`,
preserving the previous runtime behavior because newer PyO3 versions default
to declaring free-threaded safety. Free-threaded Python support requires its
own audit and CI and is not claimed here.

## Why ark-vrf 0.5.3 was not adopted

The requested upgrade was checked against exact upstream tag `v0.5.3`, commit
`9ec593e98b69395e97680330e75b5235b48121f4`. Its stock suite is a different
cryptographic protocol from the one currently used by PyJAMaz:

| Area | Existing 0.2.2 protocol | Stock 0.5.3 protocol |
| --- | --- | --- |
| Suite ID and hash-to-curve domain | Legacy ECVRF domain | New suite/tag domains |
| Padding, blinding, accumulator points | Legacy JAM points | Regenerated points |
| Compact VRF proof | IETF, two nonce commitments | Tiny, one merged nonce commitment |
| Encoded challenge | 32 bytes | 16 bytes |
| Output plus compact proof | 96 bytes | 80 bytes |
| Seed derivation and output hash | Legacy derivation/hash | Transcript-based derivation/hash |

The upstream changelog documents the [0.3 transcript changes,
0.4 IETF-to-Tiny change, and 0.5 domain/point changes](https://github.com/davxy/ark-vrf/blob/v0.5.3/CHANGELOG.md).
Keeping the same SRS would not preserve compatibility. A custom suite ID alone
would not restore the changed proof equations and challenge encoding either.

Consequently, a direct upgrade would invalidate current commitments, outputs,
and signatures. The project retains the compatible backend rather than changing
the protocol through a dependency update. Any future 0.5.3 API requires an
explicit protocol migration and independent interoperability evidence.

## Validation

`test/legacy_compatibility.json` contains valid signatures and commitments
captured from merged main `bec3f19ab21ece765aa42e3245e8d783a72d0473` (package
0.6.3), before these changes. The suite verifies those proofs under the upgraded
binding and checks deterministic IETF signature and VRF output bytes, Tiny and
Full domains, and resized Full rings. Existing official commitment goldens are
unchanged. Concurrency tests cover simultaneous first use, different signer
indices/messages, ring isolation, and concurrent constructors in subprocesses
with deadlock timeouts.

The Windows CI matrix builds, installs, and tests wheels for CPython 3.9–3.14
on both x86 and x64. Linux, musllinux, and macOS explicitly select regular
CPython 3.9–3.15 and PyPy 3.11 wheels. Automatic cross-target discovery also
selects free-threaded CPython 3.13, which PyO3 0.30.1 no longer supports;
explicit interpreter selection avoids that unsupported build and does not
claim free-threaded support. The wider architecture matrix is retained. Additional
PyJAMaz GP0.8.0 integration results are recorded in the
[validation report](pyjamaz-validation.md), and benchmark conditions and samples
are in the [benchmark report](../benchmarks/results.md). Focused crypto
compatibility evidence is not a claim of full-client conformance.
