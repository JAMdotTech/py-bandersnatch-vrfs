# PyJAMaz Graypaper 0.8.0 compatibility validation

The cached proving preparation and PyO3 0.30.1 build passed focused integration
checks against PyJAMaz's existing Graypaper 0.8.0 implementation. `ark-vrf`
remains pinned to 0.2.2; this report does not claim compatibility for an
`ark-vrf` 0.5.3 upgrade. See [the dependency review](compatibility.md).

The module explicitly declares `#[pymodule(gil_used = true)]`, preserving its
existing GIL requirement after the PyO3 upgrade. Native construction, ring
signing, and ring verification detach from Python while they run. The validation below was
repeated on the final wheels containing that explicit module declaration.

## Sources and isolation

- Application: [JAMdotTech/pyjamaz](https://github.com/JAMdotTech/pyjamaz),
  local `/Users/arjan/Development/pyjamaz-codex`, `GP_VERSION=0.8.0`,
  `APP_VERSION=0.1.49`, revision `6e1839bd28faa947d6dcd7a6218459162ba499ad`
  with its pre-existing local working-tree changes. No application source,
  requirements, or installed environment was changed for this validation.
- Independent Safrole fixtures:
  [davxy/jam-test-vectors](https://github.com/davxy/jam-test-vectors/tree/d971c8d9e737996da17760955fac26d07f657f0a/stf/safrole),
  pinned at `d971c8d9e737996da17760955fac26d07f657f0a`; 21 Tiny and 25 Full
  JSON vectors. The existing pinned checkout was selected through
  `JAM_TEST_VECTORS`. Fixtures remain in their original repository under
  [CC0-1.0](https://github.com/davxy/jam-test-vectors/blob/d971c8d9e737996da17760955fac26d07f657f0a/LICENSE);
  no fixture corpus was copied into this repository.
- Baseline: a release wheel built from this repository's merged 0.6.3 main,
  revision `bec3f19ab21ece765aa42e3245e8d783a72d0473`.
- Candidate: a release wheel built with PyO3 0.30.1, detached construction,
  and the per-context lazy prover-key cache.
- Existing application backend: installed `bandersnatch-vrfs==0.6.1`, which is
  still the application's declared dependency.

Both 0.6.3 wheels were installed into separate temporary `pip --target`
directories and selected through `PYTHONPATH`. The application environment's
0.6.1 installation was preserved. An isolated `sitecustomize.py` supplied an
empty `pyjamaz.local_settings` module before application imports, excluding
developer-local overrides and retaining the application's normal settings.
All subprocesses disabled bytecode writes and pytest's cache provider.

## CPython 3.12 results

Dimensions: CPython 3.12.11, macOS ARM64, `PVM_INTERPRETER=CPYTHON`, the
pinned external corpus above, and separate Tiny/Full subprocesses.

| Backend | Tiny | Full |
| --- | --- | --- |
| Installed 0.6.1 control | 40 passed | 47 passed |
| Merged 0.6.3 baseline | 40 passed | 47 passed |
| Candidate | 40 passed | 47 passed |

No tests were skipped. Each suite emitted one existing
`PytestCollectionWarning`: the vector data class named `Testcase` has a
constructor and is not a pytest test class.

The selection runs `test_safrole.py`, `test_safrole_validation.py`, and
`test_audit_validation.py` in both profiles. Tiny additionally runs
`test_ce131_132_real_ring_vrf_self_proxy_path_reaches_extrinsic_queue` from
`test_jamnp_base.py`, exercising genuine ring signing, ticket verification,
proxy routing, and extrinsic admission. That test explicitly creates a
six-member Tiny ring and is not included in the Full selection.

Effective settings were checked in every capture process:

| Setting | Value |
| --- | --- |
| `GP_VERSION` | `0.8.0` |
| `TEST_SUITE` | `tiny` / `full`, explicitly selected |
| `SOLO_MODE` | `False` |
| `SKIP_TIMESLOT_WALL_CLOCK_CHECK` | `False` |
| `SKIP_VALIDATE_GUARANTEES` | `False` |
| `INTEROP_MODE` | empty string |
| `POLKAJAM_SYNC_OOG_COMPAT` | `False` |
| `GP080_PR112_BLESS_COMPAT` | `False` |
| `GP080_PR112_GROW_HEAP_OOG_COMPAT` | `False` |
| `GP080_PR112_CMOV_COMPAT` | `False` |

## Additional Python runtimes

The same candidate integration selection also passed under the application's
current CPython 3.13.7 environment: **40 Tiny and 47 Full tests passed**, with
no skips and the same single collection warning per profile. The same pinned
corpus, CPYTHON PVM backend, isolated local-settings stub, and all-False flags
were used. Its capture harness also matched the CPython 3.12 baseline's
keys, outputs, commitments, IETF signatures, and raw `c`/`s` proof fields, and
verified that baseline's ring proofs.

Separately built wheels passed this bindings repository's full native test
selection on macOS ARM64:

| Candidate wheel / interpreter | Result |
| --- | --- |
| CPython 3.12.11 (`cp312`) | 25 tests and 29 subtests passed |
| CPython 3.13.7 (`cp313`) | 25 tests and 29 subtests passed |
| CPython 3.14.6 (`cp314`) | 25 tests and 29 subtests passed |

None of the native runs skipped tests or emitted warnings. Each wheel was installed
in its own temporary target and selected through `PYTHONPATH`; the existing
application environments were preserved.

## Proof and byte compatibility

A separate harness exercised the application's real `BandersnatchKeypair`
and `jam_ring_context` helpers. It captured Tiny's six-member ring and Full
rings containing 6, 9, 300, and 1023 live validators. The existing application
helper still manually pads the smaller Full rings to the profile capacity,
so these checks cover current application usage without an application change.

For the candidate versus merged 0.6.3 baseline:

- Derived secret/public keys, VRF outputs, and ring commitments are identical.
- IETF signatures are byte-identical for the JAM ticket-seal, fallback-seal,
  audit, and entropy contexts, including contexts longer than 32 bytes.
- The exported `generate_vrf_proof` API returns identical `c` and `s` bytes;
  the `PyProof` constructor and readable byte fields continue to work.
- Every captured baseline ring proof verifies with the candidate, and every
  captured candidate ring proof verifies with the baseline. Ring proof bytes
  are not required to match because ring proving includes randomness.

The installed 0.6.1 backend also verifies candidate IETF and ring proofs, and
the candidate verifies proofs produced by 0.6.1, in both profiles and all five
ring configurations. Derived keys, VRF outputs, and commitments match 0.6.1.
Some proof/nonce bytes already differ between installed 0.6.1 and the merged
0.6.3 baseline; the 0.6.1 comparison therefore checks successful proof
verification and unchanged outputs rather than requiring identical regenerated
IETF/raw-proof bytes. The new candidate retains 0.6.3's exact IETF/raw-proof
bytes.

## Final tested wheel artifacts

The final macOS ARM64 wheels were re-injected with `pip --target --upgrade`
before repeating the candidate checks. Their SHA-256 values are:

| Wheel tag | SHA-256 |
| --- | --- |
| `cp312-cp312-macosx_11_0_arm64` | `919e2b36955b0911018b40cb1d0dbf594c609052fe5b4873bd75619926e37816` |
| `cp313-cp313-macosx_11_0_arm64` | `e3c096e7ba5208ac304c4ac84f01902b7c3343c8f8ad73740338677318d648e0` |
| `cp314-cp314-macosx_11_0_arm64` | `a9d59e2f96f1de8ebd1fc3c914166a1b5ebfe55dd1b7a816a38caed7e70c1e6f` |

The unchanged baseline `cp312` wheel has SHA-256
`6ac6c711c01df30e4447a07139fb25e25c073eb6f37bd96517a249507a2f8eeb`.
These identify the local validation artifacts; later wheel builds can have
different archive bytes.

## Reproduction

Use a CPython interpreter with PyJAMaz's existing dependencies installed. The
interpreter must match each candidate wheel's CPython tag. Set the paths for
an application checkout, its pinned vector checkout, and separate wheel targets:

```sh
PYJAMAZ_SRC=/Users/arjan/Development/pyjamaz-codex
COMPAT_DIR=/private/tmp/py-bandersnatch-vrfs-compat-review
PYJAMAZ_PYTHON="$PYJAMAZ_SRC/.venv-native312/bin/python"

"$PYJAMAZ_PYTHON" -m pip install --upgrade --no-deps --no-cache-dir \
  --target "$COMPAT_DIR/baseline" /absolute/path/to/baseline-cp312.whl
"$PYJAMAZ_PYTHON" -m pip install --upgrade --no-deps --no-cache-dir \
  --target "$COMPAT_DIR/candidate" /absolute/path/to/candidate-cp312.whl

mkdir -p "$COMPAT_DIR/strict-settings"
cat > "$COMPAT_DIR/strict-settings/sitecustomize.py" <<'PY'
import sys
import types
stub = types.ModuleType("pyjamaz.local_settings")
stub.__file__ = __file__
sys.modules["pyjamaz.local_settings"] = stub
PY
```

Run outside the application checkout, substituting `baseline` or `candidate`
for the wheel target and `tiny` or `full` for the profile:

```sh
cd "$COMPAT_DIR"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$COMPAT_DIR/strict-settings:$COMPAT_DIR/candidate:$PYJAMAZ_SRC"
export JAM_FUZZ=1 JAM_FUZZ_SPEC=tiny PYJAMAZ_PROFILE=tiny
export JAM_TEST_VECTORS="$PYJAMAZ_SRC/tmp/gp080/vectors"
export PVM_INTERPRETER=CPYTHON
export PYJAMAZ_INTEROP_MODE= PYJAMAZ_POLKAJAM_SYNC_OOG_COMPAT=0
export PYJAMAZ_GP080_PR112_BLESS_COMPAT=0
export PYJAMAZ_GP080_PR112_GROW_HEAP_OOG_COMPAT=0
export PYJAMAZ_GP080_PR112_CMOV_COMPAT=0
export NUMBA_CACHE_DIR="$COMPAT_DIR/numba-cache"

"$PYJAMAZ_PYTHON" -m pytest -q -p no:cacheprovider --tb=short \
  "$PYJAMAZ_SRC/test/test_safrole.py" \
  "$PYJAMAZ_SRC/test/test_safrole_validation.py" \
  "$PYJAMAZ_SRC/test/test_audit_validation.py"
```

Append the following node ID in Tiny to reproduce the full Tiny selection:

```text
/Users/arjan/Development/pyjamaz-codex/test/test_jamnp_base.py::test_ce131_132_real_ring_vrf_self_proxy_path_reaches_extrinsic_queue
```

The committed [compatibility harness](../scripts/check_pyjamaz_compatibility.py)
reproduces the key, output, commitment, IETF/raw-proof field, and ring-proof
comparisons. It imports the actual application wrappers and finds the SRS in
the selected PyJAMaz package; `--srs` can select a separate SRS file. Captured
secret keys are derived exclusively from fixed public **test-only seeds**.

With the environment above, capture and verify in both directions:

```sh
BINDINGS_SRC=/private/tmp/py-bandersnatch-vrfs-prepared-rings
COMPAT_SCRIPT="$BINDINGS_SRC/scripts/check_pyjamaz_compatibility.py"
for profile in tiny full; do
  export JAM_FUZZ_SPEC="$profile" PYJAMAZ_PROFILE="$profile"
  PYTHONPATH="$COMPAT_DIR/strict-settings:$COMPAT_DIR/baseline:$PYJAMAZ_SRC" \
    "$PYJAMAZ_PYTHON" "$COMPAT_SCRIPT" capture "$COMPAT_DIR/baseline-$profile.json"
  PYTHONPATH="$COMPAT_DIR/strict-settings:$COMPAT_DIR/candidate:$PYJAMAZ_SRC" \
    "$PYJAMAZ_PYTHON" "$COMPAT_SCRIPT" verify "$COMPAT_DIR/baseline-$profile.json"
  PYTHONPATH="$COMPAT_DIR/strict-settings:$COMPAT_DIR/candidate:$PYJAMAZ_SRC" \
    "$PYJAMAZ_PYTHON" "$COMPAT_SCRIPT" capture "$COMPAT_DIR/candidate-$profile.json"
  PYTHONPATH="$COMPAT_DIR/strict-settings:$COMPAT_DIR/baseline:$PYJAMAZ_SRC" \
    "$PYJAMAZ_PYTHON" "$COMPAT_SCRIPT" verify "$COMPAT_DIR/candidate-$profile.json"
done
```

To compare with the application's installed 0.6.1 backend, omit the wheel
target from `PYTHONPATH` when capturing or verifying with 0.6.1. Use
`--allow-proof-differences` for both directions of that specific comparison.
This retains key/output/commitment equality and successful proof verification
while permitting the existing regenerated nonce/proof-byte differences.
Baseline-to-candidate 0.6.3 comparisons use the default exact field checks.

Machine-readable commands, settings, and logs from this review are retained
under `/private/tmp/py-bandersnatch-vrfs-compat-review`.
`baseline-results.json`, `candidate-results.json`, and
`cross-verification-results.json` identify the exact executed subprocesses
and log files. These local logs are supplementary; the committed script and
pytest commands above provide the reproducible checks.

For the CPython 3.13 application run, use
`PYJAMAZ_PYTHON="$PYJAMAZ_SRC/.venv/bin/python"` and the isolated target
containing the `cp313` candidate wheel; retain the same profile, corpus, flags,
and test selection. Native-only checks used the following command shape from
the temporary review directory, with the matching `cp313` or `cp314` target:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$COMPAT_DIR/candidate-cp313" \
  "$PYJAMAZ_SRC/.venv/bin/python" -m pytest -q -p no:cacheprovider --tb=short \
  /private/tmp/py-bandersnatch-vrfs-prepared-rings/test

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$COMPAT_DIR/candidate-cp314" \
  "$PYJAMAZ_SRC/.venv-native314/bin/python" -m pytest -q -p no:cacheprovider --tb=short \
  /private/tmp/py-bandersnatch-vrfs-prepared-rings/test
```

The additional exact commands and logs are recorded in
`candidate-cp313-results.json`, `additional-runtime-results.json`, and
`final-artifact-manifest.json` in the
same temporary review directory.

These are focused cryptographic compatibility checks, not a claim that every
Graypaper 0.8.0 subsystem conforms. PyJAMaz's migration ledger records existing
accumulation/history vector discrepancies outside this selection.
