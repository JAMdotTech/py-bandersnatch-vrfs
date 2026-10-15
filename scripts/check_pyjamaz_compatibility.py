"""Capture deterministic PyJAMaz GP080 crypto outputs and cross-verify proofs.

Run with PYTHONPATH=<isolated wheel target>:<PyJAMaz source checkout>.
Only writes the explicit JSON output path. Does not install dependencies.
Captured secret keys come exclusively from fixed, public test seeds; they are
fixture data and must never be used as production validator keys.
"""
from __future__ import annotations
import argparse
import importlib.metadata
import json
from pathlib import Path
import platform
import sys

import bandersnatch_vrfs as backend
from pyjamaz import graypaper_constants as constants
from pyjamaz import settings
from pyjamaz.signing import BandersnatchKeypair, jam_ring_context


def keypairs(count):
    return [BandersnatchKeypair.from_seed(f"GP080 dependency compatibility validator {index}".encode()) for index in range(count)]


def report_metadata():
    names = (
        "GP_VERSION", "TEST_SUITE", "SOLO_MODE", "SKIP_TIMESLOT_WALL_CLOCK_CHECK",
        "SKIP_VALIDATE_GUARANTEES", "INTEROP_MODE", "POLKAJAM_SYNC_OOG_COMPAT",
        "GP080_PR112_BLESS_COMPAT", "GP080_PR112_GROW_HEAP_OOG_COMPAT", "GP080_PR112_CMOV_COMPAT",
    )
    return {
        "python": platform.python_version(), "executable": sys.executable,
        "backend_version": importlib.metadata.version("bandersnatch-vrfs"),
        "backend_module": backend.__file__,
        "pyjamaz_source": settings.__file__,
        "local_settings_module": getattr(sys.modules.get("pyjamaz.local_settings"), "__file__", None),
        "settings": {name: getattr(settings, name, None) for name in names},
    }


def capture(srs: bytes, destination: Path):
    keys = keypairs(constants.VALIDATOR_COUNT)
    member = keys[3]
    contexts = (
        (b"jam_ticket_seal" + b"e" * 32 + b"\x00", b"unsigned JAM header"),
        (b"jam_fallback_seal" + b"e" * 32, b"unsigned JAM header"),
        (b"jam_audit" + b"e" * 32, b""),
        (b"jam_entropy" + b"v" * 32, b""),
    )
    report = {"metadata": report_metadata(), "keys": [], "ietf": [], "rings": []}
    for index in (0, 3, constants.VALIDATOR_COUNT - 1):
        key = keys[index]
        report["keys"].append({"index": index, "secret": key.private_key.hex(), "public": key.public_key.hex()})
    for vrf_input, aux in contexts:
        signature = member.ietf_vrf_sign(vrf_input, aux)
        output = member.vrf_output(vrf_input)
        assert member.ietf_vrf_verify(vrf_input, aux, signature) == output
        proof = backend.generate_vrf_proof(member.private_key, vrf_input, b"legacy proof output data", aux)
        copy = backend.PyProof(proof.c, proof.s)
        assert copy.c == proof.c and copy.s == proof.s
        report["ietf"].append({
            "input": vrf_input.hex(), "aux": aux.hex(), "signature": signature.hex(),
            "output": output.hex(), "c": proof.c.hex(), "s": proof.s.hex(),
        })
    counts = [6] if constants.VALIDATOR_COUNT == 6 else [6, 9, 300, 1023]
    for count in counts:
        ring = jam_ring_context(srs, [key.public_key for key in keys[:count]])
        vrf_input = b"jam_ticket_seal" + b"e" * 32 + b"\x00"
        signature = ring.ring_vrf_sign(3, member.private_key, vrf_input, b"")
        output = member.vrf_output(vrf_input)
        assert len(signature) == 784
        assert ring.ring_vrf_verify(vrf_input, b"", signature) == output
        report["rings"].append({"count": count, "commitment": ring.commitment.hex(), "signature": signature.hex(), "output": output.hex(), "input": vrf_input.hex()})
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({**report["metadata"], "captured_ietf": len(report["ietf"]), "captured_rings": counts}, indent=2))


def verify(srs: bytes, source: Path, *, exact_proofs: bool = True):
    report = json.loads(source.read_text())
    assert settings.TEST_SUITE == report["metadata"]["settings"]["TEST_SUITE"]
    keys = keypairs(constants.VALIDATOR_COUNT)
    member = keys[3]
    for item in report["keys"]:
        key = keys[item["index"]]
        assert key.private_key.hex() == item["secret"]
        assert key.public_key.hex() == item["public"]
    for item in report["ietf"]:
        vrf_input, aux, signature = map(bytes.fromhex, (item["input"], item["aux"], item["signature"]))
        assert member.ietf_vrf_verify(vrf_input, aux, signature).hex() == item["output"]
        assert member.vrf_output(vrf_input).hex() == item["output"]
        regenerated = member.ietf_vrf_sign(vrf_input, aux)
        assert member.ietf_vrf_verify(vrf_input, aux, regenerated).hex() == item["output"]
        if exact_proofs:
            assert regenerated.hex() == item["signature"]
        proof = backend.generate_vrf_proof(member.private_key, vrf_input, b"legacy proof output data", aux)
        assert len(proof.c) == len(bytes.fromhex(item["c"]))
        assert len(proof.s) == len(bytes.fromhex(item["s"]))
        if exact_proofs:
            assert proof.c.hex() == item["c"] and proof.s.hex() == item["s"]
    for item in report["rings"]:
        ring = jam_ring_context(srs, [key.public_key for key in keys[:item["count"]]])
        assert ring.commitment.hex() == item["commitment"]
        assert ring.ring_vrf_verify(bytes.fromhex(item["input"]), b"", bytes.fromhex(item["signature"])).hex() == item["output"]
    print(json.dumps({**report_metadata(), "verified_source": str(source), "ietf_verified": len(report["ietf"]), "rings_verified": len(report["rings"]), "proof_bytes_required_identical": exact_proofs}, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("capture", "verify"))
    parser.add_argument("report", type=Path)
    parser.add_argument("--allow-proof-differences", action="store_true", help="For installed 0.6.1 only: verify proofs while permitting different nonce bytes")
    parser.add_argument("--srs", type=Path, default=Path(settings.__file__).parent / "data" / "zcash-srs-2-11-uncompressed.bin")
    args = parser.parse_args()
    if args.mode == "verify":
        verify(args.srs.read_bytes(), args.report, exact_proofs=not args.allow_proof_differences)
    else:
        capture(args.srs.read_bytes(), args.report)


if __name__ == "__main__":
    main()
