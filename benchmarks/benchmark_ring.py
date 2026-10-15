#!/usr/bin/env python3
"""Reproducible ring benchmarks; timings are observations, never pass/fail limits."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import sys
import threading
import time

import bandersnatch_vrfs as vrf


ROOT = Path(__file__).resolve().parents[1]
PROFILES = {"tiny": (6, 6), "full": (1023, 1023), "resized_full": (6, 1023)}
INPUT = b"py-bandersnatch-vrfs benchmark input v1"
AUX = b"py-bandersnatch-vrfs benchmark auxiliary data v1"


def fixtures(profile):
    members, capacity = PROFILES[profile]
    secrets = [vrf.secret_from_seed(i.to_bytes(8, "little")) for i in range(members)]
    keys = [vrf.public_from_secret(secret) for secret in secrets]
    ring_data = (ROOT / "data/zcash-srs-2-11-uncompressed.bin").read_bytes()
    index = members - 1
    return ring_data, keys, capacity, index, secrets[index]


def context_for(fixture):
    ring_data, keys, capacity, _, _ = fixture
    return vrf.RingContext(ring_data, keys, ring_capacity=capacity)


def sign(context, fixture):
    _, _, _, index, secret = fixture
    return context.ring_vrf_sign(index, secret, INPUT, AUX)


def assert_valid(context, fixture, signature):
    expected = vrf.vrf_output(fixture[-1], INPUT)
    actual = context.ring_vrf_verify(INPUT, AUX, signature)
    if actual != expected:
        raise AssertionError("The benchmark signature did not verify to the expected VRF output")


def summary(samples, operations=1):
    median = statistics.median(samples)
    return {
        "samples_seconds": samples,
        "operations_per_sample": operations,
        "median_seconds": median,
        "median_seconds_per_operation": median / operations,
        "median_operations_per_second": operations / median,
    }


def timed(operation):
    start = time.perf_counter()
    value = operation()
    return time.perf_counter() - start, value


def cold_constructor(profile):
    # Only constructor time is measured. Fixtures and Python startup are excluded.
    fixture = fixtures(profile)
    elapsed, context = timed(lambda: context_for(fixture))
    return {"seconds": elapsed, "commitment": context.commitment.hex()}


def constructor_concurrency(fixture, commitment, repeats, jobs):
    def construct(_):
        return context_for(fixture).commitment

    result = {}
    # Keep the pool and Python workers alive before timing. Timings still include
    # dispatch/wait overhead, as an application using an executor would.
    for workers in (1, 4):
        samples = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(lambda _: None, range(workers)))
            for _ in range(repeats):
                seconds, commitments = timed(lambda: list(pool.map(construct, range(jobs))))
                if any(value != commitment for value in commitments):
                    raise AssertionError("Concurrent constructors produced a different commitment")
                samples.append(seconds)
        result[str(workers)] = summary(samples, jobs)
    result["four_worker_speedup"] = (
        result["1"]["median_seconds"] / result["4"]["median_seconds"]
    )
    return result


def gil_progress(fixture, repeats):
    # A Python-only counter can advance only while it owns the GIL. Read it
    # immediately before/after each native call, so intervals between calls do
    # not falsely count as GIL release. The counter intentionally competes with
    # construction; these durations are separate from the performance timings.
    stop = threading.Event()
    ready = threading.Event()
    counter = [0]

    def count():
        ready.set()
        while not stop.is_set():
            counter[0] += 1

    previous_interval = sys.getswitchinterval()
    sys.setswitchinterval(0.001)
    worker = threading.Thread(target=count, name="gil-progress-counter")
    worker.start()
    ready.wait()
    try:
        idle_before = counter[0]
        start = time.perf_counter()
        # Event.wait releases the GIL, providing the reference counter rate.
        stop.wait(0.15)
        idle_seconds = time.perf_counter() - start
        idle_ticks = counter[0] - idle_before
        idle_rate = idle_ticks / idle_seconds
        samples = []
        for _ in range(repeats):
            before = counter[0]
            start = time.perf_counter()
            context = context_for(fixture)
            seconds = time.perf_counter() - start
            ticks = counter[0] - before
            samples.append({
                "constructor_seconds": seconds,
                "python_counter_ticks": ticks,
                "python_counter_ticks_per_second": ticks / seconds,
                "fraction_of_idle_counter_rate": (ticks / seconds) / idle_rate,
            })
            # Keep destruction out of the measured region.
            del context
        return {
            "method": "Python-only background counter during native constructor",
            "switch_interval_seconds": 0.001,
            "idle_seconds": idle_seconds,
            "idle_counter_ticks_per_second": idle_rate,
            "samples": samples,
            "median_fraction_of_idle_counter_rate": statistics.median(
                sample["fraction_of_idle_counter_rate"] for sample in samples
            ),
        }
    finally:
        stop.set()
        worker.join()
        sys.setswitchinterval(previous_interval)


def benchmark_profile(profile, repeats, sign_iterations, constructor_jobs):
    fixture = fixtures(profile)
    cold = []
    commitments = []
    for _ in range(repeats):
        child = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--cold-profile", profile],
            check=True, capture_output=True, text=True,
        )
        sample = json.loads(child.stdout)
        cold.append(sample["seconds"])
        commitments.append(sample["commitment"])

    # Prime Rayon/native lazy initialization before measuring warm constructors.
    context = context_for(fixture)
    commitment = context.commitment
    if any(value != commitment.hex() for value in commitments):
        raise AssertionError("Fresh processes produced a different commitment")

    constructors = []
    first_signs = []
    setup_and_first_sign = []
    for _ in range(repeats):
        seconds, fresh = timed(lambda: context_for(fixture))
        constructors.append(seconds)
        sign_seconds, signature = timed(lambda: sign(fresh, fixture))
        first_signs.append(sign_seconds)
        setup_and_first_sign.append(seconds + sign_seconds)
        assert_valid(fresh, fixture, signature)

    # Prepare once, then sign repeatedly on the same context and signer index.
    signature = sign(context, fixture)
    assert_valid(context, fixture, signature)
    repeated_signs = []
    verifies = []
    for _ in range(repeats):
        signatures = []

        def sign_batch():
            for _ in range(sign_iterations):
                signatures.append(sign(context, fixture))

        seconds, _ = timed(sign_batch)
        repeated_signs.append(seconds)
        # Check every timed proof; keep checks outside signing timings.
        for signature in signatures:
            assert_valid(context, fixture, signature)

        def verify_batch():
            return [context.ring_vrf_verify(INPUT, AUX, signature) for signature in signatures]

        seconds, outputs = timed(verify_batch)
        if any(value != vrf.vrf_output(fixture[-1], INPUT) for value in outputs):
            raise AssertionError("Timed verification returned an unexpected output")
        verifies.append(seconds)

    print("Completed {}".format(profile), file=sys.stderr, flush=True)
    return {
        "members": len(fixture[1]),
        "capacity": fixture[2],
        "signer_index": fixture[3],
        "commitment_hex": commitment.hex(),
        "constructor_fresh_process": summary(cold),
        "constructor_warm_process": summary(constructors),
        "first_signature_fresh_context": summary(first_signs),
        "constructor_plus_first_signature": summary(setup_and_first_sign),
        "repeated_signature_same_context_and_index": summary(repeated_signs, sign_iterations),
        "verification": summary(verifies, sign_iterations),
        "constructor_threads": constructor_concurrency(fixture, commitment, repeats, constructor_jobs),
        "constructor_gil_progress": gil_progress(fixture, repeats),
    }


def command_output(command):
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def metadata(args):
    native_path = next(Path(vrf.__file__).parent.glob("*.so"), None)
    if native_path is None:
        native_path = next(Path(vrf.__file__).parent.glob("*.pyd"), None)
    return {
        "label": args.label,
        "source_revision": args.source_revision,
        "working_tree_revision": command_output(["git", "rev-parse", "HEAD"]),
        "working_tree_status": command_output(["git", "status", "--short"]),
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": shlex.join([sys.executable, *sys.argv]),
        "cwd": os.getcwd(),
        "python_executable": sys.executable,
        "python_version": sys.version,
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "mac_cpu_brand": command_output(["sysctl", "-n", "machdep.cpu.brand_string"])
        if sys.platform == "darwin" else None,
        "package_version": importlib.metadata.version("bandersnatch_vrfs"),
        "module_path": vrf.__file__,
        "native_module_path": str(native_path) if native_path else None,
        "native_module_sha256": sha256(native_path) if native_path else None,
        "wheel_path": args.wheel,
        "wheel_sha256": sha256(args.wheel) if args.wheel else None,
        "rayon_num_threads": os.environ.get("RAYON_NUM_THREADS", "unset (Rayon default)"),
        "repeats": args.repeats,
        "sign_iterations_per_sample": args.sign_iterations,
        "constructor_jobs_per_sample": args.constructor_jobs,
        "seed_description": "secret_from_seed(index.to_bytes(8, 'little')), index starts at zero",
        "input_hex": INPUT.hex(),
        "auxiliary_data_hex": AUX.hex(),
        "srs_sha256": sha256(ROOT / "data/zcash-srs-2-11-uncompressed.bin"),
        "notes": args.notes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", default="unlabelled")
    parser.add_argument("--source-revision", default="unspecified")
    parser.add_argument("--wheel", help="Built wheel whose hash should be recorded")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--notes", default="")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--sign-iterations", type=int, default=3)
    parser.add_argument("--constructor-jobs", type=int, default=4)
    parser.add_argument("--profiles", nargs="+", choices=PROFILES, default=list(PROFILES))
    parser.add_argument("--cold-profile", choices=PROFILES, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.cold_profile:
        print(json.dumps(cold_constructor(args.cold_profile)))
        return
    if min(args.repeats, args.sign_iterations, args.constructor_jobs) < 1:
        parser.error("repeat and iteration counts must be positive")
    start = time.perf_counter()
    result = {"schema_version": 1, "metadata": metadata(args), "profiles": {}}
    for profile in args.profiles:
        result["profiles"][profile] = benchmark_profile(
            profile, args.repeats, args.sign_iterations, args.constructor_jobs,
        )
    result["elapsed_seconds"] = time.perf_counter() - start
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
        print("Saved {} in {:.2f}s".format(args.output, result["elapsed_seconds"]), file=sys.stderr)
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
