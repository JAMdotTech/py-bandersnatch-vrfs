"""Concurrency regressions run in children so a native deadlock has a timeout."""

import subprocess
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from bandersnatch_vrfs import (
    RingContext,
    public_from_secret,
    secret_from_seed,
    vrf_output,
)


ROOT = Path(__file__).resolve().parents[1]


def ring_material():
    ring_data = (ROOT / "data/zcash-srs-2-11-uncompressed.bin").read_bytes()
    secrets = [secret_from_seed(i.to_bytes(8, "little")) for i in range(12)]
    publics = [public_from_secret(secret) for secret in secrets]
    return ring_data, secrets, publics


def concurrent_first_sign():
    ring_data, secrets, publics = ring_material()
    context = RingContext(ring_data, publics[:6], ring_capacity=1023)
    # A separate verifier must not share the signer's cached preparation.
    verifier = RingContext(ring_data, publics[:6], ring_capacity=1023)
    indices = (0, 1, 2, 5)
    barrier = threading.Barrier(len(indices))

    def sign(index):
        barrier.wait(timeout=30)
        results = []
        # Exercise initialization and reuse, with independent prover positions
        # and transcripts even when all calls share the same preparation.
        for attempt in range(2):
            message = "member-{}-attempt-{}".format(index, attempt).encode()
            aux = "aux-{}-{}".format(attempt, index).encode()
            signature = context.ring_vrf_sign(index, secrets[index], message, aux)
            results.append((message, aux, signature, vrf_output(secrets[index], message)))
        return results

    with ThreadPoolExecutor(max_workers=len(indices)) as executor:
        results = list(executor.map(sign, indices))
    for member_results in results:
        for message, aux, signature, expected in member_results:
            assert verifier.ring_vrf_verify(message, aux, signature) == expected
            try:
                verifier.ring_vrf_verify(message, aux + b"-wrong", signature)
            except ValueError:
                pass
            else:
                raise AssertionError("concurrent proof did not bind additional data")


def independent_contexts():
    ring_data, secrets, publics = ring_material()
    layouts = (
        (tuple(range(6)), 6),
        (tuple(reversed(range(6))), 6),
        (tuple(range(6)), 1023),
        (tuple(range(6, 12)), 1023),
    )
    contexts = [
        RingContext(ring_data, [publics[i] for i in layout], ring_capacity=capacity)
        for layout, capacity in layouts
    ]
    assert len({context.commitment for context in contexts}) == len(contexts)
    jobs = [(context_index, member_index) for context_index in range(4) for member_index in (0, 5)]
    barrier = threading.Barrier(len(jobs))

    def sign(job):
        context_index, member_index = job
        secret = secrets[layouts[context_index][0][member_index]]
        message = "context-{}-member-{}".format(*job).encode()
        aux = "context-aux-{}-{}".format(*job).encode()
        barrier.wait(timeout=30)
        signature = contexts[context_index].ring_vrf_sign(member_index, secret, message, aux)
        return context_index, message, aux, signature, vrf_output(secret, message)

    with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
        results = list(executor.map(sign, jobs))
    for context_index, message, aux, signature, expected in results:
        assert contexts[context_index].ring_vrf_verify(message, aux, signature) == expected
        other_context = contexts[(context_index + 1) % len(contexts)]
        try:
            other_context.ring_vrf_verify(message, aux, signature)
        except ValueError:
            pass
        else:
            raise AssertionError("proof verified against a different ring")


def concurrent_constructors():
    ring_data, _, publics = ring_material()
    layouts = ((publics[:6], 6), (publics[:6], 1023), (publics[6:], 1023))
    expected = [RingContext(ring_data, keys, ring_capacity=capacity).commitment for keys, capacity in layouts]
    jobs = tuple(range(len(layouts))) * 2
    barrier = threading.Barrier(len(jobs))

    def construct(layout_index):
        keys, capacity = layouts[layout_index]
        barrier.wait(timeout=30)
        context = RingContext(ring_data, keys, ring_capacity=capacity)
        return layout_index, context.commitment

    with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
        results = list(executor.map(construct, jobs))
    for layout_index, commitment in results:
        assert commitment == expected[layout_index]


SCENARIOS = {
    "first-sign": concurrent_first_sign,
    "independent-contexts": independent_contexts,
    "constructors": concurrent_constructors,
}


class TestRingConcurrency(unittest.TestCase):
    def run_scenario(self, name):
        try:
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), name],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.fail("native ring concurrency scenario timed out: " + name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_concurrent_first_sign_and_reuse(self):
        self.run_scenario("first-sign")

    def test_concurrent_contexts_keep_keys_order_and_capacity_separate(self):
        self.run_scenario("independent-contexts")

    def test_concurrent_constructors_match_sequential_commitments(self):
        self.run_scenario("constructors")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] in SCENARIOS:
        SCENARIOS[sys.argv[1]]()
    else:
        unittest.main()
