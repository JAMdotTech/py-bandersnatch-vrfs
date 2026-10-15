import struct
import unittest
from pathlib import Path

from bandersnatch_vrfs import (
    RingContext,
    public_from_secret,
    secret_from_seed,
    vrf_output,
)


class TestRingCapacity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ring_data = (
            Path(__file__).resolve().parents[1]
            / "data/zcash-srs-2-11-uncompressed.bin"
        ).read_bytes()
        cls.secrets = [secret_from_seed(i.to_bytes(8, "little")) for i in range(1023)]
        cls.publics = [public_from_secret(secret) for secret in cls.secrets]
        # Legacy caller-side padding, retained only as an interoperability oracle.
        cls.padding_point = bytes.fromhex(
            "92ca79e61dd90c1573a8693f199bf6e1e86835cc715cdcf93f5ef222560023aa"
        )

    def test_default_capacity_is_unchanged(self):
        for count in (0, 6, 300, 1023):
            with self.subTest(count=count):
                keys = self.publics[:count]
                default = RingContext(self.ring_data, keys)
                none = RingContext(self.ring_data, keys, ring_capacity=None)
                explicit = RingContext(self.ring_data, keys, ring_capacity=count)
                self.assertEqual(default.commitment, none.commitment)
                self.assertEqual(default.commitment, explicit.commitment)

    def test_capacity_matches_legacy_padding_and_cross_verifies(self):
        for count in (6, 300, 1023):
            with self.subTest(count=count):
                keys = self.publics[:count]
                context = RingContext(self.ring_data, keys, ring_capacity=1023)
                legacy = RingContext(
                    self.ring_data, keys + [self.padding_point] * (1023 - count)
                )
                self.assertEqual(context.commitment, legacy.commitment)

                # Exercise the last actual member, not just an early ring position.
                index = count - 1
                expected = vrf_output(self.secrets[index], b"capacity-test")
                for prover, verifier in ((context, legacy), (legacy, context)):
                    signature = prover.ring_vrf_sign(
                        index, self.secrets[index], b"capacity-test", b"aux"
                    )
                    self.assertEqual(
                        expected,
                        verifier.ring_vrf_verify(b"capacity-test", b"aux", signature),
                    )

    def test_capacity_selects_domain(self):
        keys = self.publics[:6]
        tiny = RingContext(self.ring_data, keys, ring_capacity=6)
        full = RingContext(self.ring_data, keys, ring_capacity=1023)
        self.assertNotEqual(tiny.commitment, full.commitment)
        signature = full.ring_vrf_sign(0, self.secrets[0], b"input", b"aux")
        with self.assertRaises(ValueError):
            tiny.ring_vrf_verify(b"input", b"aux", signature)

    def test_capacity_is_keyword_only(self):
        with self.assertRaises(TypeError):
            RingContext(self.ring_data, self.publics[:6], 1023)

    def test_capacity_below_member_count_is_rejected(self):
        # Five and six keys select the same native domain; still reject five.
        for capacity in (0, 5):
            with self.subTest(capacity=capacity):
                with self.assertRaisesRegex(ValueError, "number of public keys"):
                    RingContext(self.ring_data, self.publics[:6], ring_capacity=capacity)

    def test_signing_index_must_refer_to_supplied_member(self):
        context = RingContext(self.ring_data, self.publics[:6], ring_capacity=1023)
        for index in (6, 1022, 1023):
            with self.subTest(index=index):
                with self.assertRaisesRegex(ValueError, "supplied public key"):
                    context.ring_vrf_sign(index, self.secrets[0], b"input", b"aux")

    def test_empty_ring_has_no_signing_indices(self):
        context = RingContext(self.ring_data, [], ring_capacity=0)
        with self.assertRaisesRegex(ValueError, "supplied public key"):
            context.ring_vrf_sign(0, self.secrets[0], b"input", b"aux")

    def test_capacity_must_fit_srs(self):
        # The supplied SRS has 6145 G1 powers; its largest ring domain fits 1791 keys.
        keys = self.publics[:6]
        maximum = RingContext(self.ring_data, keys, ring_capacity=1791)
        full = RingContext(self.ring_data, keys, ring_capacity=1023)
        self.assertEqual(maximum.commitment, full.commitment)
        usize_max = (1 << (struct.calcsize("P") * 8)) - 1
        for capacity in (1792, 1 << (struct.calcsize("P") * 8 - 2), usize_max):
            with self.subTest(capacity=capacity):
                with self.assertRaisesRegex(ValueError, "ring_data.*ring_capacity"):
                    RingContext(self.ring_data, keys, ring_capacity=capacity)

    def test_invalid_capacity_argument(self):
        for capacity, exception in (
            (-1, OverflowError),
            (1 << 256, OverflowError),
            (6.5, TypeError),
            ("1023", TypeError),
        ):
            with self.subTest(capacity=capacity):
                with self.assertRaises(exception):
                    RingContext(self.ring_data, self.publics[:6], ring_capacity=capacity)

    def test_invalid_ring_data(self):
        # Two encoded empty PCS vectors exercise the undersized decoded SRS path.
        for data in (b"", b"invalid", self.ring_data[:64], bytes(16)):
            with self.subTest(data_length=len(data)):
                with self.assertRaises(ValueError):
                    RingContext(data, self.publics[:6], ring_capacity=1023)
