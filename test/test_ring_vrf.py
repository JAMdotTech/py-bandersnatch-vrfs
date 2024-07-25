import unittest

from bandersnatch_vrfs import ring_vrf_sign, ring_vrf_verify, ietf_vrf_sign


class TestRingVRF(unittest.TestCase):

    def test_ring_vrf_sign_verify(self):
        with open('../data/zcash-srs-2-11-uncompressed.bin', 'rb') as fp:
            ring_data = fp.read()

        prover_key_index = 3

        # TODO convert Vec<u8> to bytes
        signature = bytes(ring_vrf_sign(ring_data, prover_key_index, b"foo", b"bar"))

        self.assertEqual(
            '3d31c3db69741dbeef0b29aeb1f9370d4bbe2365c18586510db8a640101aa42266709f8da7d09a212d5282804e3b824fa8c0c1ffd13a65633ad16f5dab2002bde335816fb40de9cf2ee723ee7621da69b73676d727bc0a28828a08984620f0d625e5c5bd6eb407733c04877094b35c32a9293bc73637cd3da19a00410b74a6cdccbb1be20256cce76f68db1e1e386119870b8bcbc4ac0969f332715754d49009879ad324888180e0064831edc42201301477554180585eb0cf1199de7b512f0298e791ca47f3e2200cf3d7833c55bfacae40174ad122273f5c65aaa2037c132f8c784c7933752c6047b9d4fe7f0cd17aa87b94379b86927a13bc49e20120184f30de45fea3adfcfe06b8ea99354356be270dd9b5816649a80185c395e5d9c1e48fa4c051bc632ebc4ca02c526c4f1216bfb131c10002598e191c21a8a8f48effb0c6de9d38a089ee00ac7937cfee5f1bb43324e62e3177a22f081420a9fe105dbdff7c2f8c65684502abdf52d8100b6502f5287ac5eae2429b215cbc6645422e3eec15627f384e9f837c8186f11a76987971d9dadc92e1f281f6bf3f4a24633e88acedd8c22c23906136ba88a5feda6b7db40f5e488ae2e2b0b7a4537ef1ee3d7021deb02e8571063716be53a61b095c742b5ab6357561011aee3b2d1c5544537d2260aa70ccea3ff11966503faa898f0bf82a49099e4768edef38ef86c3e5269b10d76755144762d7da583f99e2bd0643580c6f2afb16a8ae1d11b79fc2ed33725b871e545ad010fadc7d9ad95a036ec89555bfaf3587c561032c2179a6746c5aecd2f2b32ecc376fcea547ff57730e0f0dff7cf5a7ceb1fa56919c1ea10c6bae6cbfc6bffbf87a7a1cbb6d5309aea20b8b66057789c4e1ed68c43e20547f3417e72143a968095fa5afe39717d7ca9b732d9edec03e0714ce9806848a38196011010a0ba4b34772be196597a855950db398b587b1d96c1abcdf54c45a029db0f1e577cdcd2db8f998827a33b45904fc260852888c2dd2fee32a9b1ed0879647b392f8dcd197db96f8f5ff3378f52b1d7fd6e6b479babb35f45d922ea79959865330f88ba9b4d09c9e84a2072f32ce34',
            signature.hex()
        )

        ring_vrf_output = bytes(ring_vrf_verify(ring_data, b"foo", b"bar", signature))

        self.assertEqual(
            '6b260bfda2e3ef118c529f30b60dfa4678fbeef3682b55ba002aa8633f1b0364',
            ring_vrf_output.hex()
        )

