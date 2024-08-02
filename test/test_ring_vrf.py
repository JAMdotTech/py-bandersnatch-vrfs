import unittest
from os import path

from bandersnatch_vrfs import ring_vrf_sign, ring_vrf_verify, ietf_vrf_sign, secret_from_seed, public_from_secret, \
 ietf_vrf_verify


class TestRingVRF(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Set up ring using Zcash Structured Reference String with test private/public pairs
        cls.ring_size = 1023
        cls.ring_secrets = [
            secret_from_seed(int.to_bytes(i, length=8, byteorder='little')) for i in range(0, cls.ring_size)
        ]
        cls.ring_publics = [public_from_secret(cls.ring_secrets[i]) for i in range(0, cls.ring_size)]
        data_dir = path.join(path.dirname(path.abspath(__file__)), '..', 'data')
        with open(path.join(data_dir, 'zcash-srs-2-11-uncompressed.bin'), 'rb') as fp:
            cls.ring_data = fp.read()

    def test_ring_vrf_sign_verify(self):

        prover_key_index = 3
        vrf_input_data = b"foo"

        # Anonymous VRF, used for tickets submission
        aux_data = b"bar"

        # Prover signs data
        signature = ring_vrf_sign(
            self.ring_data, self.ring_publics, self.ring_secrets[prover_key_index], prover_key_index,
            vrf_input_data, aux_data
        )

        self.assertEqual(
            '3d31c3db69741dbeef0b29aeb1f9370d4bbe2365c18586510db8a640101aa4227ea3f8b5df55dc76caf824dce78e02764f94ef5df0bbadb2fc982abd9c7a39c896ecddd194599527e2e08fea913cd1b444eef0e1add09593ab3bb5ce44b4c3be25e5c5bd6eb407733c04877094b35c32a9293bc73637cd3da19a00410b74a6cdfc4237cc9bc41ee56dfb773bd6e3848508536a40c4271a9bcaa8d7352660670bc2bec8199d5675c931357bcaddbfbe1f0c7f8c15f3f327a646952f7d3640e415836e583617737b3ff88aab485b8cf056edda4a0c8a5dff43a37d6768a055009f0aaf53fd0972a39a90a98d428a850292a87b94379b86927a13bc49e20120184f30de45fea3adfcfe06b8ea99354356be270dd9b5816649a80185c395e5d9c1e49935ac45bb41de8f2a16066da3f0ea469d37014838a7f636bc0d4f50ae571dfaf2b9aa3b2a02b9c216b0b4706fac870ca2503472fcadc60ec266664ffefb5c9a3f46f2142ea6b475a1a232c187a8cc09591d5a2b8ab9a6d32739d68282f976f0950c87b6c602e9e2fb4708cbfa705bf9b54c9b53b8b974934f9b9c6031e86d61defdfb9ea994dd897510f00df780c64eef2ccb41c506beeeeab3ce2cedf947672a2635b0e46fcb9eaecb3f12305d7c1ee371e613c8ddbec4e3d9960c0f80fe4bf07e9ca7322528932a0e9d11be731e42788086f33492c466944129a4dd223f5542e15683e7bb01ca453266697a7f234d28f2b7159343e7278bf02c01fe620b201fd89b273c2d171f8ff4adf1ca43f24207ee5b9e19b3724527d46fdf85d9fe4f02ed1fd78d90f317da2306d1f325530697af1c7ec5775c33273a0104f7722332a9cdbe6b737a1e9fc95d4a5ee5616744c2d644df3226aa33b1e24de9ddaced00dc8ff3a5ae1a5bb184ad990e6f9de1cbc1bfae53e904db070b19390aabc01bafbf618b6402bfa1b3fbfbd8c9a9f42f5eb36b9e247d97ba8fb91b1b14072380e9f747ee3afb1b3589a6188d605da2864e0721ed11b3de603ece9448049bec9777b6ae6c515455ec34cc18dad7f4e52404fbd1eb4e2cc11d6a3f1c4f3d70bae0a9326d5f90a7efddbf1098321eb6576e3e',
            signature.hex()
        )

        # Verifier checks it without knowing who is the signer.
        ring_vrf_output = ring_vrf_verify(self.ring_data, self.ring_publics, vrf_input_data, aux_data, signature)

        self.assertEqual(
            '6b260bfda2e3ef118c529f30b60dfa4678fbeef3682b55ba002aa8633f1b0364',
            ring_vrf_output.hex()
        )

    def test_ticket_claim(self):
        # Non-anonymous VRF, used for ticket claim verification during block import.
        signer_key_index = 3
        vrf_input_data = b"foo"

        # Prover signs the same vrf-input data (we want the output to match)
        # But different aux data.
        aux_data = b"hello"
        signature = ietf_vrf_sign(self.ring_secrets[signer_key_index], vrf_input_data, aux_data)

        # Verifier checks the signature knowing the signer identity.
        vrf_output_hash = ietf_vrf_verify(
            self.ring_publics[signer_key_index], vrf_input_data, aux_data, signature
        )

        self.assertEqual(
            '6b260bfda2e3ef118c529f30b60dfa4678fbeef3682b55ba002aa8633f1b0364',
            vrf_output_hash.hex()
        )

    def test_ticket_claim_failed(self):
        signer_key_index = 3
        vrf_input_data = b"foo2"
        aux_data = b"hello"

        signature = bytes.fromhex("3d31c3db69741dbeef0b29aeb1f9370d4bbe2365c18586510db8a640101aa422f4b6e0d9af714b76e385395f003c12e55de33371ba007a910e7a9a8e99b717194bcca70e076295ddc4a2ebb7f6266df4a2c9aab4b3873f0a3f62f60a39f49c0b")

        with self.assertRaises(ValueError) as e:
            ietf_vrf_verify(
                self.ring_publics[signer_key_index], vrf_input_data, aux_data, signature
            )

        self.assertTrue('Verification error' in str(e.exception))

    def test_ring_vrf_invalid_signature(self):

        vrf_input_data = b"foo"
        aux_data = b"bar"

        signature = bytes.fromhex('c7')

        # Verifier checks it without knowing who is the signer.
        with self.assertRaises(ValueError) as e:
            ring_vrf_verify(self.ring_data, self.ring_publics, vrf_input_data, aux_data, signature)

        self.assertTrue('Invalid signature' in str(e.exception))

    def test_ring_vrf_verify_failed(self):

        vrf_input_data = b"foo"
        aux_data = b"bar"

        signature = bytes.fromhex('c7cc725e1ca253150fad8c08d10a7219a6f35f813c34a1741d96320d0fbb2a2a398b04180742aaff60ffa032c39fe800e2c2649fb3fe7ec86daceb5a0f28d64f4c5072e24b8502ff18179b7f644aced25e1c1a715412fd59560236a596d309145fe2ff04c5c68b01908fd019dec9f73711c698d082d55c5e3c2a886fbdf1428abd1b1a031ec7141b8f0298f671e665541cb78ef8150add63d8a1e14327ba361b18474d966d0721dc10778f489d0395fc9eb433638026e3ebf66eca03937c0a0193a0cc0f6e2b00b03280e3164291845a94f888d90bf5a22f5a7f9772632f7400ffcc2b62aba4230b5c18c23131df2124a87b94379b86927a13bc49e20120184f30de45fea3adfcfe06b8ea99354356be270dd9b5816649a80185c395e5d9c1e4b0e25d9f065441e2f77992459c5de6ac2034c563ec20814dd5ba23be44e817685c4986aa1bd431583dced625230abe0f995b2eaa62cc4a69b1752a03479d91da62ed4d1223c92404896410e350570e0b1cd1595c69e1b1c30f36ee3e3d2faa1c84c94a07ea1b20eedb8a7a013ed2c3f853ba1f4e542097d8ddfc4d0cbbff0f709a6a2bdbb9a4a5beced39395b388d3644352bf16090ad908debed66242fe183f4e4f13c681b9b7d0c17090644c2cfe102abad470e358e4db2653b4f2d1367e289c079b18dad41fd18f57e7af6a7cebd08f59b3fdb3319f8c7fcc85012153600cde6a51d812206d6c21e9900d6282a3740e59bddf3c23ffbe0fa8d969ef97da04e7cef7d082417c05ff6b3d667e71bf51ec867ca261f81e34af2fb7abcb254804198f48e4b7ebe48d88565c5b1b3ab851ff2a212717260ca4199b44d6af0ddc5a92dc7c5fdc676de31a8b1db9b18ea6a60c64e9f13759d6a2fdc23fda9b34ab1827520b546f9e460e7272b6bfbe8e81248df52a3a6f32b6897a902acd16fb436077b641e67bee5d11162290a0622b82008b323518a71a4b1b5446a7c05f357d48262920e1f0f9167014d2b13f7fb3292b9dbd0c32c0c910e5a76d41628cc35c8985be72f9f8c02d9a436edaadc454e103d32d614215f9dd98490262e1e5cf2a94d097096c9080280834eaa681a4ffbe2a')

        # Verifier checks it without knowing who is the signer.
        with self.assertRaises(ValueError) as e:
            ring_vrf_verify(self.ring_data, self.ring_publics, vrf_input_data, aux_data, signature)

        self.assertTrue('Verification error' in str(e.exception))
