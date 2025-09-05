import unittest
from os import path

from bandersnatch_vrfs import RingContext, ietf_vrf_sign, secret_from_seed, public_from_secret, \
 ietf_vrf_verify, vrf_output


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

    def test_vrf_output(self):
        prover_key_index = 3
        vrf_input_data = b"foo"

        output = vrf_output(self.ring_secrets[prover_key_index], vrf_input_data)

        self.assertEqual(
            '6b260bfda2e3ef118c529f30b60dfa4678fbeef3682b55ba002aa8633f1b0364',
            output.hex()
        )

    def test_ring_vrf_sign_verify(self):

        prover_key_index = 3
        vrf_input_data = b"foo"

        # Anonymous VRF, used for tickets submission
        aux_data = b"bar"

        # Create ring context
        ring_context = RingContext(self.ring_data, self.ring_publics)

        # Prover signs data
        signature = ring_context.ring_vrf_sign(
            prover_key_index, self.ring_secrets[prover_key_index], vrf_input_data, aux_data
        )

        # Verifier checks it without knowing who is the signer.
        ring_vrf_output = ring_context.ring_vrf_verify(vrf_input_data, aux_data, signature)

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

        ring_context = RingContext(self.ring_data, self.ring_publics)

        # Verifier checks it without knowing who is the signer.
        with self.assertRaises(ValueError) as e:
            ring_context.ring_vrf_verify(vrf_input_data, aux_data, signature)

        self.assertTrue('Invalid signature' in str(e.exception))

    def test_ring_vrf_verify_failed(self):

        vrf_input_data = b"foo"
        aux_data = b"bar"

        signature = bytes.fromhex('c7cc725e1ca253150fad8c08d10a7219a6f35f813c34a1741d96320d0fbb2a2a398b04180742aaff60ffa032c39fe800e2c2649fb3fe7ec86daceb5a0f28d64f4c5072e24b8502ff18179b7f644aced25e1c1a715412fd59560236a596d309145fe2ff04c5c68b01908fd019dec9f73711c698d082d55c5e3c2a886fbdf1428abd1b1a031ec7141b8f0298f671e665541cb78ef8150add63d8a1e14327ba361b18474d966d0721dc10778f489d0395fc9eb433638026e3ebf66eca03937c0a0193a0cc0f6e2b00b03280e3164291845a94f888d90bf5a22f5a7f9772632f7400ffcc2b62aba4230b5c18c23131df2124a87b94379b86927a13bc49e20120184f30de45fea3adfcfe06b8ea99354356be270dd9b5816649a80185c395e5d9c1e4b0e25d9f065441e2f77992459c5de6ac2034c563ec20814dd5ba23be44e817685c4986aa1bd431583dced625230abe0f995b2eaa62cc4a69b1752a03479d91da62ed4d1223c92404896410e350570e0b1cd1595c69e1b1c30f36ee3e3d2faa1c84c94a07ea1b20eedb8a7a013ed2c3f853ba1f4e542097d8ddfc4d0cbbff0f709a6a2bdbb9a4a5beced39395b388d3644352bf16090ad908debed66242fe183f4e4f13c681b9b7d0c17090644c2cfe102abad470e358e4db2653b4f2d1367e289c079b18dad41fd18f57e7af6a7cebd08f59b3fdb3319f8c7fcc85012153600cde6a51d812206d6c21e9900d6282a3740e59bddf3c23ffbe0fa8d969ef97da04e7cef7d082417c05ff6b3d667e71bf51ec867ca261f81e34af2fb7abcb254804198f48e4b7ebe48d88565c5b1b3ab851ff2a212717260ca4199b44d6af0ddc5a92dc7c5fdc676de31a8b1db9b18ea6a60c64e9f13759d6a2fdc23fda9b34ab1827520b546f9e460e7272b6bfbe8e81248df52a3a6f32b6897a902acd16fb436077b641e67bee5d11162290a0622b82008b323518a71a4b1b5446a7c05f357d48262920e1f0f9167014d2b13f7fb3292b9dbd0c32c0c910e5a76d41628cc35c8985be72f9f8c02d9a436edaadc454e103d32d614215f9dd98490262e1e5cf2a94d097096c9080280834eaa681a4ffbe2a')

        ring_context = RingContext(self.ring_data, self.ring_publics)

        # Verifier checks it without knowing who is the signer.
        with self.assertRaises(ValueError) as e:
            ring_context.ring_vrf_verify(vrf_input_data, aux_data, signature)

        self.assertTrue('Verification error' in str(e.exception))

    def test_ring_commitment(self):
        ring_context = RingContext(self.ring_data, self.ring_publics)

        self.assertEqual(
            '826744cb1504e259cde1cc3591b3e8422a94e326efe2d07893ddd1f9ccfeb9e0c7de8722e20629382536c16d8b5be6e0872e00e53b290884737ba00f8be6f7f8ddc3bd32a2023fe27339fcec08bb5011bd1fef14ea98876bcf64cb88c003190c96c1b168e2dcc743f9eadda76c041db42d39f27a58418f88c0ea67656a224934e12b5dfc8f0f460a95c2d467fa41907b',
            ring_context.commitment.hex()
        )

    def test_ring_commitment_padding_point(self):

        ring_publics = [b'\x07F\x84m\x17F\x9f\xb2\xf9^\xf3e\xef\xca\xb9\xf4\xe2/\xa1\xfe\xb51\x11\xc9\x957k\xe8\x01\x99\x81\xcc', b'\x15\x1e\\\x8f\xe2\xb9\xd8\xa6\x06\x96jy\xed\xd2\xf9\xe5\xdbG\xe89G\xce6\x8c\xcb\xa5;\xf6\xba \xa4\x0b', b'\x93&\xed\xb2\x1eUAq\x7f\xde$\xec\x08P\x00\xb2\x87\t\x84{\x8a\xab\x1a\xc5\x1f\x84\xe9K7\xca\x1bf', b'$p\xd4\xb7>\x8a^\xfa\x81y\xc9\xef\xffl\x7f\x03\x8e\xceJ\xba^\x97\xab\xfa\n\xdd:\x1aT-\xee4', b'\xffq\xc6\xc0?\xf8\x8a\xdb^\xd5,\x96\x81\xde\x16)\xa5Np/\xc1G)\xf6\xb5\r/\nv\xf1\x85\xb3', b'!\x05e\tD\xfc\xd1\x01b\x1f\xd5\xbb1$\xc9\xfd\x19\x1d\x11Kz\xd96\xc1\xd7\x9dsO\x9f!9.']

        ring_context = RingContext(self.ring_data, ring_publics)

        self.assertEqual(
            'a904d861ad534ad7920ce2cc4e8c9e3af0494b5bafecd583c6c436fe58977ebafbfc468ed31180ed377f6b57c0d34a508dbf8d0182ea4515c850b4b33a5574dcfe2850a89e0909d88653c9134e0112cf6e3fc12f553a41bc39f909890102818b92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf',
            ring_context.commitment.hex()
        )
