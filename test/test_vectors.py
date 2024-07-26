import json
import unittest
from os import path

from bandersnatch_vrfs import public_from_secret, generate_vrf_proof


class TestVectors(unittest.TestCase):

    test_vector_file = 'bandersnatch_ed_sha512_ell2_ietf_vectors.json'

    @classmethod
    def setUpClass(cls):
        test_vector_file = path.join(path.dirname(path.abspath(__file__)), 'vectors', cls.test_vector_file)
        with open(test_vector_file) as f:
            cls.test_vector_data = json.load(f)

    def test_vectors(self):
        for vector in self.test_vector_data:
            name = vector['comment']
            secret_key = bytes.fromhex(vector['sk'])

            self.assertEqual(vector['sk'], secret_key.hex(), f"Vector {name}: Pk does not match")

            public = public_from_secret(secret_key)

            self.assertEqual(vector['pk'], public.hex(), f"Vector {name}: Pk does not match")
            # TODO
            # vector_input = bytes.fromhex(vector['h'])
            # vector_output = bytes.fromhex(vector['gamma'])
            # vector_aux = bytes.fromhex(vector['ad'])
            # vector_proof_c = bytes.fromhex(vector['proof_c'])
            # vector_proof_s = bytes.fromhex(vector['proof_s'])
            #
            # proof = generate_vrf_proof(secret_key, vector_input, vector_output, vector_aux)
            #
            # self.assertEqual(vector_proof_c.hex(), proof.c.hex(), f"Vector {name}: Proof does not match for")
            # self.assertEqual(vector_proof_s.hex(), proof.s.hex(), f"Vector {name}: Proof does not match for")




