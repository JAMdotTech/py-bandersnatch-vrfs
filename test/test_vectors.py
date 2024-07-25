import json
import unittest
from os import path

from bandersnatch_vrfs import public_from_secret


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
            secret_key = vector['sk']

            public = bytes(public_from_secret(bytes.fromhex(secret_key)))

            self.assertEqual(vector['pk'], public.hex(), f"Vector {name}: Pk does not match for")
            # TODO
            # input = vector['h']
            # output = vector['gamma']
            # proof = vector['ad']


