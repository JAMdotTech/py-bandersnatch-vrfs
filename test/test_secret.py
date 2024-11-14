import unittest

from bandersnatch_vrfs import secret_from_seed, public_from_secret


class TestSecret(unittest.TestCase):

    def test_secret_from_seed(self):
        secret_seed = int.to_bytes(3, length=32, byteorder='big')

        secret_key = secret_from_seed(secret_seed)

        self.assertEqual(
            bytes.fromhex("5820e6de5ad66dbbd7d0c9b90d10f86c19e409882ebca5d5e7d6a251b8eec916"), secret_key
        )

    def test_public_from_secret(self):
        secret_key = bytes.fromhex("5820e6de5ad66dbbd7d0c9b90d10f86c19e409882ebca5d5e7d6a251b8eec916")
        public_key = public_from_secret(secret_key)
        self.assertEqual(
            bytes.fromhex("7097d21ebe3a993d6733c5903871a5f983e073dfe53477a8014cfd37965867e8"), public_key
        )
