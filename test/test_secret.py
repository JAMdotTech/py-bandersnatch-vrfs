import unittest

from bandersnatch_vrfs import secret_from_seed, public_from_secret


class TestSecret(unittest.TestCase):

    def test_secret_from_seed(self):
        secret_seed = bytes([3, 0, 0, 0, 0, 0, 0, 0])
        secret_key = secret_from_seed(secret_seed)
        self.assertEqual(
            bytes.fromhex("2d1edba09f9ca06a5b9b3555a16959f29a841da69ebe5175694ffa4f8be04f1a"), secret_key
        )

    def test_public_from_secret(self):
        secret_key = bytes.fromhex("2bd8776e6ca6a43d51987f756be88b643ab4431b523132f675c8f0004f5d5a17")
        public_key = public_from_secret(secret_key)
        self.assertEqual(
            bytes.fromhex("76adde367eebc8b21f7ef37e327243a77e34e30f9a211fda05409b49f16f3473"), public_key
        )
