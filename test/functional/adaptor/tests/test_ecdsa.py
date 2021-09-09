import unittest

from adaptor.ecdsa import *

class TestsECDSA(unittest.TestCase):

    def test_ecdsa(self):
        x = 10
        message_hash = b'\xaa'*32
        X = x * G
        sig = ecdsa_sign(x, message_hash)
        self.assertTrue(ecdsa_verify(X, message_hash, sig))
