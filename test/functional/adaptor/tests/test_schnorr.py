import unittest

from adaptor.schnorr import *

class TestsSchnorr(unittest.TestCase):

    def test_schnorr(self):
        x = 10
        message_hash = b'\xaa'*32
        X = x * G
        sig = schnorr_sign(x, message_hash)
        self.assertTrue(schnorr_verify(X, message_hash, sig))
