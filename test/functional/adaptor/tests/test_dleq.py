import unittest

from adaptor.dleq import *

class TestsDLEQ(unittest.TestCase):

    def test_dleq(self):
        x = 10
        y = 14
        Y = y * G
        X = x * G
        R = x * Y
        proof = dleq_prove(x, X, Y, R)
        self.assertTrue(dleq_verify(X, Y, R, proof))
