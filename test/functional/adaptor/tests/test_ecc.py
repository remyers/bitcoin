import unittest

from adaptor.ecc import *

class TestsECC(unittest.TestCase):

    def test_ecc(self):
        self.assertEqual(G + G, 2*G)
        self.assertEqual(5*G + 3*G, 8*G)
        self.assertEqual(5*G - 3*G, 2*G)
        self.assertEqual(3*G - 5*G, -2*G)
        self.assertEqual(5*G + (-3*G), 2*G)
        self.assertEqual(-(-G), G)
        self.assertEqual(1*G, G)

        self.assertEqual(3 * mod_inv(3, p) % p, 1)
        self.assertEqual(3 * mod_inv(3, n) % n, 1)
