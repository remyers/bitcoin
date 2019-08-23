from test_framework.test_framework import BitcoinTestFramework
from test_framework.script import CScript, TapTree, TapLeaf
from test_framework.key import *
import binascii
import hashlib

class key_discrete_log_contract(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):

        # Create Oracle pubkeys R, V.
        v = ECKey()
        v.generate()
        r = generate_schnorr_nonce()
        R = r.get_pubkey()
        V = v.get_pubkey()

        # Create x and P for observer.
        x = ECKey()
        x.generate()
        P = x.get_pubkey()

        # Contract = P + S = P + R + H(R_x|V|m)V
        # (for anticipated future message m)
        msg = hashlib.sha256(b'oracle_msg').digest()
        P_dlc = P.generate_dlc(msg, V, R)

        # Oracle creates signature s,(R) for m.
        # (Event corresponding to m has occured.)
        sig = v.sign_schnorr_with_nonce(msg, r)
        s_b = sig[32:]
        xs = x.add(s_b)
        assert(xs.get_pubkey().get_bytes() == P_dlc.get_bytes())

if __name__ == '__main__':
    key_discrete_log_contract().main()