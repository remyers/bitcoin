from test_framework.test_framework import BitcoinTestFramework
from test_framework.script import CScript, TapTree, TapLeaf
from test_framework.key import *
import binascii
import hashlib

class key_adaptor_signature(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):

        # Repeat test for random participant numbers/tweaker index.
        for i in range(0,10):

            num_participants = random.randint(2,6)

            keys = []
            pubkeys = []
            for _ in range(num_participants):
                private_key = ECKey()
                private_key.generate()
                public_key = private_key.get_pubkey()
                keys.append((private_key, public_key))
                pubkeys.append(public_key)

            c_map, pk_musig = generate_musig_key(pubkeys)

            keys_c = []
            for private, public in keys:
                private_c = private.mul(c_map[public])
                public_c = public.mul(c_map[public])
                keys_c.append((private_c, public_c))

            nonce_map = {}
            nonce_points = []
            for private_c, public_c in keys_c:
                nonce_map[public_c] = generate_schnorr_nonce()
                nonce_points.append(nonce_map[public_c].get_pubkey())

            R_agg, negated = aggregate_schnorr_nonces(nonce_points)

            msg = hashlib.sha256(b'transaction').digest()
            sigs = []
            for private_c, public_c in keys_c:
                signature = private_c.sign_musig(nonce_map[public_c], negated, R_agg, pk_musig, msg)
                sigs.append(signature)

            # Adaptor Signatures.
            # s' = r + t + H(R_x|P|m)x      (Adaptor Sig Creation)
            # S' = R_B + T + H(R_x|P|m)x_B  (Adaptor Sig Validation)
            t = hashlib.sha256(b'adaptor tweak').digest()
            tk = ECKey()
            tk.set(t, True)
            Tk = tk.get_pubkey()

            # Tweak a signature.
            i = random.randint(0, len(sigs)-1)
            sig = sigs[i]
            sig_adaptor = tweak_signature(sig, t)
            private_c, public_c = keys_c[i]
            assert(public_c.verify_adaptor(sig_adaptor, Tk, R_agg, pk_musig, msg))

            # Recover Secret
            t_recovered = get_adaptor_tweak(sig_adaptor, sig)
            assert(t_recovered == t)

            # Convert Adaptor signature to Regular Valid Signature.
            # R, s' -> R, s
            sig_recovered = tweak_signature(sig_adaptor,t,negate=True)
            assert(sig_recovered == sig)


if __name__ == '__main__':
    key_adaptor_signature().main()