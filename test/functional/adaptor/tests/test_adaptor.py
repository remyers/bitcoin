import os
import unittest

from adaptor.adaptor import *
from adaptor.ecdsa import *
from adaptor.schnorr import *

def rand32():
    return int_from_bytes(os.urandom(32))

class TestsAdaptor(unittest.TestCase):

    def test_adaptor_ecdsa(self):
        x = 10
        y = 14
        message_hash = b'\xaa'*32
        Y = y * G
        X = x * G
        a = ecdsa_adaptor_encrypt(x, Y, message_hash)
        self.assertTrue(ecdsa_adaptor_verify(X, Y, message_hash, a))
        sig = ecdsa_adaptor_decrypt(a, y)
        y_recovered = ecdsa_adaptor_recover(Y, a, sig)
        self.assertEqual(y, y_recovered)

    def test_adaptor_schnorr(self):
        x = 10
        y = 14
        message_hash = b'\xaa'*32
        Y = y * G
        X = x * G
        a = schnorr_adaptor_encrypt(x, y, message_hash)
        self.assertTrue(schnorr_adaptor_verify(X, Y, message_hash, a))
        sig = schnorr_adaptor_decrypt(a, y)
        y_recovered = schnorr_adaptor_recover(a, sig)
        self.assertEqual(y, y_recovered)

    def test_dlc_bet_ecdsa(self):
        # Source: https://github.com/discreetlogcontracts/dlcspecs/blob/master/Introduction.md
        # Alice and Bob want to bet on an outcome of some event.
        # For the sake of simplicity, the event has a binary outcome, either
        # Alice or Bob wins.
        # Alice and Bob have access to an Oracle.
        # The Oracle will publish its pubkey P and the nonce R that it will use
        # for the event.
        # Alice's keys
        a = rand32()
        A = a * G
        # Bob's keys
        b = rand32()
        B = b * G
        # Oracle's keys
        p = rand32()
        P = p * G
        # Oracle's event nonces
        k = rand32()
        R = k * G

        # Alice and Bob create a "Funding Transaction" sending funds to a 2of2
        # output multi(2, A, B) without signing it.
        # We need to know the txid of the tx even if it's not signed, thus all
        # tx inputs must be segwit.
        # Each gambler constructs a tx spending such output and sending the
        # funds to his/her desired destination, such tx are called Contract
        # Execution Transactions (CET).
        # CETs require some signature hashes to be signed, CET sending funds to
        # Alice requires m_ta, CET sending funds to Bob requires m_tb.
        # They associate m_ea and m_eb to the outcomes of the event.
        # If Alice wins, Oracle will schnorr sign m_ea.
        # If Bob wins, Oracle will schnorr sign m_eb.
        # Why schnorr? We need linearity.
        m_ta = b'\x1a' * 32  # signature hash to be signed if Alice wins
        m_tb = b'\x1b' * 32  # signature hash to be signed if Bob wins
        m_ea = b'\xea' * 32  # message that Oracle will sign if Alice wins
        m_eb = b'\xeb' * 32  # message that Oracle will sign if Bob wins

        # Alice and Bob compute the signature points for the two messages.
        S_a = R + schnorr_challenge(P, R, m_ea) * P
        S_b = R + schnorr_challenge(P, R, m_eb) * P
        # What is the signature point?
        # s, R = schnorr_sign(p, m)
        # S = s * G  # signature point
        # Note that the signature points can be computed without secrets.
        # If Alice wins, Oracle will sign m_ea, and thus reveal the discrete
        # logarithm of S_a.

        # Alice produces an adaptor signature for message m_tb, encrypted with
        # signature point S_b.
        adaptor_sig_a = ecdsa_adaptor_encrypt(a, S_b, m_tb)
        # Bob produces an adaptor signature for message m_ta, encrypted with
        # signature point S_a.
        adaptor_sig_b = ecdsa_adaptor_encrypt(b, S_a, m_ta)

        # They both exchange the adaptor signatures.
        # Alice verifies Bob's adaptor signature:
        self.assertTrue(ecdsa_adaptor_verify(B, S_a, m_ta, adaptor_sig_b))
        # Bob verifies Alice's adaptor signature:
        self.assertTrue(ecdsa_adaptor_verify(A, S_b, m_tb, adaptor_sig_a))
        # After verification succeeds, each party signs the Funding
        # Transaction, which can then be broadcast.
        # Alice and Bob wait for the event to happen.
        # If the Oracle becomes unavailable, Alice and Bob can cooperate to
        # spend, ignoring the event result.

        # Now suppose WLOG that Alice wins.
        # Oracle signs m_ea, using nonce (k, R) and publishes the signature.
        sig = schnorr_sign(p, m_ea, k=k)
        # Alice sees the signature and extracts the decryption key s_a for the
        # adaptor signature produced by Bob.
        s_a, R_recovered = sig
        self.assertEqual(R_recovered, R)
        # Alice decrypts Bob's adaptor signature and extract a valid signature
        # from Bob for message m_ta.
        sig_b = ecdsa_adaptor_decrypt(adaptor_sig_b, s_a)
        self.assertTrue(ecdsa_verify(B, m_ta, sig_b))

        # Finally Alice sings message m_ta and is now able to spend the 2of2
        # output.
        sig_a = ecdsa_sign(a, m_ta)
        self.assertTrue(ecdsa_verify(A, m_ta, sig_a))
