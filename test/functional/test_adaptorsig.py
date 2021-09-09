#!/usr/bin/env python3
# Copyright (c) 2015-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Simulation tests for eltoo payment channel update scheme
"""
from adaptor.adaptor import *
from adaptor.ecdsa import *
from adaptor.schnorr import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal
)

from test_framework.key import (
    adaptor_encrypt_schnorr,
    adaptor_verify_schnorr,
    adaptor_decrypt_schnorr,
    adaptor_recover_schnorr,
    compute_xonly_pubkey,
    generate_privkey,
    sign_schnorr,
    tweak_add_pubkey,
    verify_schnorr,
    ECKey,
    ECPubKey,
    SECP256K1_ORDER
)

class TestAdaptorsig(BitcoinTestFramework):

    def run_test(self):
            # new default wallet should load by default when there are no other wallets
            self.nodes[0].createwallet(wallet_name='', load_on_startup=False)
            self.restart_node(0)

            # test schnorr adapter signatures
            self.test_schnorr()
            self.test_adaptor_schnorr()
            self.test_adaptor_schnorr2()

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def test_schnorr(self):
        # x = 10
        # message_hash = b'\xaa'*32
        # X = x * G
        # sig = schnorr_sign(x, message_hash)
        # assert schnorr_verify(X, message_hash, sig)

        x = generate_privkey()
        message_hash = b'\xaa'*32
        X, _ = compute_xonly_pubkey(x)
        sig = sign_schnorr(x, message_hash)
        assert verify_schnorr(X, sig, message_hash)

    def test_adaptor_schnorr(self):
        x = 10
        y = 14
        message_hash = b'\xaa'*32
        Y = y * G
        X = x * G
        a = schnorr_adaptor_encrypt(x, y, message_hash)
        assert schnorr_adaptor_verify(X, Y, message_hash, a)
        sig = schnorr_adaptor_decrypt(a, y)
        y_recovered = schnorr_adaptor_recover(a, sig)
        assert_equal(y, y_recovered)

    def test_adaptor_schnorr2(self):
        x = int(10).to_bytes(32,'big') # generate_privkey()
        y = int(14).to_bytes(32,'big') # generate_privkey()
        message_hash = b'\xaa'*32
        X, neg_x = compute_xonly_pubkey(x)
        Y, neg_y = compute_xonly_pubkey(y)
        a = adaptor_encrypt_schnorr(x, y, message_hash)
        assert adaptor_verify_schnorr(X, Y, message_hash, a)
        sig = adaptor_decrypt_schnorr(a, y)
        y_recovered = adaptor_recover_schnorr(a, sig)
        assert_equal(y, y_recovered)

if __name__ == '__main__':
    TestAdaptorsig().main()