#!/usr/bin/env python3
# Copyright (c) 2015-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test PoC adaptor signatures using SECP256K1 and x only pubkeys

WARNING: This code has not be validated for correctness, safety or performance. Do not use for
anything but tests."""
import hashlib
from test_framework.test_framework import BitcoinTestFramework

from test_framework.key import (
    compute_xonly_pubkey,
    encryption_key_for,
    generate_privkey,
    schnorr_adaptor_encrypt,
    schnorr_adaptor_verify,
    schnorr_adaptor_decrypt,
    schnorr_adaptor_recover,
    verify_schnorr,
)

class TestAdaptorsig(BitcoinTestFramework):

    def run_test(self):
        # test adaptor signature scheme from Rust schnorr_fun::adaptor impl
        self.test_adaptor_schnorr()

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def test_adaptor_schnorr(self):
        # translated to Python from https://docs.rs/schnorr_fun/0.6.2/schnorr_fun/adaptor/index.html

        # Alice knows: signing_key
        # Bob knows: decryption_key
        # Both know: verification_key, encryption_key
        signing_key = generate_privkey() # x
        verification_key = compute_xonly_pubkey(signing_key)[0] # X
        decryption_key = generate_privkey() # y
        encryption_key = encryption_key_for(int.from_bytes(decryption_key, 'big')) # Y
        msg = hashlib.sha256(b"give 100 coins to Bob").digest()

        # Alice creates an encrypted signature for msg and sends it to Bob
        encrypted_signature, needs_negation = schnorr_adaptor_encrypt(signing_key, verification_key, encryption_key, msg)

        # Bob verifies the encrypted signature and decrypts it
        assert schnorr_adaptor_verify(verification_key, encryption_key, msg, encrypted_signature, needs_negation)
        signature = schnorr_adaptor_decrypt(decryption_key, encrypted_signature, needs_negation)

        # Verify schnorr signature using standard method
        assert verify_schnorr(verification_key, signature, msg)

        # Bob then broadcasts the signature to the public.
        # Once Alice sees it she can recover Bob's secret decryption key
        recovered_decryption_key = schnorr_adaptor_recover(encryption_key, encrypted_signature, signature, needs_negation)
        assert recovered_decryption_key != None

        # Alice got the decryption key, otherwise the signature is not the decryption of our original encrypted signature
        assert recovered_decryption_key == int.from_bytes(decryption_key,'big')

if __name__ == '__main__':
    TestAdaptorsig().main()