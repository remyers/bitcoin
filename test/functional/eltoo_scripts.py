#!/usr/bin/env python3
# Copyright (c) 2015-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
eltoo payment channel scripts
"""

from test_framework.messages import (
    CScriptWitness
)

from test_framework.script import (
    hash160,
    CScript,
    CScriptNum,
    OP_1,
    OP_2,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_DROP,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_IF,
    OP_NOTIF
)

CSV_DELAY = 20
CLTV_START_TIME = 500000000

def int_to_bytes(x) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

# eltoo taproot scripts
# see https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-May/001996.html
def get_update_tapscript(state):
    # eltoo Update output
    return CScript([
        CScriptNum(CLTV_START_TIME + state),    # check state before signature
        OP_CHECKLOCKTIMEVERIFY,                 # does nothing if nLockTime of tx is a later state
        OP_DROP,                                # remove state value from stack
        OP_1,                                   # single byte 0x1 means the BIP-118 public key == taproot internal key
        OP_CHECKSIG
    ])


def get_settle_tapscript():
    # eltoo Settle output
    return CScript([
        CScriptNum(CSV_DELAY),                  # check csv delay before signature
        OP_CHECKSEQUENCEVERIFY,                 # does nothing if nSequence of tx is later than (blocks) delay
        OP_DROP,                                # remove delay value from stack
        OP_1,                                   # single byte 0x1 means the BIP-118 public key == taproot internal key
        OP_CHECKSIG
    ])


def get_htlc_claim_tapscript(preimage_hash, pubkey):
    # HTLC Claim output (with preimage)
    return CScript([
        OP_HASH160,                             # check preimage before signature
        preimage_hash,
        OP_EQUALVERIFY,
        pubkey,                            # pubkey of party claiming payment
        OP_CHECKSIG
    ])


def get_htlc_refund_tapscript(expiry, pubkey):
    # HTLC Refund output (after expiry)
    return CScript([
        CScriptNum(expiry),                     # check htlc expiry before signature
        OP_CHECKLOCKTIMEVERIFY,                 # does not change stack if nLockTime of tx is a later time
        OP_DROP,                                # remove expiry value from stack
        pubkey,                            # pubkey of party claiming refund
        OP_CHECKSIG
    ])


def get_eltoo_update_script(state, witness, other_witness):
    """Get the script associated with a P2PKH."""
    # or(1@and(older(100),thresh(2,pk(C),pk(C))),
    # 9@and(after(1000),thresh(2,pk(C),pk(C)))),
    return CScript([
        OP_2, witness.update_pk, other_witness.update_pk, OP_2, OP_CHECKMULTISIG,
        OP_NOTIF,
            OP_2, witness.settle_pk, other_witness.settle_pk, OP_2, OP_CHECKMULTISIGVERIFY,
            CScriptNum(CSV_DELAY), OP_CHECKSEQUENCEVERIFY,
        OP_ELSE,
            CScriptNum(CLTV_START_TIME + state), OP_CHECKLOCKTIMEVERIFY,
        OP_ENDIF,
    ])


def get_eltoo_update_script_witness(witness_program, is_update, witness, other_witness):
    script_witness = CScriptWitness()
    if is_update:
        sig1 = witness.update_sig
        sig2 = other_witness.update_sig
        script_witness.stack = [b'', sig1, sig2, witness_program]
    else:
        sig1 = witness.settle_sig
        sig2 = other_witness.settle_sig
        script_witness.stack = [b'', sig1, sig2, b'', b'', b'', witness_program]
    return script_witness


def get_eltoo_htlc_script(refund_pubkey, payment_pubkey, preimage_hash, expiry):
    return CScript([
        OP_IF,
            OP_HASH160, preimage_hash, OP_EQUALVERIFY,
            payment_pubkey,
        OP_ELSE,
            CScriptNum(expiry), OP_CHECKLOCKTIMEVERIFY, OP_DROP,
            refund_pubkey,
        OP_ENDIF,
        OP_CHECKSIG,
    ])

def get_eltoo_htlc_script_witness(witness_program, preimage, sig):
    script_witness = CScriptWitness()

    # minimal IF requires empty vector or exactly '0x01' value to prevent maleability
    if preimage is not None:
        script_witness.stack = [sig, preimage, int_to_bytes(1), witness_program]
    else:
        script_witness.stack = [sig, b'', witness_program]
    return script_witness


def get_p2pkh_script(pubkey):
    """Get the script associated with a P2PKH."""
    return CScript([OP_DUP, OP_HASH160, hash160(pubkey), OP_EQUALVERIFY, OP_CHECKSIG])