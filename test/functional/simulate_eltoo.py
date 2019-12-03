#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Simulation tests for eltoo payment channel update scheme
"""

import copy
from test_framework.base58 import (
    b58decode,
    b58decode_chk,
    b58encode,
    b58encode_chk,
    checksum
)
from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.descriptors import descsum_create
from test_framework.key import ECKey, ECPubKey
from test_framework.messages import (
    COutPoint,
    CScriptWitness,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    FromHex,
    ToHex,
)
from test_framework.mininode import P2PDataStore
from test_framework.script import (
    CScript,
    CScriptNum,
    OP_0,
    OP_1, 
    OP_2,
    OP_2DUP,
    OP_3DUP,
    OP_2DROP,
    OP_CHECKLOCKTIMEVERIFY, 
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_DROP,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_FALSE,
    OP_HASH160,
    OP_IF,
    OP_INVALIDOPCODE,
    OP_NOTIF,
    OP_RETURN,
    OP_TRUE,
    SIGHASH_ALL,
    SIGHASH_ANYPREVOUT,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ALLINPUT,
    SIGHASH_ANYONECANPAY,
    SIGHASH_ANYPREVOUT,
    SIGHASH_NOINPUT,
    SIGHASH_ANYPREVOUTANYSCRIPT,
    SegwitVersion1SignatureHash,
    SignatureHash,
    hash160,
    hash256,
    sha256
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_raises_rpc_error,
    assert_equal
)
import time
import random

RANDOM_RANGE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
NUM_OUTPUTS_TO_COLLECT = 33
CSV_DELAY = 20
DUST_LIMIT = 800
FEE_AMOUNT = 1000
CHANNEL_AMOUNT = 1000000
RELAY_FEE = 100
NUM_SIGNERS = 2
CLTV_START_TIME = 500000000
INVOICE_TIMEOUT = 3600 # 60 minute
BLOCK_TIME = 600 # 10 minutes

def int_to_bytes(x) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def get_eltoo_update_script(node, state, witness, other_witness):
    """Get the script associated with a P2PKH."""
    # or(1@and(older(100),thresh(2,pk(C),pk(C))),
    # 9@and(after(1000),thresh(2,pk(C),pk(C)))),
    return CScript([
        OP_2, witness.GetUpdatePk(node.watch_wallet), other_witness.GetUpdatePk(node.watch_wallet), OP_2, OP_CHECKMULTISIG,
        OP_NOTIF,
            OP_2, witness.GetSettlePk(node.watch_wallet, state), other_witness.GetSettlePk(node.watch_wallet, state), OP_2, OP_CHECKMULTISIGVERIFY,
            CScriptNum(CSV_DELAY), OP_CHECKSEQUENCEVERIFY,
        OP_ELSE,
            CScriptNum(CLTV_START_TIME+state), OP_CHECKLOCKTIMEVERIFY,
        OP_ENDIF,
    ])

def get_eltoo_update_script_witness(witness_program, is_update, witness, other_witness):
    script_witness = CScriptWitness()
    if (is_update):
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
    if preimage != None:
        script_witness.stack = [sig, preimage, int_to_bytes(1), witness_program]
    else:
        script_witness.stack = [sig, b'', witness_program]
    return script_witness

def get_p2pkh_script(pubkey):
    """Get the script associated with a P2PKH."""
    return CScript([OP_DUP, OP_HASH160, hash160(pubkey), OP_EQUALVERIFY, OP_CHECKSIG])

def bip32_generate_hdaddresses(key, network="testnet"):
    """Get tprv, tpub for key and chaincode"""

    # generate random chaincode
    chaincode = random.randrange(0, RANDOM_RANGE).to_bytes(32, 'big')
    chaincode_hex = (''.join(format(i, '02x') for i in chaincode))

    # get private key and public key bytes
    prvkey_bytes = key.get_bytes()
    pubkey_bytes = key.get_pubkey().get_bytes()

    # create 33B hex keys
    prvkey_hex = '00' + (''.join(format(i, '02x') for i in prvkey_bytes))
    pubkey_hex= (''.join(format(i, '02x') for i in pubkey_bytes))

    # use mainnet or testnet version bytes
    if network=="mainnet":
        xpub_version = '0488b21E'
        xprv_version = '0488ADE4'
    else:
        xpub_version = '043587CF'
        xprv_version = '04358394'

    # TODO: generate something other than a master key
    depth = '00'
    fingerprint = '00000000'
    child_index = '00000000'

    xprv_decoded_hex = xprv_version + depth + fingerprint + child_index + chaincode_hex + prvkey_hex
    xprv_decoded = bytes.fromhex(xprv_decoded_hex)
    xprv = b58encode_chk(xprv_decoded)

    xpub_decoded_hex = xpub_version + depth + fingerprint + child_index + chaincode_hex + pubkey_hex
    xpub_decoded = bytes.fromhex(xpub_decoded_hex)
    xpub = b58encode_chk(xpub_decoded)

    return xprv, xpub

def bip32_pubkey(wallet, hdaddress, index, path="/1/1/"):

    descriptor = descsum_create("wpkh(" + hdaddress + path + str(index) +")")
    address = wallet.deriveaddresses(descriptor)[0]
    info = wallet.getaddressinfo(address)
    if info['solvable'] == False:
        result = wallet.importmulti(
           [{
                "desc": descsum_create("wpkh(" + hdaddress + path + str(index) +")") ,
                "timestamp": "now"
            }]
        )
        assert result[0]['success'] == True
        info = wallet.getaddressinfo(address)
    
    pubkey_bytes = bytes.fromhex(info['pubkey'])

    return pubkey_bytes

def bip32_sign(wallet, tx_hash, hdaddress, index, path="/1/1/"):
    descriptor = descsum_create("wpkh(" + hdaddress + path + str(index) +")")
    address = wallet.deriveaddresses(descriptor)[0]
    info = wallet.getaddressinfo(address)
    if info['ismine'] == False:
        result = wallet.importmulti(
           [{
                "desc": descsum_create("wpkh(" + hdaddress + path + str(index) +")") ,
                "timestamp": "now"
            }]
        )
        assert result[0]['success'] == True
        info = wallet.getaddressinfo(address)

    key_wif = wallet.dumpprivkey(address)
    key_bytes = b58decode_chk(key_wif)[1:-1] # strip first and last byte
    update_key = ECKey()
    update_key.set(key_bytes, compressed=True)

    sig = update_key.sign_ecdsa(tx_hash) 

    return sig

def bip32_verify(sig, tx_hash, wallet, hdaddress, state, path="/1/1/"):
    pubkey_bytes = bip32_pubkey( wallet, hdaddress, state, path)
    pk = ECPubKey()
    pk.set( pubkey_bytes )
    v = pk.verify_ecdsa( sig, tx_hash )
    return v
    
class Invoice:
    __slots__ = ("id", "preimage_hash", "amount", "expiry")

    def __init__(self, id, preimage_hash, amount, expiry):
        self.id = id
        self.preimage_hash = preimage_hash
        self.amount = amount
        self.expiry = expiry

    def deserialize(self, f):
       pass

    def serialize(self):
        pass

    def __repr__(self):
        return "Invoice(id=%i hash=%064x amount=%i expiry=%i)" % (self.id, self.preimage_hash, self.amount, self.expiry)

class Witness:
    __slots__ = "xpub", "state", "update_sig", "settle_sig"

    def __init__(self, keys, state=0):
        self.xpub = keys.xpub
        self.state = 0
        self.update_sig = None
        self.settle_sig = None

    def GetUpdatePk(self, wallet):
        return bip32_pubkey(wallet, self.xpub, 0)

    def GetSettlePk(self, wallet, state):
        return bip32_pubkey(wallet, self.xpub, 2 + state)

    def GetPaymentPk(self, wallet):
        return bip32_pubkey(wallet, self.xpub, 1)
    
    def __eq__(self, other):
        match = True
        match &= self.xpub == other.xpub
        match &= self.state == other.state
        # do not compare signatures, only public keys
        return match

    def __repr__(self):
        return "Witness(xpub=%s, state=%d)" % (self.xpub, self.state)

class Keys:
    __slots__ = "key", "xpub", "xprv"

    def __init__(self, xpub = None):
            if xpub != None:
                self.key = None
                self.xprv = None
                self.xpub = xpub
            else:
                self.key = ECKey()
                self.key.generate()
                self.xprv, self.xpub = bip32_generate_hdaddresses(self.key)

    def GetUpdatePk(self, wallet):
        return bip32_pubkey(wallet, self.xpub, 0)

    def GetSettlePk(self, wallet, state):
        return bip32_pubkey(wallet, self.xpub, 2 + state)

    def GetPaymentPk(self, wallet):
        return bip32_pubkey(wallet, self.xpub, 1)

    def GetUpdateSignature(self, wallet, tx_hash, sighash):
        assert self.xprv
        return bip32_sign(wallet, tx_hash, self.xprv, 0) + chr(sighash).encode('latin-1')

    def GetSettleSignature(self, wallet, tx_hash, sighash, state):
        assert self.xprv
        return bip32_sign(wallet, tx_hash, self.xprv, 2 + state) + chr(sighash).encode('latin-1')

    def GetPaymentSignature(self, wallet, tx_hash, sighash):
        assert self.xprv
        return bip32_sign(wallet, tx_hash, self.xprv, 1) + chr(sighash).encode('latin-1')

class PaymentChannel:
    __slots__ = "state", "witness", "other_witness", "spending_tx", "settled_refund_amount", "settled_payment_amount", "received_payments", "offered_payments"

    def __init__(self, witness, other_witness):
        self.state = 0
        self.witness = copy.copy(witness)
        self.other_witness = copy.copy(other_witness)
        self.spending_tx = None
        self.settled_refund_amount = CHANNEL_AMOUNT
        self.settled_payment_amount = 0
        self.offered_payments = {}
        self.received_payments = {}
    
    def TotalOfferedPayments(self):
        total = 0
        for key, value in self.offered_payments.items():
            total += value.amount
        return total

    def TotalReceivedPayments(self):
        total = 0
        for key, value in self.received_payments.items():
            total += value.amount
        return total

    def __repr__(self):
        return "PaymentChannel(spending_tx=%064x settled_refund_amount=%i settled_payment_amount=%i offered_payments=%i received_payments=%i)" % (self.spending_tx, self.settled_refund_amount, 
            self.settled_payment_amount, self.TotalOfferedPayments(), self.TotalReceivedPayments())

class UpdateTx(CTransaction):
    __slots__ = ("state", "witness", "other_witness")
    
    def __init__(self, node, channel_partner):
        super().__init__(tx=None)

        #   keep a copy of initialization parameters
        payment_channel = node.payment_channels[channel_partner]
        self.state = payment_channel.state
        self.witness = copy.copy(payment_channel.witness)
        self.other_witness = copy.copy(payment_channel.other_witness)

        #   set tx version 2 for BIP-68 outputs with relative timelocks
        self.nVersion = 2

        #   initialize channel state
        self.nLockTime = CLTV_START_TIME + self.state

        #   build witness program
        witness_program = get_eltoo_update_script(node, self.state, self.witness, self.other_witness)
        witness_hash = sha256(witness_program)
        script_wsh = CScript([OP_0, witness_hash])

        #   add channel output
        self.vout = [ CTxOut(CHANNEL_AMOUNT, script_wsh) ] # channel balance

    def Sign(self, node, channel_partner):

        keys = node.keychain[channel_partner]

        # add dummy vin, digest only serializes the nSequence value
        prevscript = CScript()
        self.vin.append( CTxIn(outpoint = COutPoint(prevscript, 0), scriptSig = b"", nSequence=0xFFFFFFFE) )

        tx_hash = SegwitVersion1SignatureHash(prevscript, self, 0, SIGHASH_ANYPREVOUT | SIGHASH_SINGLE, CHANNEL_AMOUNT)
        signature = keys.GetUpdateSignature(node.wallet, tx_hash, SIGHASH_ANYPREVOUT | SIGHASH_SINGLE)
        
        # remove dummy vin
        self.vin.pop()

        return signature

    def Verify(self, node):
        verified = True
        witnesses = [ self.witness, self.other_witness ]

        # add dummy vin, digest only serializes the nSequence value
        prevscript = CScript()
        self.vin.append( CTxIn(outpoint = COutPoint(prevscript, 0), scriptSig = b"", nSequence=0xFFFFFFFE) )

        for witness in witnesses:
            pk = ECPubKey()
            pk.set( witness.GetUpdatePk(node.watch_wallet) )
            sig = witness.update_sig[0:-1]
            sighash = witness.update_sig[-1]
            assert(sighash == (SIGHASH_ANYPREVOUT | SIGHASH_SINGLE))
            tx_hash = SegwitVersion1SignatureHash(prevscript, self, 0, sighash, CHANNEL_AMOUNT)
            v = pk.verify_ecdsa( sig, tx_hash )
            if v == False:
                verified = False

        # remove dummy vin
        self.vin.pop()
        
        return verified

    def AddWitness(self, node, spend_tx):
        # witness script to spend update tx to update tx
        self.wit.vtxinwit = [ CTxInWitness() ]
        witness_program = get_eltoo_update_script(node,spend_tx.state, spend_tx.witness, spend_tx.other_witness)
        sig1 = self.witness.update_sig
        sig2 = self.other_witness.update_sig
        self.wit.vtxinwit[0].scriptWitness = CScriptWitness()
        self.wit.vtxinwit[0].scriptWitness.stack = [b'', sig1, sig2, witness_program]
        assert(len(self.vin) == 0)
        self.vin = [ CTxIn(outpoint = COutPoint(spend_tx.sha256, 0), scriptSig = b"", nSequence=0xFFFFFFFE) ]

class SettleTx(CTransaction):
    __slots__ = ("payment_channel")

    def __init__(self, node, channel_partner):
        super().__init__(tx=None)

        self.payment_channel = copy.deepcopy(node.payment_channels[channel_partner])

        #   set tx version 2 for BIP-68 outputs with relative timelocks
        self.nVersion = 2

        #   initialize channel state
        self.nLockTime = CLTV_START_TIME + self.payment_channel.state

        #   build witness program
        witness_program = get_eltoo_update_script(node, self.payment_channel.state, self.payment_channel.witness, self.payment_channel.other_witness)
        witness_hash = sha256(witness_program)
        script_wsh = CScript([OP_0, witness_hash])

        assert self.payment_channel.settled_refund_amount + self.payment_channel.settled_payment_amount + self.payment_channel.TotalOfferedPayments() - CHANNEL_AMOUNT == 0
        settled_amounts = [ self.payment_channel.settled_refund_amount, self.payment_channel.settled_payment_amount ]
        signers = [ self.payment_channel.witness.GetPaymentPk(node.watch_wallet), self.payment_channel.other_witness.GetPaymentPk(node.watch_wallet) ]
        signer_index = 0
        outputs = []
        for amount in settled_amounts:
            if amount > DUST_LIMIT:
                #   pay to new p2pkh outputs, TODO: should use p2wpkh
                payment_pk = signers[signer_index]
                script_pkh = CScript([OP_0, hash160(payment_pk)])
                #self.log.debug("add_settle_outputs: state=%s, signer_index=%d, witness hash160(%s)\n", state, signer_index, ToHex(settlement_pubkey))
                outputs.append(CTxOut(amount, script_pkh))
            signer_index+=1

        for htlc_hash, htlc in self.payment_channel.offered_payments.items():
            if htlc.amount > DUST_LIMIT:
                #   refund and pay to p2pkh outputs, TODO: should use p2wpkh
                refund_pubkey = self.payment_channel.witness.GetPaymentPk(node.watch_wallet)
                payment_pubkey = self.payment_channel.other_witness.GetPaymentPk(node.watch_wallet)
                preimage_hash = self.payment_channel.offered_payments[htlc_hash].preimage_hash
                expiry = self.payment_channel.offered_payments[htlc_hash].expiry
                
                #   build witness program
                witness_program = get_eltoo_htlc_script(refund_pubkey, payment_pubkey, preimage_hash, expiry)
                witness_hash = sha256(witness_program)
                script_wsh = CScript([OP_0, witness_hash])
                #self.log.debug("add_settle_outputs: state=%s, signer_index=%d\n\twitness sha256(%s)=%s\n\twsh sha256(%s)=%s\n", state, signer_index, ToHex(witness_program),
                #    ToHex(witness_hash), ToHex(script_wsh), ToHex(sha256(script_wsh)))
                outputs.append(CTxOut(htlc.amount, script_wsh))

        #   add settlement outputs to settlement transaction
        self.vout = outputs

    def Sign(self, node, channel_partner):
        # TODO: spending from a SetupTx (first UpdateTx) should not use the NOINPUT sighash 

        keys = node.keychain[channel_partner]

        # add dummy vin, digest only serializes the nSequence value
        prevscript = CScript()
        self.vin.append( CTxIn(outpoint = COutPoint(prevscript, 0), scriptSig = b"", nSequence=CSV_DELAY) )

        tx_hash = SegwitVersion1SignatureHash(prevscript, self, 0, SIGHASH_ANYPREVOUT | SIGHASH_SINGLE, CHANNEL_AMOUNT)
        signature = keys.GetSettleSignature(node.wallet, tx_hash, SIGHASH_ANYPREVOUT | SIGHASH_SINGLE, self.payment_channel.state)

        # remove dummy vin
        self.vin.pop()

        return signature

    def Verify(self, node):
        verified = True
        witnesses = [ self.payment_channel.witness, self.payment_channel.other_witness ]

        # add dummy vin, digest only serializes the nSequence value
        prevscript = CScript()
        self.vin.append( CTxIn(outpoint = COutPoint(prevscript, 0), scriptSig = b"", nSequence=CSV_DELAY) )

        for witness in witnesses:
            pk = ECPubKey()
            pk.set( witness.GetSettlePk(node.watch_wallet, self.payment_channel.state) )
            sig = witness.settle_sig[0:-1]
            sighash = witness.settle_sig[-1]
            assert(sighash == (SIGHASH_ANYPREVOUT | SIGHASH_SINGLE))
            tx_hash = SegwitVersion1SignatureHash(prevscript, self, 0, sighash, CHANNEL_AMOUNT)
            v = pk.verify_ecdsa( sig, tx_hash )
            verified = verified and pk.verify_ecdsa( sig, tx_hash )

        # remove dummy vin
        self.vin.pop()
        
        return verified

    def AddWitness(self, node, spend_tx):
        # witness script to spend update tx to settle tx
        assert spend_tx.state == self.payment_channel.state
        self.wit.vtxinwit = [ CTxInWitness() ]
        witness_program = get_eltoo_update_script(node, spend_tx.state, spend_tx.witness, spend_tx.other_witness)
        sig1 = self.payment_channel.witness.settle_sig
        sig2 = self.payment_channel.other_witness.settle_sig
        self.wit.vtxinwit[0].scriptWitness = CScriptWitness()
        self.wit.vtxinwit[0].scriptWitness.stack = [b'', sig1, sig2, b'', b'', b'', witness_program]
        assert(len(self.vin) == 0)
        self.vin = [ CTxIn(outpoint = COutPoint(spend_tx.sha256, 0), scriptSig = b"", nSequence=CSV_DELAY) ]

class RedeemTx(CTransaction):
    __slots__ = ("payment_channel", "secrets", "is_funder", "settled_only", "include_invalid", "block_time")

    def __init__(self, node, payment_channel, secrets, is_funder, settled_only, include_invalid, block_time):
        super().__init__(tx=None)

        self.payment_channel = copy.deepcopy(payment_channel)
        self.secrets = secrets
        self.is_funder = is_funder
        self.settled_only = settled_only
        self.include_invalid = include_invalid
        self.block_time = block_time

        # add settled amount (refund or payment)
        settled_amount = 0
        if self.is_funder:
            amount = self.payment_channel.settled_refund_amount
        else:
            amount = self.payment_channel.settled_payment_amount

        if amount > DUST_LIMIT:
            settled_amount = amount

        # add htlc amounts that are greater than dust and timeout has expired
        if not settled_only:
            for htlc_hash, htlc in self.payment_channel.offered_payments.items():
                if not self.include_invalid and self.is_funder and htlc.expiry > self.block_time:
                    continue
                if not self.include_invalid and not self.is_funder and htlc.preimage_hash not in self.secrets:
                    continue
                if htlc.amount > DUST_LIMIT:
                    settled_amount += htlc.amount
        
        # remove transaction fee from output amount
        settled_amount -= FEE_AMOUNT
        assert(settled_amount > FEE_AMOUNT)

        # no csv outputs, so nVersion can be 1 or 2
        self.nVersion = 2

        # refund outputs to channel funder are only spendable after a specified clock time, all others are unrestricted
        if not self.is_funder or settled_only:
            self.nLockTime = 0           
        else:
            self.nLockTime = self.block_time

        #   build witness program for settled output (p2wpkh)
        pubkey = self.payment_channel.witness.GetPaymentPk(node.watch_wallet)
        script_pkh = CScript([OP_0, hash160(pubkey)])

        #   add channel output
        self.vout = [ CTxOut(settled_amount, script_pkh) ] # channel balance

    def AddWitness(self, node, channel_partner, spend_tx, settled_only):
        keys=node.keychain[channel_partner]
        if self.is_funder:
            signer_index=0
        else:
            signer_index=1
        settled_amounts = [ self.payment_channel.settled_refund_amount, self.payment_channel.settled_payment_amount ]

        # add settled input from htlc sender (after a timeout) or htlc receiver (with preimage)
        input_index = 0
        for amount_index in range(len(settled_amounts)) :
            if settled_amounts[amount_index] > DUST_LIMIT:
                # add input from signer
                if amount_index is signer_index:
                    self.vin.append( CTxIn(outpoint = COutPoint(spend_tx.sha256, input_index), scriptSig = b"", nSequence=0xfffffffe) )
                input_index += 1
            
        if not settled_only:
            # add htlc inputs, one per htlc
            for htlc_hash, htlc in self.payment_channel.offered_payments.items():
                if not self.include_invalid and self.is_funder and htlc.expiry > self.block_time:
                    continue
                if not self.include_invalid and not self.is_funder and htlc.preimage_hash not in self.secrets:
                    continue
                if htlc.amount > DUST_LIMIT:
                    self.vin.append( CTxIn(outpoint = COutPoint(spend_tx.sha256, input_index), scriptSig = b"", nSequence=0xfffffffe) )
                    input_index += 1

        self.wit.vtxinwit = []
        #   add the p2wpkh witness scripts to spend the settled channel amounts
        input_index = 0
        for amount_index in range(len(settled_amounts)) :
            if settled_amounts[amount_index] > DUST_LIMIT:
                # add input witness from signer
                if amount_index is signer_index:
                    pubkey = keys.GetPaymentPk(node.watch_wallet)
                    witness_program = get_p2pkh_script(pubkey=pubkey)
                    amount = settled_amounts[amount_index]
                    # sig = self.Sign(keys=keys, htlc_index=-1, input_index=input_index)
                    tx_hash = SegwitVersion1SignatureHash(witness_program, self, input_index, SIGHASH_SINGLE, amount)
                    sig = keys.GetPaymentSignature(node.wallet, tx_hash, SIGHASH_SINGLE)
                    self.wit.vtxinwit.append(CTxInWitness())
                    self.wit.vtxinwit[-1].scriptWitness = CScriptWitness()
                    self.wit.vtxinwit[-1].scriptWitness.stack = [sig, pubkey]
                    input_index += 1

        if not settled_only:
            #   add the p2wsh witness scripts to spend the settled channel amounts
            for htlc_hash, htlc in self.payment_channel.offered_payments.items():
                    if not self.include_invalid and self.is_funder and htlc.expiry > self.block_time:
                        continue
                    if not self.include_invalid and not self.is_funder and htlc.preimage_hash not in self.secrets:
                        continue
                    if  htlc.amount > DUST_LIMIT:
                        #   generate signature for current state 
                        refund_pubkey = self.payment_channel.witness.GetPaymentPk(node.watch_wallet)
                        payment_pubkey = self.payment_channel.other_witness.GetPaymentPk(node.watch_wallet)
                        witness_program = get_eltoo_htlc_script(refund_pubkey, payment_pubkey, htlc.preimage_hash, htlc.expiry)
                        amount = htlc.amount
                        # sig = self.Sign(keys=keys, htlc_index=htlc_index, input_index=input_index)
                        tx_hash = SegwitVersion1SignatureHash(witness_program, self, input_index, SIGHASH_SINGLE, amount)
                        sig = keys.GetPaymentSignature(node.wallet, tx_hash, SIGHASH_SINGLE)
                        self.wit.vtxinwit.append(CTxInWitness())
                        if self.is_funder:
                            preimage = None
                        else:
                            preimage = self.secrets[htlc.preimage_hash]
                        self.wit.vtxinwit[-1].scriptWitness = get_eltoo_htlc_script_witness(witness_program, preimage, sig)
                        witness_hash = sha256(witness_program)
                        script_wsh = CScript([OP_0, witness_hash])
                        input_index += 1

class CloseTx(CTransaction):
    __slots__ = ("payment_channel", "setup_tx")

    def __init__(self, node, channel_partner, setup_tx):
        super().__init__(tx=None)

        payment_channel=node.payment_channels[channel_partner]
        self.payment_channel = copy.deepcopy(payment_channel)
        self.setup_tx = setup_tx

        for htlc_hash, htlc in self.payment_channel.offered_payments.items():
            # assume payer sweeps all unfulfilled HTLCs
            self.payment_channel.refund_amount += htlc.amount

        # sanity check
        assert self.payment_channel.settled_refund_amount + self.payment_channel.settled_payment_amount == CHANNEL_AMOUNT
        self.payment_channel.offered_payments.clear()
        
        # remove transaction fee from output amounts
        if self.payment_channel.settled_refund_amount > self.payment_channel.settled_payment_amount:
            self.payment_channel.settled_payment_amount -= min(int(FEE_AMOUNT/2), self.payment_channel.settled_payment_amount)
            self.payment_channel.settled_refund_amount = CHANNEL_AMOUNT - self.payment_channel.settled_payment_amount - FEE_AMOUNT
        else:
            self.payment_channel.settled_refund_amount -= min(int(FEE_AMOUNT/2), self.payment_channel.settled_refund_amount)
            self.payment_channel.settled_payment_amount = CHANNEL_AMOUNT - self.payment_channel.settled_refund_amount - FEE_AMOUNT
        assert self.payment_channel.settled_refund_amount + self.payment_channel.settled_payment_amount + FEE_AMOUNT == CHANNEL_AMOUNT

        # no csv outputs, so nVersion can be 1 or 2
        self.nVersion = 2

        # refund outputs to channel partners immediately
        self.nLockTime = CLTV_START_TIME + self.payment_channel.state+1   

        # add setup_tx vin
        self.vin = [ CTxIn(outpoint = COutPoint(setup_tx.sha256, 0), scriptSig = b"", nSequence=0xFFFFFFFE) ]

        #   build witness program for settled refund output (p2wpkh)
        pubkey = self.payment_channel.witness.GetPaymentPk(node.watch_wallet)
        script_pkh = CScript([OP_0, hash160(pubkey)])

        outputs = []

        #   refund output
        if self.payment_channel.settled_refund_amount > DUST_LIMIT:
            outputs.append( CTxOut(self.payment_channel.settled_refund_amount, script_pkh) )

        #   build witness program for settled payment output (p2wpkh)
        pubkey = self.payment_channel.other_witness.GetPaymentPk(node.watch_wallet)
        script_pkh = CScript([OP_0, hash160(pubkey)])

        #   settled output
        if self.payment_channel.settled_payment_amount > DUST_LIMIT:
            outputs.append( CTxOut(self.payment_channel.settled_payment_amount, script_pkh) )

        self.vout = outputs

    def IsChannelFunder(self, node, keys):
        pubkey = keys.GetUpdatePk(node.watch_wallet)
        if pubkey == self.payment_channel.witness.GetUpdatePk(node.watch_wallet):
            return True
        else:
            return False

    def Sign(self, node, channel_partner, setup_tx):
        
        # spending from a SetupTx (first UpdateTx) should not use the NOINPUT sighash 

        keys = node.keychain[channel_partner]

        witness_program = get_eltoo_update_script(node, setup_tx.state, setup_tx.witness, setup_tx.other_witness)
        tx_hash = SegwitVersion1SignatureHash(witness_program, self, 0, SIGHASH_SINGLE, CHANNEL_AMOUNT)
        signature = keys.GetUpdateSignature(node.wallet, tx_hash, SIGHASH_SINGLE)

        if self.IsChannelFunder(node, keys):
            self.payment_channel.witness.update_sig = signature
        else:
            self.payment_channel.other_witness.update_sig = signature

        return signature

    def Verify(self, node, setup_tx):
        verified = True
        witnesses = [ self.payment_channel.witness, self.payment_channel.other_witness ]

        for witness in witnesses:
            pk = ECPubKey()
            pk.set( witness.GetUpdatePk(node.watch_wallet) )
            sig = witness.update_sig[0:-1]
            sighash = witness.update_sig[-1]
            assert(sighash == (SIGHASH_SINGLE))
            witness_program = get_eltoo_update_script(node, setup_tx.state, setup_tx.witness, setup_tx.other_witness)
            tx_hash = SegwitVersion1SignatureHash(witness_program, self, 0, sighash, CHANNEL_AMOUNT)
            v = pk.verify_ecdsa( sig, tx_hash )
            verified = verified and pk.verify_ecdsa( sig, tx_hash )
        
        return verified

    def AddWitness(self, node, spend_tx):
        # witness script to spend update tx to close tx
        self.wit.vtxinwit = [ CTxInWitness() ]
        witness_program = get_eltoo_update_script(node, spend_tx.state, spend_tx.witness, spend_tx.other_witness)
        sig1 = self.payment_channel.witness.update_sig
        sig2 = self.payment_channel.other_witness.update_sig
        self.wit.vtxinwit[0].scriptWitness = CScriptWitness()
        self.wit.vtxinwit[0].scriptWitness.stack = [b'', sig1, sig2, witness_program]

class L2Node:
    __slots__ = "gid","issued_invoices", "secrets", "payment_channels", "keychain", "complete_payment_channels", "node", "wallet", "watch_wallet"

    def __init__(self, gid, node):
        self.gid = gid
        self.issued_invoices = []
        self.secrets = {}
        self.payment_channels = {}
        self.keychain = {}
        self.complete_payment_channels = {}
        self.node = node

        wallet_list = node.listwallets()
        if not str(self.gid) in wallet_list:
            # create a HD wallet for generating private keys
            self.node.createwallet(wallet_name=str(self.gid), disable_private_keys=False)
        self.wallet = self.node.get_wallet_rpc(str(self.gid))

        if not str(self.gid)+"_watch" in wallet_list:
            # create a HD watch wallet for generating public keys from us and our channel partners
            self.node.createwallet(wallet_name=str(self.gid)+"_watch", disable_private_keys=True)
        self.watch_wallet = self.node.get_wallet_rpc(str(self.gid)+"_watch")

    def __hash__(self):
        return hash(self.gid)

    def __eq__(self, other):
        return (self.gid == other.gid)

    def __ne__(self, other):
        # Not strictly necessary, but to avoid having both x==y and x!=y
        # True at the same time
        return not(self == other)

    def IsChannelFunder(self, channel_partner):
        pubkey = self.keychain[channel_partner].GetUpdatePk(self.watch_wallet)
        if pubkey == self.payment_channels[channel_partner].witness.GetUpdatePk(self.watch_wallet):
            return True
        else:
            return False

    def ProposeChannel(self):
        keys = Keys()
        witness = Witness(keys)

        return (keys, witness)

    def JoinChannel(self, channel_partner, witness):
        # generate local keys for proposed channel
        self.keychain[channel_partner] = Keys()
        other_witness = Witness(self.keychain[channel_partner])
        
        # initialize a new payment channel
        self.payment_channels[channel_partner] = PaymentChannel(witness, other_witness)

        # no need to sign an Update Tx transaction, only need to sign a SettleTx that refunds the first Setup Tx

        # sign settle transaction
        assert self.payment_channels[channel_partner].state == 0
        settle_tx = SettleTx(self, channel_partner)
        self.payment_channels[channel_partner].other_witness.settle_sig = \
            settle_tx.Sign(self, channel_partner)

        # create the first Update Tx (aka Setup Tx)
        self.payment_channels[channel_partner].spending_tx = UpdateTx(self, channel_partner)

        # return witness updated with valid signatures for the refund settle transaction
        return self.payment_channels[channel_partner].other_witness

    def CreateChannel(self, channel_partner, keys, witness, other_witness):
        # use keys created for this payment channel by ProposeChannel
        self.keychain[channel_partner] = keys

        # initialize a new payment channel
        self.payment_channels[channel_partner] = PaymentChannel(witness, other_witness)
        assert len(self.keychain) == len(self.payment_channels)

        # no need to sign an Update Tx transaction, only need to sign a SettleTx that refunds the first Setup Tx

        # sign settle transaction
        assert self.payment_channels[channel_partner].state == 0
        settle_tx = SettleTx(self, channel_partner)
        signature = settle_tx.Sign(self, channel_partner)

        # save signature to payment channel and settle tx
        self.payment_channels[channel_partner].witness.settle_sig = signature
        settle_tx.payment_channel.witness.settle_sig = signature

        # check that we can create a valid refund/settle transaction to use if we need to close the channel
        assert(settle_tx.Verify(self))

        # create the first Update Tx (aka Setup Tx)
        setup_tx = UpdateTx(self, channel_partner)

        # save the most recent co-signed payment_channel state that can be used to uncooperatively close the channel
        self.complete_payment_channels[channel_partner] = (copy.deepcopy(self.payment_channels[channel_partner]), copy.deepcopy(self.keychain[channel_partner]))

        return setup_tx, settle_tx

    def CreateInvoice(self, id, amount, expiry):
        secret = random.randrange(0, RANDOM_RANGE).to_bytes(32, 'big')
        self.secrets[hash160(secret)] = secret
        invoice = Invoice(id=id, preimage_hash=hash160(secret), amount=amount, expiry=expiry)
        return invoice

    def LearnSecret(self, secret):
        self.secrets[hash160(secret)] = secret

    def ProposePayment(self, channel_partner, invoice, prev_update_tx):

        # create updated payment channel information for the next proposed payment channel state
        payment_channel = self.payment_channels[channel_partner]
        payment_channel.state += 1
        payment_channel.settled_refund_amount -= invoice.amount
        payment_channel.offered_payments[invoice.preimage_hash] = invoice

        # save updated payment channel state
        self.payment_channels[channel_partner] = payment_channel
        
        # create an update tx that spends any update tx with an earlier state
        update_tx = UpdateTx(self, channel_partner)

        # sign with new update key
        update_sig = update_tx.Sign(self, channel_partner)
        update_tx.witness.update_sig = update_sig

        # create a settle tx that spends the new update tx
        settle_tx = SettleTx(self, channel_partner)

        # sign with new update key for this state
        settle_sig = settle_tx.Sign(self, channel_partner)
        settle_tx.payment_channel.witness.settle_sig = settle_sig

        return (update_tx, settle_tx)

    def ReceivePayment(self, channel_partner, update_tx, settle_tx):

        # check that new payment channel state passes sanity checks
        payment_channel = settle_tx.payment_channel
        assert payment_channel.witness == update_tx.witness
        assert payment_channel.other_witness == update_tx.other_witness
        assert payment_channel.state == update_tx.state
        assert payment_channel.state > self.payment_channels[channel_partner].state
        assert payment_channel.settled_refund_amount + payment_channel.settled_payment_amount + payment_channel.TotalOfferedPayments() - CHANNEL_AMOUNT == 0
        assert payment_channel.settled_payment_amount >= self.payment_channels[channel_partner].settled_payment_amount
        assert payment_channel.TotalOfferedPayments() > self.payment_channels[channel_partner].TotalOfferedPayments()

        # sign update tx with my key
        update_sig = update_tx.Sign(self, channel_partner)
        update_tx.other_witness.update_sig = update_sig

        # sign settle tx with new settle key
        settle_sig = settle_tx.Sign(self, channel_partner)
        settle_tx.payment_channel.other_witness.settle_sig = settle_sig

        # verify both channel partners signed the txs
        assert update_tx.Verify(self)
        assert settle_tx.Verify(self)

        # accept new channl state
        self.payment_channels[channel_partner] = payment_channel

        # check if we know the secret
        found_htlc = None
        secret = None
        for hashed_secret, tmp_secret in self.secrets.items():
            found_htlc = payment_channel.offered_payments.get(hashed_secret, None)
            if found_htlc != None:
                secret = tmp_secret
                break

        return update_tx, settle_tx, secret

    def UncooperativelyClose(self, channel_partner, settle_tx, settled_only=False, include_invalid=True, block_time=0):
        
        # create an redeem tx that spends a commited settle tx
        is_funder = self.IsChannelFunder(channel_partner)
        redeem_tx = RedeemTx(node=self, payment_channel=settle_tx.payment_channel, secrets=self.secrets, is_funder=is_funder, settled_only=settled_only, include_invalid=include_invalid, block_time=block_time)
        redeem_tx.AddWitness(node=self, channel_partner=channel_partner, spend_tx=settle_tx, settled_only=settled_only)

        return redeem_tx

    def ProposeUpdate(self, channel_partner, block_time):
        # payment receiver creates new update tx and settle tx with new settled balances based on invoices that can be redeemed or expired
        assert not self.IsChannelFunder(channel_partner)

        # most recent co-signed payment_channel state that can be used to uncooperatively close the channel
        self.complete_payment_channels[channel_partner] = (copy.deepcopy(self.payment_channels[channel_partner]), copy.deepcopy(self.keychain[channel_partner]))

        redeemed_secrets = {}
        removed_invoices = []
        for htlc_hash, invoice in self.payment_channels[channel_partner].offered_payments.items():
            if invoice.expiry < block_time:
                # remove expired invoices, credit back as settled refund
                removed_invoices.append(htlc_hash)
                self.payment_channels[channel_partner].settled_refund_amount += invoice.amount
            elif self.secrets.get(htlc_hash, None) != None:
                # remove redeemed invoices, credit as settled payments
                removed_invoices.append(htlc_hash)
                redeemed_secrets[htlc_hash] = self.secrets.get(htlc_hash)
                self.payment_channels[channel_partner].settled_payment_amount += invoice.amount

        for htlc_hash in removed_invoices:
            self.payment_channels[channel_partner].offered_payments.pop(htlc_hash, None)

        # create updated payment channel information for the next proposed payment channel state
        self.payment_channels[channel_partner].state += 1

        # create an update tx that spends any update tx with an earlier state
        update_tx = UpdateTx(self, channel_partner)

        # sign with new update keys
        update_sig = update_tx.Sign(self, channel_partner)
        update_tx.other_witness.update_sig = update_sig

        # create a settle tx that spends the new update tx
        settle_tx = SettleTx(self, channel_partner)

        # sign with new pending settle key for this state
        settle_sig = settle_tx.Sign(self, channel_partner)
        settle_tx.payment_channel.other_witness.settle_sig = settle_sig

        return update_tx, settle_tx, redeemed_secrets     

    def AcceptUpdate(self, channel_partner, update_tx, settle_tx, redeemed_secrets, block_time):
        # payment sender confirms the new update tx and settle tx with new settled balances based on invoices that can be redeemed or expired
        assert self.IsChannelFunder(channel_partner)
        
        updated_payment_channel = copy.deepcopy(self.payment_channels[channel_partner])
        updated_payment_channel.state += 1
        removed_invoices = []
        for htlc_hash, invoice in updated_payment_channel.offered_payments.items():
            if invoice.expiry < block_time:
                # remove expired invoices, credit back as settled refund
                removed_invoices.append(htlc_hash)
                updated_payment_channel.settled_refund_amount += invoice.amount
            elif redeemed_secrets.get(htlc_hash, None) != None:
                removed_invoices.append(htlc_hash)
                updated_payment_channel.settled_payment_amount += invoice.amount

        for htlc_hash in removed_invoices:
            updated_payment_channel.offered_payments.pop(htlc_hash, None)

        is_valid = updated_payment_channel.settled_payment_amount == settle_tx.payment_channel.settled_payment_amount
        is_valid &= updated_payment_channel.settled_refund_amount == settle_tx.payment_channel.settled_refund_amount
        is_valid &= updated_payment_channel.offered_payments == settle_tx.payment_channel.offered_payments

        if is_valid:
            self.payment_channels[channel_partner] = updated_payment_channel
                    
            # learn new secrets 
            for hashed_secret, secret in redeemed_secrets.items():
                self.LearnSecret(secret)

            # sign with update key
            update_sig = update_tx.Sign(self, channel_partner)
            update_tx.witness.update_sig = update_sig

            # sign with new settle key for this state
            settle_sig = settle_tx.Sign(self, channel_partner)
            settle_tx.payment_channel.witness.settle_sig = settle_sig
        else:
            return None, None

        return update_tx, settle_tx

    def ConfirmUpdate(self, channel_partner, update_tx, settle_tx):
        # payment receiver confirms the new update tx and settle tx with new settled balances was signed by payment sender
        assert not self.IsChannelFunder(channel_partner)

        # if both channel partners signed the new update tx and settle tx, then update to the new payment_channel state
        if update_tx.Verify(self) and settle_tx.Verify(self):
            return True
        else:
            # should now do a noncooperative close from the last completed state signed by the payer
            self.payment_channels[channel_partner], self.keychain[channel_partner] = copy.deepcopy(self.complete_payment_channels[channel_partner])
            return False

    def ProposeClose(self, channel_partner, setup_tx):
        # create an clase tx that spends a commited setup tx immediately with the settled balances
        close_tx = CloseTx(self, channel_partner, setup_tx=setup_tx)
        close_tx.Sign(self, channel_partner, setup_tx=setup_tx)
        return close_tx

    def AcceptClose(self, channel_partner, close_tx, setup_tx):
        # confirm settled amounts are as expected
        tmp_close_tx = CloseTx(self, channel_partner, setup_tx=setup_tx)
        is_valid = close_tx.payment_channel.settled_payment_amount == tmp_close_tx.payment_channel.settled_payment_amount
        is_valid &= close_tx.payment_channel.settled_refund_amount == tmp_close_tx.payment_channel.settled_refund_amount
        
        if is_valid:
            close_tx.Sign(self, channel_partner, setup_tx=setup_tx)
            if close_tx.Verify(self, setup_tx):
                # add witness information to close tx so it can be committed
                close_tx.AddWitness(self, setup_tx)
                return close_tx

        return None

class SimulateL2Tests(BitcoinTestFramework):

    def next_block(self, number, additional_coinbase_value=0, script=CScript([OP_TRUE]), solve=True, *, version=1):
        if self.tip is None:
            base_block_hash = self.genesis_hash
            block_time = int(self.start_time) + 1
        else:
            base_block_hash = self.tip.sha256
            block_time = self.tip.nTime + 1
        # First create the coinbase
        height = self.block_heights[base_block_hash] + 1
        coinbase = create_coinbase(height, self.coinbase_pubkey)
        coinbase.vout[0].nValue += additional_coinbase_value
        coinbase.rehash()
        block = create_block(base_block_hash, coinbase, block_time, version=version)
        if solve:
            block.solve()
        self.tip = block
        self.block_heights[block.sha256] = height
        assert number not in self.blocks
        self.blocks[number] = block
        return block

    def send_blocks(self, blocks, success=True, reject_reason=None, force_send=False, reconnect=False, timeout=60):
        """Sends blocks to test node. Syncs and verifies that tip has advanced to most recent block.

        Call with success = False if the tip shouldn't advance to the most recent block."""
        self.nodes[0].p2p.send_blocks_and_test(blocks, self.nodes[0], success=success, reject_reason=reject_reason, force_send=force_send, timeout=timeout, expect_disconnect=reconnect)

        if reconnect:
            self.reconnect_p2p(timeout=timeout)

    # save the current tip so it can be spent by a later block
    def save_spendable_output(self):
        self.log.debug("saving spendable output %s" % self.tip.vtx[0])
        self.spendable_outputs.append(self.tip)

    # get an output that we previously marked as spendable
    def get_spendable_output(self):
        self.log.debug("getting spendable output %s" % self.spendable_outputs[0].vtx[0])
        return self.spendable_outputs.pop(0).vtx[0]

    def bootstrap_p2p(self, timeout=10):
        """Add a P2P connection to the node.

        Helper to connect and wait for version handshake."""
        self.nodes[0].add_p2p_connection(P2PDataStore())
        # We need to wait for the initial getheaders from the peer before we
        # start populating our blockstore. If we don't, then we may run ahead
        # to the next subtest before we receive the getheaders. We'd then send
        # an INV for the next block and receive two getheaders - one for the
        # IBD and one for the INV. We'd respond to both and could get
        # unexpectedly disconnected if the DoS score for that error is 50.
        self.nodes[0].p2p.wait_for_getheaders(timeout=timeout)

    def init_coinbase(self):
        self.bootstrap_p2p()  # Add one p2p connection to the node

        # TODO: use self.nodes[0].get_deterministic_priv_key and b58decode_chk instead of generating my own blocks!

        self.tip = None
        self.blocks = {}
        self.block_heights = {}
        self.spendable_outputs = []

        self.genesis_hash = int(self.nodes[0].getbestblockhash(), 16)
        self.block_heights[self.genesis_hash] = 0

        self.coinbase_key = ECKey()
        self.coinbase_key.generate()
        self.coinbase_pubkey = self.coinbase_key.get_pubkey().get_bytes()

        # set initial blocktime to current time
        self.start_time = int(1500000000)# int(time.time())
        self.nodes[0].setmocktime=(self.start_time)

        # generate mature coinbase to spend
        NUM_BUFFER_BLOCKS_TO_GENERATE = 110
        for i in range(NUM_BUFFER_BLOCKS_TO_GENERATE):
            bn = self.next_block(i)
            self.save_spendable_output()
            self.send_blocks([bn])

        blockheight = self.nodes[0].getblockheader(blockhash=self.nodes[0].getbestblockhash())['height']

        # collect spendable outputs now to avoid cluttering the code later on
        self.coinbase_utxo = []
        for i in range(NUM_OUTPUTS_TO_COLLECT):
            self.coinbase_utxo.append(self.get_spendable_output())
        self.coinbase_index = 0

        self.nodes[0].generate(33)

    def fund(self, fee_funder, tx, spend_tx, amount):
        assert self.coinbase_index < NUM_OUTPUTS_TO_COLLECT
        assert amount >= FEE_AMOUNT

        fund_tx = self.coinbase_utxo[self.coinbase_index]
        assert fund_tx != None
        self.coinbase_index+=1
        fund_key = self.coinbase_key
        outIdx = 0

        #   update vin and witness to spend a specific update tx (skipped for setup tx)
        if spend_tx != None:
            tx.AddWitness(fee_funder, spend_tx)

        #   pay change to new p2pkh output, TODO: should use p2wpkh
        change_key = ECKey()
        change_key.generate()
        change_pubkey = change_key.get_pubkey().get_bytes()
        change_script_pkh = CScript([OP_0, hash160(change_pubkey)])
        change_amount = fund_tx.vout[0].nValue - amount

        #   add new funding input and change output
        tx.vin.append(CTxIn(COutPoint(fund_tx.sha256, 0), b""))
        tx.vout.append(CTxOut(change_amount, change_script_pkh))

        #   pay fee from spend_tx w/change output (assumed to be last txin)
        inIdx = len(tx.vin)-1
        
        #   sign the tx fee input w/change output
        scriptPubKey = bytearray(fund_tx.vout[outIdx].scriptPubKey)
        (sighash, err) = SignatureHash(fund_tx.vout[0].scriptPubKey, tx, inIdx, SIGHASH_ALL)
        sig = fund_key.sign_ecdsa(sighash) + bytes(bytearray([SIGHASH_ALL]))
        tx.vin[inIdx].scriptSig = CScript([sig])

        #   update the hash of this transaction
        tx.rehash()

        return (change_key, change_amount)

    def commit(self, tx, error_code=None, error_message=None):
        #   update hash
        tx.rehash()

        #   confirm it is in the mempool
        tx_hex = ToHex(tx)
        if error_code is None or error_message is None:
            txid = self.nodes[0].sendrawtransaction(tx_hex)
        else:
            txid = assert_raises_rpc_error(error_code, error_message, self.nodes[0].sendrawtransaction, tx_hex)
        return txid
            
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def test1(self, payer_sweeps_utxo):
        # topology: node1 opens a channel with node 2
        A = L2Node(gid=1, node=self.nodes[0])
        B = L2Node(gid=2, node=self.nodes[0])

        # create the set of keys needed to open a new payment channel
        keys, witness = A.ProposeChannel()

        # create a new channel and sign the initial refund of a new payment channel
        other_witness = B.JoinChannel(channel_partner=A, witness=witness)

        # create a new channel
        setup_tx, refund_tx = A.CreateChannel(channel_partner=B, keys=keys, witness=witness, other_witness=other_witness)

        # fund and commit the setup tx to create the new channel
        self.fund(A, tx=setup_tx, spend_tx=None, amount=CHANNEL_AMOUNT+FEE_AMOUNT)
        txid = self.commit(setup_tx)

        # mine the setup tx into a new block
        self.nodes[0].setmocktime=(self.start_time)
        self.nodes[0].generate(1)

        # A tries to commit the refund tx before the CSV delay has expired
        self.fund(A, tx=refund_tx, spend_tx=setup_tx, amount=FEE_AMOUNT)
        txid = self.commit(refund_tx, error_code=-26, error_message="non-BIP68-final")

        # B creates first invoice
        invoice = B.CreateInvoice('test1a', amount=10000, expiry=self.start_time + INVOICE_TIMEOUT)

        # A creates partially signed transactions to pay the invoice from B
        update1_tx, settle1_tx = A.ProposePayment(B, invoice, setup_tx)

        # B receives payment from A and returns corresponding secret and fully signed transactions
        update1_tx, settle1_tx, secret = B.ReceivePayment(A, update1_tx, settle1_tx)

        # mine the setup tx into a new block, increment time by 10 minutes
        self.nodes[0].generate(1)

        # B creates second invoice
        invoice = B.CreateInvoice('test1b', amount=10000, expiry=self.start_time + INVOICE_TIMEOUT + BLOCK_TIME)

        # A creates a new partially signed transactions with higher state to pay the second invoice from B
        update2_tx, settle2_tx = A.ProposePayment(B, invoice, setup_tx)

        # B receives payment from A and returns corresponding secret and fully signed transactions
        update2_tx, settle2_tx, secret = B.ReceivePayment(A, update2_tx, settle2_tx)

        # fund the transaction fees for the update tx before committing it
        self.fund(A, tx=update2_tx, spend_tx=setup_tx, amount=FEE_AMOUNT)

        # B commits the update tx to start the uncooperative close of the channel
        txid = self.commit(update2_tx)

        # fund the transaction fees for the settle tx before committing it
        self.fund(A, tx=settle2_tx, spend_tx=update2_tx, amount=FEE_AMOUNT)

        # B tries to commits the settle tx before the CSV timeout
        txid = self.commit(settle2_tx, error_code=-26, error_message="non-BIP68-final")

        # A tries to commit an update tx that spends the commited update to an earlier state (encoded by nLocktime)
        self.fund(A, tx=update1_tx, spend_tx=update2_tx, amount=FEE_AMOUNT)
        txid = self.commit(update1_tx, error_code=-26, error_message="non-mandatory-script-verify-flag") # Locktime requirement not satisfied

        # mine the update tx into a new block, and advance blocks until settle tx can be spent
        self.nodes[0].generate(CSV_DELAY+1)

        # A or B commits the settle tx to finalize the uncooperative close of the channel after the CSV timeout
        txid = self.commit(settle2_tx)

        if payer_sweeps_utxo:
            # A collects the settled amount and tries to sweep even invalid/unexpired htlcs
            redeem_tx = A.UncooperativelyClose(B, settle2_tx, include_invalid=True, block_time=self.start_time + INVOICE_TIMEOUT)

            # wait for invoice to expire
            self.nodes[0].setmocktime=(self.start_time + INVOICE_TIMEOUT)
            self.nodes[0].generate(1)

            # A attempts to commits the redeem tx to complete the uncooperative close of the channel before the invoice has timed out
            txid = self.commit(redeem_tx, error_code=-26, error_message="non-mandatory-script-verify-flag") #  (Locktime requirement not satisfied)

            # advance locktime on redeem tx to past expiry of the invoices
            redeem_tx = A.UncooperativelyClose(B, settle2_tx, include_invalid=False, block_time=self.start_time + INVOICE_TIMEOUT + BLOCK_TIME)

            # wait for invoice to expire
            self.nodes[0].setmocktime=(self.start_time + INVOICE_TIMEOUT + BLOCK_TIME+1)
            self.nodes[0].generate(10)

            # A commits the redeem tx to complete the uncooperative close of the channel and sweep the htlc
            txid = self.commit(redeem_tx)
            
        else:
            # B collects the settled amount and uses the secret to sweep an unsettled htlc
            redeem_tx = B.UncooperativelyClose(A, settle2_tx)

            # B commits the redeem tx to complete the uncooperative close of the channel
            txid = self.commit(redeem_tx)

            # A collects the settled amount, and has no unsettled htlcs to collect
            redeem_tx = A.UncooperativelyClose(B, settle2_tx, settled_only=True)

            # A commits the redeem tx to complete the uncooperative close of the channel
            txid = self.commit(redeem_tx)

    def test2(self):

        # topology: node1 opens a channel with node 2
        A = L2Node(1, node=self.nodes[0])
        B = L2Node(2, node=self.nodes[0])
        C = L2Node(3, node=self.nodes[0])

        keys = {}
        witness = {}
        other_witness = {}
        setup_tx = {}
        refund_tx = {}

        '-------------------------'

        # create the set of keys needed to open a new payment channel
        keys[A], witness[A] = A.ProposeChannel()

        # create a new channel and sign the initial refund of a new payment channel
        other_witness[B] = B.JoinChannel(channel_partner=A, witness=witness[A])

        # create a new channel
        setup_tx[A], refund_tx[A] = A.CreateChannel(channel_partner=B, keys=keys[A], witness=witness[A], other_witness=other_witness[B])

        # fund and commit the setup tx to create the new channel
        self.fund(A, tx=setup_tx[A], spend_tx=None, amount=CHANNEL_AMOUNT+FEE_AMOUNT)
        txid = self.commit(setup_tx[A])

        '-------------------------'

        # create the set of keys needed to open a new payment channel
        keys[B], witness[B] = B.ProposeChannel()

        # create a new channel and sign the initial refund of a new payment channel
        other_witness[C] = C.JoinChannel(channel_partner=B, witness=witness[B])

        # create a new channel
        setup_tx[B], refund_tx[B] = B.CreateChannel(channel_partner=C, keys=keys[B], witness=witness[B], other_witness=other_witness[C])

        # fund and commit the setup tx to create the new channel
        self.fund(A, tx=setup_tx[B], spend_tx=None, amount=CHANNEL_AMOUNT+FEE_AMOUNT)
        txid = self.commit(setup_tx[B])

        # mine the setup tx into a new block
        self.nodes[0].generate(1)
        '-------------------------'

        invoice = {}

        # A offers to pay B the amount C requested in exchange for the secret that proves C has been paid
        invoice[A] = C.CreateInvoice('test2', amount=5000, expiry=self.start_time + INVOICE_TIMEOUT)

        # B offers to pay C the amount A offers (less relay fee) in exchange for the secret that proves that C has been paid
        invoice[B] = invoice[A]
        invoice[B].amount -= RELAY_FEE
        '-------------------------'

        update_tx = {}
        settle_tx = {}
        redeem_tx = {}
        other_settle_key = {}
        secret = {}

        # A creates partially signed transactions for B to pay the invoice from C
        update_tx[A], settle_tx[A] = A.ProposePayment(B, invoice[A], setup_tx[A])

        # B receives a payment commitment from A and returns the corresponding signed transactions, but not the secret needed to redeem the payment
        update_tx[B], settle_tx[B], secret[B] = B.ReceivePayment(A, update_tx[A], settle_tx[A])
        assert secret[B] == None

        # B creates partially signed transactions to pay the invoice from C
        tmp_update_tx, tmp_settle_tx = B.ProposePayment(C, invoice[B], setup_tx[B])

        # C receives a payment commitment from B and returns the corresponding fully signed transactions and secret needed to redeem the payment
        update_tx[C], settle_tx[C], secret[C] = C.ReceivePayment(B, tmp_update_tx, tmp_settle_tx)
        assert secret[C] != None

        # fund the transaction fees for the update tx before committing it
        self.fund(A, tx=update_tx[B], spend_tx=setup_tx[A], amount=FEE_AMOUNT)

        # B commits the update tx to start the uncooperative close of the channel
        txid = self.commit(update_tx[B])

        # fund the transaction fees for the update tx before committing it 

        # mine the update tx into a new block, and advance blocks until settle tx can be spent
        self.nodes[0].generate(CSV_DELAY+10)
        '-------------------------'

        # fund the transaction fees for the settle tx before committing it
        self.fund(A, tx=settle_tx[B], spend_tx=update_tx[B], amount=FEE_AMOUNT)

        # B commits the settle tx to finalize the uncooperative close of the channel 
        txid = self.commit(settle_tx[B])
        '-------------------------'

        # B associates the wrong preimage secret with the preimage hash
        B.secrets[invoice[B].preimage_hash] = b''

        # B tries to collect the settled htlc amount without the correct secret
        redeem_tx[B] = B.UncooperativelyClose(A, settle_tx[B], settled_only=False, include_invalid=True, block_time=self.start_time + INVOICE_TIMEOUT)

        # B commits the redeem tx to complete the uncooperative close of the channel and collect settled and confirmed utxos (less transaction fees)
        txid = self.commit(redeem_tx[B], error_code=-26, error_message="non-mandatory-script-verify-flag")

        # B learns the secret from C
        assert hash160(secret[C]) == invoice[B].preimage_hash
        B.LearnSecret(secret[C])
        '-------------------------'

        # B collects the settled amount and uses the secret to sweep an unsettled htlc
        redeem_tx[B] = B.UncooperativelyClose(A, settle_tx[B])

        # B commits the redeem tx to complete the uncooperative close of the channel and collect settled and confirmed utxos (less transaction fees)
        txid = self.commit(redeem_tx[B])

        # A collects the settled amount, and has no unsettled htlcs to collect
        redeem_tx[A] = A.UncooperativelyClose(B, settle_tx[B], settled_only=True, include_invalid=True, block_time=self.start_time + INVOICE_TIMEOUT)

        # A commits the redeem tx to complete the uncooperative close of the channel
        txid = self.commit(redeem_tx[A])

    def uncooperative_close(self, fee_funder, payment_sender, payment_receiver, spend_tx, update_tx, settle_tx, block_time):
        # do an uncooperative close using secrets to settle htlcs directly on the blockchain with last signed payment from B

        # fund the transaction fees for the update tx before committing it
        self.fund(fee_funder, tx=update_tx, spend_tx=spend_tx, amount=FEE_AMOUNT)

        # either side commits a signed update tx to start the uncooperative close of the channel
        txid = self.commit(update_tx)

        # mine the update tx into a new block, and advance blocks until settle tx can be spent
        self.nodes[0].setmocktime=(block_time)
        self.nodes[0].generate(CSV_DELAY+10)
        '-------------------------'

        # fund the transaction fees for the settle tx before committing it
        self.fund(fee_funder, tx=settle_tx, spend_tx=update_tx, amount=FEE_AMOUNT)

        # either side commits a signed settle tx to finalize the uncooperative close of the channel 
        txid = self.commit(settle_tx)
        '-------------------------'

        # payment receiver collects their settled payments and uses their secrets to sweep any unsettled htlcs
        redeem_tx = payment_receiver.UncooperativelyClose(payment_sender, settle_tx)

        # payment receiver commits the redeem tx to complete the uncooperative close of the channel and collect settled and confirmed utxos (less transaction fees)
        txid = self.commit(redeem_tx)

        # payment sender collects the settled refund amount, and any unsettled htlcs that have expired
        redeem_tx = payment_sender.UncooperativelyClose(payment_receiver, settle_tx, settled_only=False, include_invalid=False, block_time=block_time + INVOICE_TIMEOUT)

        # A commits the redeem tx to complete the uncooperative close of the channel
        self.nodes[0].setmocktime=(block_time + INVOICE_TIMEOUT)
        txid = self.commit(redeem_tx)

        return block_time

    def test3(self):

        block_time = self.start_time

        # topology: node1 opens a channel with node 2
        A = L2Node(1, self.nodes[0])
        B = L2Node(2, self.nodes[0])
        C = L2Node(3, self.nodes[0])

        keys = {}
        witness = {}
        other_witness = {}
        setup_tx = {}
        refund_tx = {}
        '-------------------------'

        # create the set of keys needed to open a new payment channel
        keys[A], witness[A] = A.ProposeChannel()

        # create a new channel and sign the initial refund of a new payment channel
        other_witness[B] = B.JoinChannel(channel_partner=A, witness=witness[A])

        # create a new channel
        setup_tx[A], refund_tx[A] = A.CreateChannel(channel_partner=B, keys=keys[A], witness=witness[A], other_witness=other_witness[B])

        # fund and commit the setup tx to create the new channel
        self.fund(A, tx=setup_tx[A], spend_tx=None, amount=CHANNEL_AMOUNT+FEE_AMOUNT)
        txid = self.commit(setup_tx[A])
        '-------------------------'

        # create the set of keys needed to open a new payment channel
        keys[B], witness[B] = B.ProposeChannel()

        # create a new channel and sign the initial refund of a new payment channel
        other_witness[C] = C.JoinChannel(channel_partner=B, witness=witness[B])

        # create a new channel
        setup_tx[B], refund_tx[B] = B.CreateChannel(channel_partner=C, keys=keys[B], witness=witness[B], other_witness=other_witness[C])

        # fund and commit the setup tx to create the new channel
        self.fund(A, tx=setup_tx[B], spend_tx=None, amount=CHANNEL_AMOUNT+FEE_AMOUNT)
        txid = self.commit(setup_tx[B])

        # mine the setup tx into a new block
        self.nodes[0].generate(1)
        '-------------------------'

        for loop in range(5):
            invoice = {}

            # A offers to pay B the amount C requested in exchange for the secret that proves C has been paid
            invoice[A] = C.CreateInvoice('test2', amount=5000, expiry= block_time + INVOICE_TIMEOUT)

            # B offers to pay C the amount A offers (less relay fee) in exchange for the secret that proves that C has been paid
            invoice[B] = invoice[A]
            invoice[B].amount -= RELAY_FEE
            '-------------------------'

            update1_tx = {}
            settle1_tx = {}
            update2_tx = {}
            settle2_tx = {}
            redeem_tx = {}
            secret = {}

            # A creates partially signed transactions for B to pay the invoice from C
            update1_tx[A], settle1_tx[A] = A.ProposePayment(B, invoice[A], setup_tx[A])

            # B receives a payment commitment from A and returns the corresponding signed transactions, but not the secret needed to redeem the payment
            update2_tx[B], settle2_tx[B], secret[B] = B.ReceivePayment(A, update1_tx[A], settle1_tx[A])
            assert secret[B] == None

            # B creates partially signed transactions to pay the invoice from C (less their relay fee)
            update1_tx[B], settle1_tx[B] = B.ProposePayment(C, invoice[B], setup_tx[B])

            # C receives a payment commitment from B and returns the corresponding fully signed transactions and secret needed to redeem the payment
            update2_tx[C], settle2_tx[C], secret[C] = C.ReceivePayment(B, update1_tx[B], settle1_tx[B])
            assert hash160(secret[C]) == invoice[B].preimage_hash

            # C proposes to B to update their settled balance instead of doing an uncooperative close
            tmp_update_tx, tmp_settle_tx, secrets = C.ProposeUpdate(B, block_time=block_time)
            
            # B accepts the secrets as proof of C's new settled payments balance
            tmp_update_tx, tmp_settle_tx = B.AcceptUpdate(C, tmp_update_tx, tmp_settle_tx, secrets, block_time)

            if C.ConfirmUpdate(B, tmp_update_tx, tmp_settle_tx):
                # after C confirms that B signed the new update tx and settle tx, C does not need to uncooperatively close the channel
                update2_tx[C] = tmp_update_tx
                settle2_tx[C] = tmp_settle_tx
                block_time += 1

            else:
                # assumes atleast one payment succeeded
                assert update2_tx.get(C) != None and settle2_tx(C) != None

                # otherwise, C can uncooperatively close the channel from the last signed state
                block_time = self.uncooperative_close(A, B, C, setup_tx[B], update2_tx[C], settle2_tx[C], block_time)

            # B proposes to A to update their settled balance instead of doing an uncooperative close
            tmp_update_tx, tmp_settle_tx, secrets = B.ProposeUpdate(A, block_time=block_time)
            
            # A accepts the secrets as proof of B's new settled payments balance
            tmp_update_tx, tmp_settle_tx = A.AcceptUpdate(B, tmp_update_tx, tmp_settle_tx, secrets, block_time)

            if B.ConfirmUpdate(A, tmp_update_tx, tmp_settle_tx):
                # confirmed that A signed the new update tx and settle tx, no need to uncooperatively close the channel
                update2_tx[B] = tmp_update_tx
                settle2_tx[B] = tmp_settle_tx
                block_time += 1

            else:
                block_time = self.uncooperative_close(A, A, B, setup_tx[A], update2_tx[B], settle2_tx[B], block_time)
            
        close_tx = A.ProposeClose(B, setup_tx[A])
        close_tx = B.AcceptClose(A, close_tx, setup_tx[A])

        # if B does not sign and submit close_tx, then A should do an uncooperative close
        txid = self.commit(close_tx)

        close_tx = B.ProposeClose(C, setup_tx[B])
        close_tx = C.AcceptClose(B, close_tx, setup_tx[B])

        # if C does not sign and submit close_tx, then B should do an uncooperative close
        txid = self.commit(close_tx)

    def run_test(self):

        '''
        # test addresses from bip32.org 
        # - testnet: crazy horse battery staple
        # - Derivation Path: info:m (master)

        key = ECKey()
        key.generate()
        tprv, tpub = bip32_generate_hdaddresses(key, network="testnet")

        self.nodes[0].createwallet(wallet_name="mine", disable_private_keys=False)
        mine_wallet = self.nodes[0].get_wallet_rpc("mine") 

        self.nodes[0].createwallet(wallet_name="theirs", disable_private_keys=True)
        theirs_wallet = self.nodes[0].get_wallet_rpc("theirs")

        refund_pubkey  = bytes.fromhex(bip32_pubkey(mine_wallet, tprv, 0))
        payment_pubkey = bytes.fromhex(bip32_pubkey(theirs_wallet, tpub, 1))
        secret = random.randrange(0, RANDOM_RANGE).to_bytes(32, 'big')
        preimage_hash = hash160(secret)
        expiry = int(time.time()) + INVOICE_TIMEOUT
        state = 0

        witness_program = get_eltoo_htlc_script(refund_pubkey, payment_pubkey, preimage_hash, expiry)
        witness_hash = sha256(witness_program)
        update_script_wsh = CScript([OP_0, witness_hash])
        prevscript = CScript()
        #self.log.debug("add_settle_outputs: state=%s, signer_index=%d\n\twitness sha256(%s)=%s\n\twsh sha256(%s)=%s\n", state, signer_index, ToHex(witness_program),
        #    ToHex(witness_hash), ToHex(script_wsh), ToHex(sha256(script_wsh)))

        addr = mine_wallet.getnewaddress()
        block_hash = self.nodes[0].generatetoaddress(1, addr)[0]
        block = self.nodes[0].getblock(block_hash)
        txid = block['tx'][0]
        hex_tx = mine_wallet.gettransaction(txid)['hex']
        coinbase_tx = FromHex(CTransaction(), hex_tx)
        coinbase_tx.rehash()
        self.nodes[0].generate(100)
        amount = coinbase_tx.vout[0].nValue - FEE_AMOUNT

        #   fund tx -> update tx
        fund_tx = CTransaction()
        fund_tx.nVersion = 2
        fund_tx.nLockTime = CLTV_START_TIME + state
        fund_tx.vout = [ CTxOut(amount, update_script_wsh) ]
        fund_tx.vin = [ CTxIn(outpoint = COutPoint(coinbase_tx.sha256, 0), 
            scriptSig = b"", nSequence=0xFFFFFFFE) ]

        fund_tx_hash = SegwitVersion1SignatureHash(prevscript, fund_tx, 0, 
            SIGHASH_ALL, amount)
        # signature = keys.update_key.sign_ecdsa(tx_hash) + chr(SIGHASH_ALL).encode('latin-1')

        # sign and submit fund tx to transfer from coinbase tx output -> update tx output
        fund_tx.rehash()
        fund_tx_hex = ToHex(fund_tx)

        result = mine_wallet.signrawtransactionwithwallet(fund_tx_hex)
        txid_fund = self.nodes[0].sendrawtransaction(result['hex'])

        # sign and submit transaction from update tx -> p2pkh
        settle_pubkey = bytes.fromhex(bip32_pubkey(mine_wallet, tprv, 2))
        witness_program = get_p2pkh_script(settle_pubkey)
        witness_hash = sha256(witness_program)
        script_wsh = CScript([OP_0, witness_hash])
        
        # update state and amount
        state = state + 1
        amount = amount - FEE_AMOUNT

        #   settle tx
        update_tx = CTransaction()
        update_tx.nVersion = 2
        update_tx.nLockTime = CLTV_START_TIME + state
        update_tx.vout = [ CTxOut(amount, script_wsh) ]
        update_tx.vin = [ CTxIn(outpoint = COutPoint(fund_tx.sha256, 0), 
            scriptSig = b"", nSequence=0xFFFFFFFE) ]

        update_tx_hash = SegwitVersion1SignatureHash(prevscript, update_tx, 0, 
            SIGHASH_ANYPREVOUT | SIGHASH_SINGLE, amount)
        
        sig1 = bip32_sign(update_tx_hash, mine_wallet, tprv, 0)
        v = bip32_verify(sig1, update_tx_hash, mine_wallet, tprv, 0)

        sig2 = bip32_sign(update_tx_hash, mine_wallet, tprv, 1)
        v = bip32_verify(sig2, update_tx_hash, mine_wallet, tprv, 1)

        # sign and submit transaction from coinbase tx -> update tx
        # witness script to spend update tx to update tx
        update_tx.wit.vtxinwit = [ CTxInWitness() ]
        witness = Witness()
        witness.update_pk = bytes.fromhex(bip32_pubkey(mine_wallet, tprv, 0))
        witness.settle_pk = bytes.fromhex(bip32_pubkey(mine_wallet, tprv, 0))
        other_witness = Witness()
        other_witness.update_pk = bytes.fromhex(bip32_pubkey(mine_wallet, tprv, 0))
        other_witness.settle_pk = bytes.fromhex(bip32_pubkey(mine_wallet, tprv, 0))

        witness_program = get_eltoo_update_script(state, witness, other_witness)
        update_tx.wit.vtxinwit[0].scriptWitness = CScriptWitness()
        update_tx.wit.vtxinwit[0].scriptWitness.stack = [b'', sig1, sig2, witness_program]
        assert(len(self.vin) == 0)
        self.vin = [ CTxIn(outpoint = COutPoint(update_tx.sha256, 0), scriptSig = b"", nSequence=0xFFFFFFFE) ]

        update_txid = self.nodes[0].sendrawtransaction()
        '''

        # create some coinbase txs to spend
        self.init_coinbase()

        # test two nodes performing an uncooperative close with one htlc pending, tested cheats:
        # - payer tries to commit a refund tx before the CSV delay expires
        # - payer tries to commit spend an update tx to an update tx with an earlier state
        # - payer tries to redeem HTLC before invoice expires
        self.test1(payer_sweeps_utxo=True)

        # test two nodes performing an uncooperative close with one htlc pending, tested cheats:
        # - payee tries to settle last state before the CSV timeout
        # - payee tries to redeem HTLC with wrong secret
        self.test1(payer_sweeps_utxo=False)
        
        # test node A paying node C via node B, node B uses secret passed by C to uncooperatively close the channel with C
        # - test cheat of node A using old update
        # - test cheat of B replacing with a newer one
        self.test2()

        # test node A paying node C via node B, node B uses secret passed by C to cooperative update their channels
        # - test cooperative channel updating
        # - test cooperative channel closing
        self.test3()

if __name__ == '__main__':
    SimulateL2Tests().main()
