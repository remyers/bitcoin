#!/usr/bin/env python3
# Copyright (c) 2015-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Simulation tests for Vault covenant scheme using anyprevout
"""

from collections import OrderedDict
from io import BytesIO
import json
from test_framework.address import program_to_witness
from test_framework.blocktools import (
    create_block,
    create_coinbase
)
from test_framework.key import (
    compute_xonly_pubkey,
    generate_privkey,
    sign_schnorr,
    ECKey
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut
)
from test_framework.p2p import P2PDataStore
from test_framework.script import (
    hash160,
    taproot_construct,
    CScript,
    CScriptNum,
    KEY_VERSION_ANYPREVOUT,
    OP_0,
    OP_1,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIGVERIFY,
    OP_TRUE,
    SIGHASH_ALL,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
    SIGHASH_ANYPREVOUT,
    SIGHASH_ANYPREVOUTANYSCRIPT,
    LegacySignatureHash,
    TaprootSignatureHash
)

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_raises_rpc_error
)

import random

NUM_OUTPUTS_TO_COLLECT = 33
CSV_DELAY = 20
DUST_LIMIT = 600
FEE_AMOUNT = 1000
VAULT_AMOUNT = 1000000
RELAY_FEE = 100
BLOCK_TIME = 600  # 10 minutes
MIN_FEE = 50000
DEFAULT_NSEQUENCE = 0xFFFFFFFE  # disable nSequence lock

# vault taproot scripts
def get_spend_tapscript(pubkey, signature=None, key_ver=KEY_VERSION_ANYPREVOUT):
    # spend output
    sig_script = [] if signature is None else [signature]
    return CScript( sig_script +
     [
        OP_1,                                   # single byte 0x1 means the BIP-118 public key == taproot internal key
        OP_CHECKSIGVERIFY,
        bytes([key_ver])+pubkey,                # spending pubkey
        OP_CHECKSIGVERIFY,
        CScriptNum(CSV_DELAY),
        OP_CHECKSEQUENCEVERIFY                  # does nothing if nSequence of tx is later than (blocks) delay
    ])

def get_revault_tapscript(signature=None):
    # revault output
    sig_script = [] if signature is None else [signature]
    return CScript(sig_script +
    [
        OP_1,                                   # single byte 0x1 means the BIP-118 public key == taproot internal key
        OP_CHECKSIGVERIFY
    ])

# from bitcoinops util.py
def generate_and_send_coins(node, address, amount_sat):
    """Generate blocks on node and then send amount_sat to address.
    No change output is added to the transaction.
    Return a CTransaction object."""
    version = node.getnetworkinfo()['subversion']
    print("\nClient version is {}\n".format(version))

    # Generate 101 blocks and send reward to bech32 address
    reward_address = node.getnewaddress(address_type="bech32")
    node.generatetoaddress(101, reward_address)
    balance = node.getbalance()
    print("Balance: {}\n".format(balance))

    assert balance > 1

    unspent_txid = node.listunspent(1)[-1]["txid"]
    inputs = [{"txid": unspent_txid, "vout": 0}]

    # Create a raw transaction sending 1 BTC to the address, then sign and send it.
    # We won't create a change output, so maxfeerate must be set to 0
    # to allow any fee rate.
    tx_hex = node.createrawtransaction(inputs=inputs, outputs=[{address: amount_sat / 100_000_000}])

    res = node.signrawtransactionwithwallet(hexstring=tx_hex)

    tx_hex = res["hex"]
    assert res["complete"]
    assert 'errors' not in res

    txid = node.sendrawtransaction(hexstring=tx_hex, maxfeerate=0)

    tx_hex = node.getrawtransaction(txid)

    # Reconstruct wallet transaction locally
    tx = CTransaction()
    tx.deserialize(BytesIO(bytes.fromhex(tx_hex)))
    tx.rehash()

    return tx

# from bitcoinops util.py
def test_transaction(node, tx, error_message=None):
    tx_str = tx.serialize().hex()
    ret = node.testmempoolaccept(rawtxs=[tx_str], maxfeerate=0)[0]
    print(ret)
    if error_message is not None:
        assert ret['reject-reason'] == error_message
    return ret['allowed']

def get_vault_scripts(spend_pubkey, vault_signature=None):
    spend_script = get_spend_tapscript(spend_pubkey, vault_signature) 
    revault_script = get_revault_tapscript()
    scripts = [
        ("spend", spend_script), ("revault", revault_script)
    ]
    return scripts

def create_spend_tx(source_tx, inner_pubkey, spend_pubkey, amount_sat, vault_signature=None):
    # SPEND TX
    # nlocktime: 0
    # nsequence: CSV_DELAY
    # sighash=SINGLE | ANYPREVOUTANYSCRIPT
    spend_tx = CTransaction()
    spend_tx.nVersion = 2
    spend_tx.nLockTime = 0

    # Populate the transaction inputs
    source_tx.rehash()
    outpoint = COutPoint(int(source_tx.hash, 16), 0)
    spend_tx.vin = [CTxIn(outpoint=outpoint, nSequence=CSV_DELAY)]

    dest_tap = taproot_construct(inner_pubkey, get_vault_scripts(spend_pubkey, vault_signature))
    dest_output = CTxOut(nValue=amount_sat, scriptPubKey=bytes(dest_tap.scriptPubKey))
    spend_tx.vout = [dest_output]

    return spend_tx

def vault_sign_spend_tx(tx, funding_tx, privkey_vault, spend_pubkey, sighash_flag=SIGHASH_ANYPREVOUTANYSCRIPT, covenant=False):
    # Generate a Taproot signature hash to spend `nValue` from any previous output with any script (ignore prevout's scriptPubKey)
    sighash = TaprootSignatureHash(
        tx,
        [funding_tx.vout[0]],
        SIGHASH_SINGLE | sighash_flag,
        input_index=0,
        scriptpath=True,
        script=CScript(),
        key_ver=KEY_VERSION_ANYPREVOUT,
    )

    # Sign with internal private key of vault
    signature = sign_schnorr(privkey_vault, sighash) + bytes([SIGHASH_SINGLE | sighash_flag])
    vault_signature = signature if covenant is True else None

    # Generate vault taptree for tx, with signature in the script for a covenant
    pubkey_vault, _ = compute_xonly_pubkey(privkey_vault)
    spend_script = get_spend_tapscript(spend_pubkey, vault_signature)
    vault_taptree = taproot_construct(pubkey_vault, get_vault_scripts(spend_pubkey, vault_signature))

    # Control block created from leaf version and merkle branch information and common inner pubkey and it's negative flag
    spend_leaf = vault_taptree.leaves["spend"]
    spend_control_block = bytes([spend_leaf.version + vault_taptree.negflag]) + vault_taptree.internal_pubkey + spend_leaf.merklebranch

    # Add witness to transaction
    witness_elements = [spend_script, spend_control_block]
    tx.wit.vtxinwit.append(CTxInWitness())
    tx.wit.vtxinwit[0].scriptWitness.stack = witness_elements

    return signature

def spender_sign_spend_tx(tx, funding_tx, spend_privkey, sighash_flag=SIGHASH_ANYPREVOUTANYSCRIPT):
    
    # Generate a Taproot signature hash to spend `nValue` from any previous output with any script (ignore prevout's scriptPubKey)
    sighash = TaprootSignatureHash(
        tx,
        [funding_tx.vout[0]],
        SIGHASH_SINGLE | sighash_flag,
        input_index=0,
        scriptpath=True,
        script=CScript(),
        key_ver=KEY_VERSION_ANYPREVOUT,
    )

    # Sign with spending key
    spend_signature = sign_schnorr(spend_privkey, sighash) + bytes([SIGHASH_SINGLE | sighash_flag])

    # Add witness to transaction
    inputs = [spend_signature]
    tx.wit.vtxinwit[0].scriptWitness.stack = inputs + tx.wit.vtxinwit[0].scriptWitness.stack

    return spend_signature

def create_revault_tx(source_tx, inner_pubkey, vault_pubkey, spend_pubkey, amount_sat, vault_signature):
    # REVAULT TX
    # nlocktime: 0
    # nsequence: DEFAULT_NSEQUENCE
    # sighash=SINGLE | ANYPREVOUTANYSCRIPT
    revault_tx = CTransaction()
    revault_tx.nVersion = 2
    revault_tx.nLockTime = 0

    # Populate the transaction inputs   
    source_tx.rehash()
    outpoint = COutPoint(int(source_tx.hash, 16), 0)
    revault_tx.vin = [CTxIn(outpoint=outpoint, nSequence=DEFAULT_NSEQUENCE)]

    # create vault output
    dest_tap = taproot_construct(inner_pubkey, get_vault_scripts(spend_pubkey, vault_signature))
    dest_output = CTxOut(nValue=amount_sat, scriptPubKey=bytes(dest_tap.scriptPubKey))
    revault_tx.vout = [dest_output]

    # Generate vault taptree for tx, with signature in the script for a covenant
    spend_script = get_spend_tapscript(spend_pubkey, vault_signature)
    vault_taptree = taproot_construct(vault_pubkey, get_vault_scripts(spend_pubkey, vault_signature))

    # Control block created from leaf version and merkle branch information and common inner pubkey and it's negative flag
    spend_leaf = vault_taptree.leaves["revault"]
    spend_control_block = bytes([spend_leaf.version + vault_taptree.negflag]) + vault_taptree.internal_pubkey + spend_leaf.merklebranch

    # Add witness to transaction
    witness_elements = [spend_script, spend_control_block]
    revault_tx.wit.vtxinwit.append(CTxInWitness())
    revault_tx.wit.vtxinwit[0].scriptWitness.stack = witness_elements

    return revault_tx

class APOCovenantTests(BitcoinTestFramework):

    def next_block(self, number, spend=None, additional_coinbase_value=0, script=CScript([OP_TRUE]), solve=True, *, version=4):
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
        if spend is None:
            block = create_block(base_block_hash, coinbase, block_time, version=version)
        else:
            coinbase.vout[0].nValue += spend.vout[0].nValue - 1  # all but one satoshi to fees
            coinbase.rehash()
            block = create_block(base_block_hash, coinbase, block_time, version=version)
            tx = self.create_tx(spend, 0, 1, script)  # spend 1 satoshi
            sign_tx(tx, spend)
            self.add_transactions_to_block(block, [tx])
            block.hashMerkleRoot = block.calc_merkle_root()
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
        self.helper_peer.send_blocks_and_test(
            blocks,
            self.nodes[0],
            success=success,
            reject_reason=reject_reason,
            force_send=force_send,
            timeout=timeout,
            expect_disconnect=reconnect,
        )

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
        self.helper_peer = self.nodes[0].add_p2p_connection(P2PDataStore())
        # We need to wait for the initial getheaders from the peer before we
        # start populating our blockstore. If we don't, then we may run ahead
        # to the next subtest before we receive the getheaders. We'd then send
        # an INV for the next block and receive two getheaders - one for the
        # IBD and one for the INV. We'd respond to both and could get
        # unexpectedly disconnected if the DoS score for that error is 50.
        self.helper_peer.wait_for_getheaders(timeout=timeout)

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
        self.start_time = int(1500000000)  # int(time.time())
        self.nodes[0].setmocktime(self.start_time)

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

    def byo_txfee(self, tx, amount):
        assert self.coinbase_index < NUM_OUTPUTS_TO_COLLECT
        assert amount >= FEE_AMOUNT

        cb_tx = self.coinbase_utxo[self.coinbase_index]
        assert cb_tx is not None
        self.coinbase_index += 1
        fund_key = self.coinbase_key
        outIdx = 0

        # pay change to new p2pkh output, TODO: should use p2wpkh
        change_key = ECKey()
        change_key.generate()
        change_pubkey = change_key.get_pubkey().get_bytes()
        change_script_pkh = CScript([OP_0, hash160(change_pubkey)])
        change_amount = cb_tx.vout[0].nValue - amount

        # add new funding input and change output
        tx.vin.append(CTxIn(COutPoint(cb_tx.sha256, 0), b""))
        tx.vout.append(CTxOut(change_amount, change_script_pkh))

        # sign the tx fee input w/change output
        inIdx = len(tx.vin) - 1
        (sighash, err) = LegacySignatureHash(cb_tx.vout[outIdx].scriptPubKey, tx, inIdx, SIGHASH_ALL)
        sig = fund_key.sign_ecdsa(sighash) + bytes(bytearray([SIGHASH_ALL]))
        tx.vin[inIdx].scriptSig = CScript([sig])

        # update the hash of this transaction
        tx.rehash()

        return change_key, change_amount

    def commit(self, tx, error_code=None, error_message=None):
        # update hash
        tx.rehash()

        # confirm it is in the mempool
        tx_hex = tx.serialize().hex()
        if error_code is None or error_message is None:
            txid = self.nodes[0].sendrawtransaction(tx_hex)
        else:
            txid = assert_raises_rpc_error(error_code, error_message, self.nodes[0].sendrawtransaction, tx_hex)
        return txid

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    # test apo covenant tapscript tx
    def test_vault_covenant(self):

        # Musig(A...Z) schnorr key to use as the taproot internal key for creating the covenant signatures, securely deleted after use
        vault_privkey = generate_privkey()
        vault_pubkey, _ = compute_xonly_pubkey(vault_privkey)

        # Musig(A,B) schnorr key required to spend from vault
        AB_privkey = generate_privkey()
        AB_pubkey, _ = compute_xonly_pubkey(AB_privkey)

        # destination to spend vault balance to
        destination_address = self.nodes[0].getnewaddress(address_type="bech32")

        # generate coins and create an output that can be spent with the vault taproot scripts: spend and revault
        vault_tap = taproot_construct(vault_pubkey, get_vault_scripts(AB_pubkey))
        vault_address = program_to_witness(version=0x01, program=bytes(vault_tap.scriptPubKey)[2:], main=False)
        generate_and_send_coins(self.nodes[0], vault_address, VAULT_AMOUNT)
        dummy_tx = CTransaction()
        dummy_tx.vout = [CTxOut(nValue=0, scriptPubKey=b'')]

        # create signature for spending from the vault; sign with ANYPREVOUTANYSCRIPT
        vault_tx = create_spend_tx(source_tx=dummy_tx, inner_pubkey=vault_pubkey, spend_pubkey=AB_pubkey, amount_sat=VAULT_AMOUNT)
        vault_sig = vault_sign_spend_tx(vault_tx, dummy_tx, vault_privkey, AB_pubkey)

        # add signature to tapscript of spend leaf (and remove signature from the witness script)
        spend_tx = create_spend_tx(source_tx=dummy_tx, inner_pubkey=vault_pubkey, spend_pubkey=AB_pubkey, amount_sat=VAULT_AMOUNT, vault_signature=vault_sig)
        vault_signature = vault_sign_spend_tx(spend_tx, dummy_tx, vault_privkey, AB_pubkey, covenant=True)

        # generate coins and create an output with vault covenants outputs
        vault_covenant_tap = taproot_construct(vault_pubkey, get_vault_scripts(AB_pubkey, vault_signature))
        vault_covenant_address = program_to_witness(version=0x01, program=bytes(vault_covenant_tap.scriptPubKey)[2:], main=False)
        unvault_tx = generate_and_send_coins(self.nodes[0], vault_covenant_address, VAULT_AMOUNT)

        ###
        # To spend from the vault: 
        # - rebind spend tx to the funded vault covenant output
        # - add the spender signature to the spend tx witness 
        # - add BYO tx fee input / change output
        ###

        # rebind the prevout of spend1_tx_covenant inputs to the onchain spend0_tx_covenant_txid output before adding funding inputs (signed with SIGHASH_ALL)
        spend_tx.vin[0] = CTxIn(outpoint=COutPoint(int(unvault_tx.hash, 16), 0), nSequence=CSV_DELAY)

        # spender signs the transaction
        spender_sign_spend_tx(spend_tx, dummy_tx, AB_privkey)

        # add input for transaction fees and change output
        self.byo_txfee(tx=spend_tx, amount=FEE_AMOUNT)

        # fail: can not spend until after CSV delay
        assert not test_transaction(self.nodes[0], spend_tx, "non-BIP68-final")

        # succeed: can return to vault immediately
        # assert test_transaction(self.nodes[0], revault1_tx_covenant)

        # succeed: can spend after CSV delay
        self.nodes[0].generate(CSV_DELAY)
        assert test_transaction(self.nodes[0], spend_tx)

        # succeed: 

        print("Success!")

    def run_test(self):
        # new default wallet should load by default when there are no other wallets
        self.nodes[0].createwallet(wallet_name='', load_on_startup=False)
        self.restart_node(0)

        # create some coinbase txs to spend
        self.init_coinbase()

        # test eltoo tapscript tx
        self.test_vault_covenant()

if __name__ == '__main__':
    APOCovenantTests().main()
