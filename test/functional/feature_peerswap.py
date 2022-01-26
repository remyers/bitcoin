#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Tests taproot peerswap transactions
"""

from io import BytesIO
from test_framework.address import program_to_witness
from test_framework.blocktools import (
    create_block,
    create_coinbase
)
from test_framework.key import (
    compute_xonly_pubkey,
    generate_privkey,
    sign_schnorr,
    tweak_add_pubkey,
    ECKey,
)
from test_framework.messages import (
    sha256,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut
)
from test_framework.p2p import P2PDataStore
from test_framework.script import (
    hash160,
    sha256,
    taproot_construct,
    CScript,
    CScriptNum,
    OP_0,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_CHECKSIGADD,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_NUMEQUAL,
    OP_TRUE,
    OP_VERIFY,
    SIGHASH_DEFAULT,
    SIGHASH_ALL,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
    LegacySignatureHash,
    TaprootSignatureHash,
)
from test_framework.segwit_addr import (
    decode_segwit_address
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_raises_rpc_error
)
import time
import random

KEY_VERSION_TAPROOT=b'' # non-upgraded 32-byte schnorr public key does not prepend a version
NUM_OUTPUTS_TO_COLLECT = 33
CSV_DELAY = 20
DUST_LIMIT = 600
FEE_AMOUNT = 1000
CHANNEL_AMOUNT = 1000000
RELAY_FEE = 100
NUM_SIGNERS = 2
CLTV_START_TIME = 500000000
INVOICE_TIMEOUT = 3600  # 60 minute
BLOCK_TIME = 600  # 10 minutes
MIN_FEE = 50000
DEFAULT_NSEQUENCE = 0xFFFFFFFE  # disable nSequence lock

def get_htlc_claim_tapscript(preimage_hash, pubkey, keyver):
    # HTLC Claim output (with preimage)
    return CScript([
        OP_HASH160,                             # check preimage before signature
        preimage_hash,
        OP_EQUALVERIFY,
        keyver+pubkey,                          # keyver + pubkey of party claiming payment
        OP_CHECKSIG
    ])

def get_htlc_refund_tapscript(expiry, pubkey, keyver):
    # HTLC Refund output (after expiry)
    return CScript([
        keyver+pubkey,                          # keyver + pubkey of party claiming refund
        OP_CHECKSIGVERIFY,
        CScriptNum(expiry),                     # check htlc expiry before signature
        OP_CHECKLOCKTIMEVERIFY                  # does not change stack if nLockTime of tx is a later time
    ])

# from bitcoinops util.py
def create_spending_transaction(node, txid, version=1, nSequence=0, nLockTime=0):
    """Construct a CTransaction object that spends the first ouput from txid."""
    # Construct transaction
    spending_tx = CTransaction()

    # Populate the transaction version
    spending_tx.nVersion = version

    # Populate the locktime
    spending_tx.nLockTime = nLockTime

    # Populate the transaction inputs
    outpoint = COutPoint(int(txid, 16), 0)
    spending_tx_in = CTxIn(outpoint=outpoint, nSequence=nSequence)
    spending_tx.vin = [spending_tx_in]
    dest_addr = node.getnewaddress(address_type="bech32")
    scriptpubkey = bytes.fromhex(node.getaddressinfo(dest_addr)['scriptPubKey'])

    # Complete output which returns 0.5 BTC to Bitcoin Core wallet
    amount_sat = int(0.5 * 100_000_000)
    dest_output = CTxOut(nValue=amount_sat, scriptPubKey=scriptpubkey)
    spending_tx.vout = [dest_output]

    return spending_tx


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


def get_htlc_scripts(preimage_hash, claim_pubkey, expiry, refund_pubkey, keyver):
    htlc_claim_script = get_htlc_claim_tapscript(preimage_hash, claim_pubkey, keyver)
    htlc_refund_script = get_htlc_refund_tapscript(expiry, refund_pubkey, keyver)
    scripts = [
        ("htlc_claim", htlc_claim_script), ("htlc_refund", htlc_refund_script)
    ]
    return scripts


def create_settle_tx(source_tx, outputs):
    # SETTLE TX
    # nlocktime: CLTV_START_TIME + state + 1
    # nsequence: CSV_DELAY
    # sighash=ALL
    # output 0: A
    # output 1: B
    # output 2..n: <HTLCs>
    settle_tx = CTransaction()
    settle_tx.nVersion = 2
    settle_tx.nLockTime = source_tx.nLockTime + 1

    # Populate the transaction inputs
    source_tx.rehash()
    outpoint = COutPoint(int(source_tx.hash, 16), 0)
    settle_tx.vin = [CTxIn(outpoint=outpoint, nSequence=CSV_DELAY)]

    # Complete output which emits `amount_sat` BTC to each `dest_spk`
    for dest_spk, amount_sat in outputs:
        dest_output = CTxOut(nValue=amount_sat, scriptPubKey=bytes(dest_spk))
        settle_tx.vout.append(dest_output)

    return settle_tx

def create_htlc_claim_tx(source_tx, dest_spk, htlc_index, amount_sat):
    # HTLC CLAIM TX
    # nlocktime: 0
    # nsequence: DEFAULT_NSEQUENCE
    # sighash=SINGLE | ANYONECANPAY
    htlc_claim_tx = CTransaction()
    htlc_claim_tx.nVersion = 2
    htlc_claim_tx.nLockTime = 0

    # Populate the transaction inputs
    source_tx.rehash()
    outpoint = COutPoint(int(source_tx.hash, 16), htlc_index)
    htlc_claim_tx.vin = [CTxIn(outpoint=outpoint, nSequence=DEFAULT_NSEQUENCE)]
    dest_output = CTxOut(nValue=amount_sat, scriptPubKey=bytes(dest_spk))
    htlc_claim_tx.vout = [dest_output]

    return htlc_claim_tx

def create_htlc_refund_tx(source_tx, dest_spk, htlc_index, amount_sat, expiry):
    # HTLC REFUND TX
    # nlocktime: expiry
    # nsequence: DEFAULT_NSEQUENCE
    # sighash=SINGLE | ANYONECANPAY
    htlc_refund_tx = CTransaction()
    htlc_refund_tx.nVersion = 2
    htlc_refund_tx.nLockTime = expiry

    # Populate the transaction inputs
    source_tx.rehash()
    outpoint = COutPoint(int(source_tx.hash, 16), htlc_index)
    htlc_refund_tx.vin = [CTxIn(outpoint=outpoint, nSequence=DEFAULT_NSEQUENCE)]
    dest_output = CTxOut(nValue=amount_sat, scriptPubKey=bytes(dest_spk))
    htlc_refund_tx.vout = [dest_output]

    return htlc_refund_tx


def sign_htlc_claim_tx(tx, htlc_index, spend_tx, inner_pubkey, preimage, claim_privkey, expiry, refund_pubkey, sighash_flag=SIGHASH_ANYONECANPAY, keyver=KEY_VERSION_TAPROOT):

    preimage_hash = hash160(preimage)
    claim_pubkey, _ = compute_xonly_pubkey(claim_privkey)

    # Generate taptree for htlc tx
    htlc_claim_script = get_htlc_claim_tapscript(preimage_hash, claim_pubkey, keyver)
    htlc_refund_script = get_htlc_refund_tapscript(expiry, refund_pubkey, keyver)
    htlc_taptree = taproot_construct(inner_pubkey, [
        ("htlc_claim", htlc_claim_script), ("htlc_refund", htlc_refund_script)
    ])

    # Generate the Taproot Signature Hash for signing
    sighash = TaprootSignatureHash(
        tx,
        [spend_tx.vout[htlc_index]],
        SIGHASH_SINGLE | sighash_flag,
        input_index=0,
        scriptpath=True,
        script=htlc_claim_script
    )

    # Sign with internal private key
    signature = sign_schnorr(claim_privkey, sighash) + bytes([SIGHASH_SINGLE | sighash_flag])

    # Control block created from leaf version and merkle branch information and common inner pubkey and it's negative flag
    htlc_claim_leaf = htlc_taptree.leaves["htlc_claim"]
    htlc_claim_control_block = bytes([htlc_claim_leaf.version + htlc_taptree.negflag]) + htlc_taptree.inner_pubkey + htlc_claim_leaf.merklebranch

    # Add witness to transaction
    inputs = [signature, preimage]
    witness_elements = [htlc_claim_script, htlc_claim_control_block]
    tx.wit.vtxinwit.append(CTxInWitness())
    tx.wit.vtxinwit[0].scriptWitness.stack = inputs + witness_elements

def sign_htlc_refund_tx(tx, htlc_index, spend_tx, inner_pubkey, preimage_hash, claim_pubkey, expiry, refund_privkey, sighash_flag=SIGHASH_ANYONECANPAY, keyver=KEY_VERSION_TAPROOT):
    refund_pubkey, _ = compute_xonly_pubkey(refund_privkey)

    # Generate taptree for htlc tx
    htlc_claim_script = get_htlc_claim_tapscript(preimage_hash, claim_pubkey, keyver)
    htlc_refund_script = get_htlc_refund_tapscript(expiry, refund_pubkey, keyver)
    htlc_taptree = taproot_construct(inner_pubkey, [
        ("htlc_claim", htlc_claim_script), ("htlc_refund", htlc_refund_script)
    ])

    # Generate the Taproot Signature Hash for signing
    sighash = TaprootSignatureHash(
        tx,
        [spend_tx.vout[htlc_index]],
        SIGHASH_SINGLE | sighash_flag,
        input_index=0,
        scriptpath=True,
        script=htlc_refund_script
    )

    # Sign with internal private key
    signature = sign_schnorr(refund_privkey, sighash) + bytes([SIGHASH_SINGLE | sighash_flag])

    # Control block created from leaf version and merkle branch information and common inner pubkey and it's negative flag
    htlc_refund_leaf = htlc_taptree.leaves["htlc_refund"]
    htlc_refund_control_block = bytes([htlc_refund_leaf.version + htlc_taptree.negflag]) + htlc_taptree.inner_pubkey + htlc_refund_leaf.merklebranch

    # Add witness to transaction
    inputs = [signature]
    witness_elements = [htlc_refund_script, htlc_refund_control_block]
    tx.wit.vtxinwit.append(CTxInWitness())
    tx.wit.vtxinwit[0].scriptWitness.stack = inputs + witness_elements


class SimulatePeerSwapTests(BitcoinTestFramework):

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

    def fund(self, tx, spend_tx, amount):
        assert self.coinbase_index < NUM_OUTPUTS_TO_COLLECT
        assert amount >= FEE_AMOUNT

        fund_tx = self.coinbase_utxo[self.coinbase_index]
        assert fund_tx is not None
        self.coinbase_index += 1
        fund_key = self.coinbase_key
        outIdx = 0

        # update vin and witness to spend a specific update tx (skipped for setup tx)
        if spend_tx is not None:
            tx.add_witness(spend_tx)

        # pay change to new p2pkh output, TODO: should use p2wpkh
        change_key = ECKey()
        change_key.generate()
        change_pubkey = change_key.get_pubkey().get_bytes()
        change_script_pkh = CScript([OP_0, hash160(change_pubkey)])
        change_amount = fund_tx.vout[0].nValue - amount

        # add new funding input and change output
        tx.vin.append(CTxIn(COutPoint(fund_tx.sha256, 0), b""))
        tx.vout.append(CTxOut(change_amount, change_script_pkh))

        # pay fee from spend_tx w/change output (assumed to be last txin)
        inIdx = len(tx.vin) - 1

        # sign the tx fee input w/change output
        scriptPubKey = bytearray(fund_tx.vout[outIdx].scriptPubKey)
        (sighash, err) = LegacySignatureHash(fund_tx.vout[0].scriptPubKey, tx, inIdx, SIGHASH_ALL)
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
        # self.options.timeout_factor = 20 # increase timeout for RPC calls so we can debug during the call

    def test_bitcoinops_workshop_tapscript(self):

        # create schnorr privkey and x only pubkey keys
        privkey1 = generate_privkey()
        pubkey1, _ = compute_xonly_pubkey(privkey1)
        privkey2 = generate_privkey()
        pubkey2, _ = compute_xonly_pubkey(privkey2)
        print("pubkey1: {}".format(pubkey1.hex()))
        print("pubkey2: {}".format(pubkey2.hex()))

        # Method: 32B preimage - sha256(bytes)
        # Method: 20B digest - hash160(bytes)
        secret = b'secret'
        preimage = sha256(secret)
        digest = hash160(preimage)
        delay = 20

        # Construct tapscript
        csa_delay_tapscript = CScript([
            pubkey1,
            OP_CHECKSIG,
            pubkey2,
            OP_CHECKSIGADD,
            2,
            OP_NUMEQUAL,
            OP_VERIFY,
            14,
            OP_CHECKSEQUENCEVERIFY
        ])

        print("csa_delay_tapscript operations:")
        for op in csa_delay_tapscript:
            print(op.hex()) if isinstance(op, bytes) else print(op)

        privkey_internal = generate_privkey()
        pubkey_internal, _ = compute_xonly_pubkey(privkey_internal)

        # create taptree from internal public key and list of (name, script) tuples
        taptree = taproot_construct(pubkey_internal, [("csa_delay", csa_delay_tapscript)])

        # Tweak the internal key to obtain the Segwit program
        tweaked, _ = tweak_add_pubkey(pubkey_internal, taptree.tweak)

        # Create (regtest) bech32 address from 32-byte tweaked public key
        address = program_to_witness(version=0x01, program=tweaked, main=False)
        (witver, witprog) = decode_segwit_address("bcrt", address)

        print("witver {}".format(witver))
        print("witprog {}".format(witprog))

        print("bech32 address is {}".format(address))
        print("Taproot witness program, len={} is {}\n".format(len(tweaked), tweaked.hex()))

        print("scriptPubKey operations:\n")
        for op in taptree.scriptPubKey:
            print(op.hex()) if isinstance(op, bytes) else print(op)

        # Generate coins and create an output
        tx = generate_and_send_coins(self.nodes[0], address, 100_000_000)
        print("Transaction {}, output 0\nsent to {}\n".format(tx.hash, address))

        # Create a spending transaction
        spending_tx = create_spending_transaction(self.nodes[0], tx.hash, version=2, nSequence=delay)
        print("Spending transaction:\n{}".format(spending_tx))

        # Generate the Taproot Signature Hash for signing
        sighash = TaprootSignatureHash(
            spending_tx,
            [tx.vout[0]],
            SIGHASH_DEFAULT,
            input_index=0,
            scriptpath=True,
            script=csa_delay_tapscript,
        )

        # Sign with both privkeys
        signature1 = sign_schnorr(privkey1, sighash)
        signature2 = sign_schnorr(privkey2, sighash)

        print("Signature1: {}".format(signature1.hex()))
        print("Signature2: {}".format(signature2.hex()))

        # Control block created from leaf version and merkle branch information and common inner pubkey and it's negative flag
        leaf = taptree.leaves["csa_delay"]
        control_block = bytes([leaf.version + taptree.negflag]) + taptree.inner_pubkey + leaf.merklebranch

        # Add witness to transaction
        inputs = [signature2, signature1]
        witness_elements = [csa_delay_tapscript, control_block]
        spending_tx.wit.vtxinwit.append(CTxInWitness())
        spending_tx.wit.vtxinwit[0].scriptWitness.stack = inputs + witness_elements

        print("Spending transaction:\n{}\n".format(spending_tx))

        # Test mempool acceptance with and without delay
        assert not test_transaction(self.nodes[0], spending_tx)
        self.nodes[0].generate(delay)
        assert test_transaction(self.nodes[0], spending_tx)

        print("Success!")

    # test peerswap tapscript tx
    def test_tapscript_peerswap(self):

        # Musig(A,B) schnorr key to use as the taproot internal key for tapscript outputs
        privkey_AB = generate_privkey()
        pubkey_AB, _ = compute_xonly_pubkey(privkey_AB)

        # schnorr keys to spend A balance and htlcs
        privkey_A = generate_privkey()
        pubkey_A, _ = compute_xonly_pubkey(privkey_A)

        # schnorr keys to spend B balance and htlcs
        privkey_B = generate_privkey()
        pubkey_B, _ = compute_xonly_pubkey(privkey_B)

        # htlc witness data
        secret0 = b'secret0'
        preimage0_hash = hash160(secret0)
        expiry = self.start_time + INVOICE_TIMEOUT

        # wallet addresses for settled balances
        toA_spk = bytes.fromhex(self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress(address_type="bech32"))['scriptPubKey'])
        toB_spk = bytes.fromhex(self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress(address_type="bech32"))['scriptPubKey'])

        # Generate taptree for htlc tx
        scripts = get_htlc_scripts(preimage0_hash, pubkey_A, expiry, pubkey_B, KEY_VERSION_TAPROOT)
        htlc_taptree = taproot_construct(pubkey_AB, scripts)

        # generate coins and send to the funding output
        funding_address = program_to_witness(version=0x01, program=bytes(htlc_taptree.scriptPubKey)[2:], main=False)
        funding_tx = generate_and_send_coins(self.nodes[0], funding_address, CHANNEL_AMOUNT)

        # ----------------------------------------

        # peer A creates tx to claim inflight htlc output from uncooperative close using funding transaction
        htlc_claim_tx = create_htlc_claim_tx(funding_tx, toA_spk, 0, CHANNEL_AMOUNT)
        sign_htlc_claim_tx(htlc_claim_tx, 0, funding_tx, pubkey_AB, secret0, privkey_A, expiry, pubkey_B)
        self.fund(tx=htlc_claim_tx, spend_tx=None, amount=FEE_AMOUNT)

        # succeed: test that htlc claim tx is valid
        # because preimage Fis correct
        assert test_transaction(self.nodes[0], htlc_claim_tx)

        # peer B creates tx to refund inflight htlc output from uncooperative close using funding transaction
        htlc_refund_tx = create_htlc_refund_tx(funding_tx, toB_spk, 0, CHANNEL_AMOUNT, expiry)
        sign_htlc_refund_tx(htlc_refund_tx, 0, funding_tx, pubkey_AB, preimage0_hash, pubkey_A, expiry, privkey_B)
        self.fund(tx=htlc_refund_tx, spend_tx=None, amount=FEE_AMOUNT)

        # fail: test that htlc refund tx is valid
        # because timelock has not expired
        assert not test_transaction(self.nodes[0], htlc_refund_tx, 'non-final')

        # set time of last 6 blocks so median time past of last 11 blocks is past expiry (see BIP-113)
        self.nodes[0].setmocktime(expiry+1)
        self.nodes[0].generate(6)

        # succeed: test that htlc refund tx is valid
        # because timelock has expired
        assert test_transaction(self.nodes[0], htlc_refund_tx)

        print("Success!")

    def setup_nodes(self):
        self.add_nodes(self.num_nodes)
        self.start_nodes()

    def run_test(self):
        # new default wallet should load by default when there are no other wallets
        self.nodes[0].createwallet(wallet_name='', load_on_startup=False)
        self.restart_node(0)

        # create some coinbase txs to spend
        self.init_coinbase()

        # test bitcoinops workshop 2-of-2 csa tapscript tx
        self.test_bitcoinops_workshop_tapscript()

        # test eltoo tapscript tx
        self.test_tapscript_peerswap()


if __name__ == '__main__':
    SimulatePeerSwapTests().main()
