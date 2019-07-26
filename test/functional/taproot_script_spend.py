from test_framework.test_framework import BitcoinTestFramework
from test_framework.address import program_to_witness
from test_framework.script import CScriptOp, CScript, TaprootSignatureHash, taproot_construct
from test_framework.script import OP_DUP, OP_HASH160, OP_EQUAL, OP_EQUALVERIFY, OP_CHECKSIG, OP_CHECKSIGADD
from test_framework.messages import CTxInWitness, CScriptWitness, COutPoint, CTxIn, CTxOut, CTransaction, sha256 
from test_framework.util import hex_str_to_bytes

from test_framework.key import ECKey
import hashlib 
import itertools 
import random
from io import BytesIO

# Move to transaction.
def tx_from_hex(hexstring):
    tx = CTransaction()
    f = BytesIO(hex_str_to_bytes(hexstring))
    tx.deserialize(f)
    return tx

# Move to addr.
def get_taproot_bech32(info):
    if isinstance(info, tuple):
        info = info[0]
    return program_to_witness(1, info[2:])
    # Info is returned from the taproot constructor.

# Generate set of tapscripts equivalent to n-of-m multsig.
# "pk0 CSA pk1 CSA ... CS n EQ" 
def generate_multisig_tapscripts(n, pubkeys_b):
    # pubkeys_b = [pubkey.get_bytes() for pubkey in pubkeys] 
    pubkeys_b.sort() 
    key_sets = list(itertools.combinations(iter(pubkeys_b), n))
    tapscripts = []
    pubkeys_map = {}
    for set in key_sets:
        op_array = []
        for pubkey_b in set:
            op_array += [pubkey_b] 
            if pubkey_b == set[0]:
                op_array += [OP_CHECKSIG]
            else:
                op_array += [OP_CHECKSIGADD]
        op_array += [n, OP_EQUAL]
        tapscript = CScript(op_array)   
        tapscripts.append(tapscript)
        pubkeys_map[tapscript] = set 
    return tapscripts, pubkeys_map    

class TaprootScriptPathSpend(BitcoinTestFramework):
    
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=127.0.0.1", "-acceptnonstdtxn=0", "-par=1"]]

    def run_test(self):     

        self.nodes[0].generate(110)
        bal = self.nodes[0].getbalance()

        # Generate n-of-n multisig outputs equivalent to a single n-of-m multisig.
        m = random.randint(3,6)
        n = random.randint(2,m)
        secv = {} # Pubkey to private key mapping
        pkv = []
        for i in range(m):
            sec = ECKey()
            sec.generate()
            pkv.append(sec.get_pubkey().get_bytes()) # we work with raw pk bytes.
            secv[pkv[-1]] = sec
        tapscripts, pubkeys_map = generate_multisig_tapscripts(n, pkv)

        # TODO: Rethink internal key.
        sk = ECKey()
        sk.generate()
        pk = sk.get_pubkey()
        taproot_info = taproot_construct(pk, tapscripts) 
        addr = get_taproot_bech32(taproot_info)
        outputs = {}    
        outputs[addr] = bal / 100000

        # Send to taproot output.
        funding_txid_str = self.nodes[0].sendmany("", outputs) 
        funding_tx_str = self.nodes[0].getrawtransaction(funding_txid_str)
        funding_tx = tx_from_hex(funding_tx_str)

        # Determine which output is taproot output.
        taproot_index = 0
        utxos = funding_tx.vout
        taproot_output = utxos[taproot_index]
        while (taproot_output.scriptPubKey != taproot_info[0]):
            taproot_index += 1
            taproot_output = utxos[taproot_index]
        taproot_value = taproot_output.nValue

        # # Generate spending transaction [version][in][][locktime]
        taproot_spend_tx = CTransaction()
        taproot_spend_tx.nVersion = 1 
        taproot_spend_tx.nLockTime = 0        
        funding_tx.rehash()
        taproot_output_point = COutPoint(funding_tx.sha256, taproot_index) 
        tx_input = CTxIn(outpoint = taproot_output_point)
        taproot_spend_tx.vin = [tx_input] 

        # Spend entire amount back to wallet.
        # # [version][in][out][locktime]
        dest_addr = self.nodes[0].getnewaddress(address_type="bech32")
        spk = hex_str_to_bytes(self.nodes[0].getaddressinfo(dest_addr)['scriptPubKey'])
        min_fee = 5000 
        dest_out= CTxOut(nValue=taproot_value-min_fee, scriptPubKey=spk)
        taproot_spend_tx.vout = [dest_out]

        # # Construct scriptSig for p2pkh.
        htv = [0,1,2,3,0x81,0x82,0x83]

        # Spend a random tapscript from tapscripts.
        spent_tapscript = random.choice(tapscripts) 
        sighash = TaprootSignatureHash(taproot_spend_tx, [taproot_output], htv[0], 0, scriptpath = True, tapscript = spent_tapscript)

        # Determine signatures and publickeys necessary to spend this tapscript.
        pks = pubkeys_map[spent_tapscript]
        sks = [secv[pk] for pk in pks]
        sigs = []
        
        # Sig order is reverse order of corresponding pubkeys in script.
        for sk in reversed(sks):
            sigs.append(sk.sign_schnorr(sighash))           

        taproot_spend_tx.wit.vtxinwit.append(CTxInWitness())
        taproot_spend_tx.wit.vtxinwit[0].scriptWitness.stack = sigs + [spent_tapscript, taproot_info[2][spent_tapscript]]
        taproot_spend_str = taproot_spend_tx.serialize().hex()

        assert(self.nodes[0].testmempoolaccept([taproot_spend_str])) 

if __name__ == '__main__':
    TaprootScriptPathSpend().main()

