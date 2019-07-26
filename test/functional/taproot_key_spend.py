from test_framework.test_framework import BitcoinTestFramework
from test_framework.address import program_to_witness
from test_framework.script import CScript, TaprootSignatureHash, taproot_construct
from test_framework.script import OP_CHECKSIG
from test_framework.messages import CTxInWitness, CScriptWitness, COutPoint, CTxIn, CTxOut, CTransaction, sha256 
from test_framework.util import hex_str_to_bytes
from test_framework.key import ECKey

import hashlib 
from io import BytesIO
import binascii

def tx_from_hex(hexstring):
    tx = CTransaction()
    f = BytesIO(hex_str_to_bytes(hexstring))
    tx.deserialize(f)
    return tx

def get_taproot_bech32(info):
    if isinstance(info, tuple):
        info = info[0]
    return program_to_witness(1, info[2:])

class TaprootKeyPathSpend(BitcoinTestFramework):
    
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=127.0.0.1", "-acceptnonstdtxn=0", "-par=1"]]

    def run_test(self):     

        self.nodes[0].generate(110)
        bal = self.nodes[0].getbalance()

        # Taproot constructor.
        # Private key(s) ...
        sec1 = ECKey()
        sec2 = ECKey()
        sec1.generate()
        sec2.generate()

        # 2-of-2 key path
        # Single spender key path.
        pub1= sec1.get_pubkey()
        pub2= sec1.get_pubkey()

        # Generate pk "tapscripts".
        pkh1 = hashlib.new('ripemd160', sha256(pub1.get_bytes())).digest()
        p2pkh1_script = CScript([pkh1, OP_CHECKSIG])
        
        pkh2 = hashlib.new('ripemd160', sha256(pub2.get_bytes())).digest()
        p2pkh2_script = CScript([pkh2, OP_CHECKSIG])
        
        scripts = [p2pkh1_script, p2pkh2_script]        

        # 1) SEND TO TAPROOT
        # Generate taproot address.
        taproot_info = taproot_construct(pub1, scripts) # Internal pubkey.
        outputs = {}
        addr = get_taproot_bech32(taproot_info)    
        outputs[addr] = bal / 100000

        # Generate UTXO's
        funding_txid_str = self.nodes[0].sendmany("", outputs) 
        funding_tx_str = self.nodes[0].getrawtransaction(funding_txid_str)
        funding_tx = tx_from_hex(funding_tx_str) 
        funding_tx.rehash() 
        
        index = 0
        utxos = funding_tx.vout
        output = utxos[index]
        while (utxos[index].scriptPubKey != taproot_info[0]):
            index += 1
            output = utxos[index]
        funding_value = output.nValue
        
        # 2) TAPROOT SPEND
        sec1_tweaked = sec1.tweak_add(taproot_info[1])
        
        # Generate spending transaction [version][in][][locktime]
        tx_spending = CTransaction()
        tx_spending.nVersion = 1 
        tx_spending.nLockTime = 0
        utxo = COutPoint(funding_tx.sha256, index) 
        tx_input = CTxIn(outpoint = utxo) 
        tx_spending.vin = [tx_input] 

        # Reconstruct output which sends back to host wallet.
        # [version][in][out][locktime]
        dest_addr = self.nodes[0].getnewaddress(address_type="bech32")
        spk = hex_str_to_bytes(self.nodes[0].getaddressinfo(dest_addr)['scriptPubKey'])
        min_fee = 5000
        dest_out= CTxOut(nValue=funding_value-min_fee, scriptPubKey=spk)
        tx_spending.vout = [dest_out]

        # Witness Construction
        htv = [0,1,2,3,0x81,0x82,0x83]
        sighash = TaprootSignatureHash(tx_spending, [output], htv[0])
        sig1 = sec1_tweaked.sign_schnorr(sighash) 

        # TODO: This can be shortened.
        witness = CScriptWitness()
        witness.stack.append(sig1)
        witness_in = CTxInWitness()
        witness_in.scriptWitness = witness
        tx_spending.wit.vtxinwit.append(witness_in)
        tx_spending_str = tx_spending.serialize().hex()

        # Broadcast transaction.
        # print(self.nodes[0].sendrawtransaction(tx_spending_str)) 
        assert(self.nodes[0].testmempoolaccept([tx_spending_str])) 

if __name__ == '__main__':
    TaprootKeyPathSpend().main()

