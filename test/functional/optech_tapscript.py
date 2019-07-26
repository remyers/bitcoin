from test_framework.test_framework import BitcoinTestFramework
from test_framework.script import CScript, TapTree, TapLeaf

from test_framework.key import ECKey
import binascii

class OptechTapscript(BitcoinTestFramework):
    
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):     
        
        print("\nConstructing a Pay-to-Pubkey tapscript")

        sk = ECKey()
        sk.generate()
        pk = sk.get_pubkey()
        print("Pubkey from pk tapscript: ", pk.get_bytes().hex())

        ts_pk = TapLeaf()
        ts_pk.from_keys([pk])

        # Print output descriptor.
        print(ts_pk.desc)


        print("\nConstructing a Pay-to-Pubkey tapscript from a descriptor")

        ts_desc = "ts(pk(026bf6d12e669cb96afb170daedcc0affe36fad226e9bf2b49c2ef9519361bb882))"
        ts = TapLeaf()
        ts.from_desc(ts_desc)

        # Assert descriptor decoding and encoding result in same string.
        assert(ts.desc == ts_desc)

        # Print out tapscript operation by operation.
        for op in ts.script:
            if isinstance(op, bytes):
                print(op.hex())
            else:
                print(op)    

        print("\nConstructing a n-of-n ChecksigAdd tapscript")
            
        sks = []
        pks = []
        for i in range(3):
            sks.append(ECKey())
            sks[i].generate()
            pks.append(sks[i].get_pubkey())
                    
        ts_csa = TapLeaf()
        ts_csa.from_keys(pks)

        print(ts_csa.desc)

        for op in ts_csa.script:
            if isinstance(op, bytes):
                print(op.hex())
            else:
                print(op)


        print("\nConstructing n-of-m spending threshold with tapscript")
            
        sks = []
        pks = []
        for i in range(4):
            sks.append(ECKey())
            sks[i].generate()
            pks.append(sks[i].get_pubkey())
                    
        tss , pk_map = TapLeaf.generate_threshold_csa(2, pks)

        for ts in tss:
            print(ts.desc)


if __name__ == '__main__':
    OptechTapscript().main()


