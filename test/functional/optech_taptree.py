from test_framework.test_framework import BitcoinTestFramework
from test_framework.script import TapTree, TapLeaf, Node
from test_framework.key import ECKey


class OptechTapscript(BitcoinTestFramework):
    
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):     
        
        print("\nConstructing a TapTree from a descriptor")
        
        tp_desc = "tp(026bf6d12e669cb96afb170daedcc0affe36fad226e9bf2b49c2ef9519361bb882,[ts(pk(026bf6d12e669cb96afb170daedcc0affe36fad226e9bf2b49c2ef9519361bb882)),[ts(pk(029f093894657d515646e23042e5ba198a11e8dd8c315deb55db62e7cbc4bab047)),[ts(pk(025a59322be1a5b2f0bfb496c7a4808baf55a9c51f4be98aa475c5592a0b915f7e)),ts(raw(0337062390b186749bd7012d75081ed5e6445fda91df0cf669dc924fd3731ad4ca))]]])"
        tp = TapTree()
        tp.from_desc(tp_desc)

        # Internal key.
        print(tp.key.get_bytes().hex())

        # TODO
        # for ts, height in tp.tapleafs:
            # print(ts.desc, height)    

        print("\nConstructing a TapTree Node-by-Node")
        
        # Generate Tapscripts
        sks = []
        pks = []
        for i in range(3):
            sks.append(ECKey())
            sks[i].generate()
            pks.append(sks[i].get_pubkey())
                    
        tss , pk_map = TapLeaf.generate_threshold_csa(2, pks)

        # Build Taptree
        sk = ECKey()
        sk.generate()
        pk = sk.get_pubkey()

        tp = TapTree()
        tp.key = pk
        tp.root.left = tss[0]
        tp.root.right = Node()
        tp.root.right.left = tss[1]
        tp.root.right.right = tss[2]

        print(tp.desc)

        print("\nDescribing TapTree Spending Policy")

        # Internal Key
        sk = ECKey()
        sk.generate()
        pk = sk.get_pubkey()

        # Generate Tapscripts
        sks = []
        pks = []
        for i in range(4):
            sks.append(ECKey())
            sks[i].generate()
            pks.append(sks[i].get_pubkey())
                    
        tss , pk_map = TapLeaf.generate_threshold_csa(2, pks)

        # Policy Expression: or(1@tss[0], 2@tss[1], 2@tss[2], 3@tss[3])
        # TODO: Policy Expression Interpreter.
        policy = [(1, tss[0]),(2, tss[2]),(2, tss[2]),(3, tss[3])]

        tp_tree = TapTree()
        tp_tree.key = pk
        tp_tree.from_policy(policy)
        
        print(tp_tree.desc)
        

if __name__ == '__main__':
    OptechTapscript().main()


