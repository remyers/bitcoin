# Anyprevout and eltoo

This site is dedicated to efforts to further the specification, implementation and testing of two related projects: [BIP-118](https://github.com/bitcoin/bips/blob/master/bip-0118.mediawiki) (Anyprevout) and the [eltoo](https://blockstream.com/eltoo.pdf) Lightning protocol.

## TODO:
 - [X] BIP-118: Basic unit tests, [legacy](https://github.com/ajtowns/bitcoin/blob/57cb1249a20d2e09952040693eb62d04fe1f1399/src/test/sighash_tests.cpp#L247) and [taproot](https://github.com/ajtowns/bitcoin/blob/57cb1249a20d2e09952040693eb62d04fe1f1399/src/test/sighash_tests.cpp#L404)
- [ ] Review and comment on BIP-118
- [X] eltoo: Basic transaction tests, [simulate_eltoo.py: test_tapscript_eltoo()](https://github.com/remyers/bitcoin/blob/eltoo-anyprevout/test/functional/simulate_eltoo.py#L1623]
- [ ] Website
- [ ] Blog post about basic transaction tests
- [ ] eltoo: PTLCs transaction tests
- [ ] eltoo: Layered Commitments transaction tests 
- [ ] eltoo: Update simulation code to use anyprevout
- [ ] eltoo: add PTLCs to simulation
- [ ] eltoo: add Layered Commitments to simulation
- [ ] eltoo: add Channel Factories to simulation

## Anyprevout

## eltoo

### SIGHASH_NOINPUT eltoo
* (eltoo simulation)[https://github.com/remyers/bitcoin/blob/anyprevout/test/functional/simulate_eltoo.py]

### Taproot eltoo
* [sketch by AJ Towns](https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-May/001996.html)

### Taproot PTLCs

### Layered Commitments

### Channel Factories

