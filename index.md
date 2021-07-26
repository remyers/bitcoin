---
title: "Bitcoin"
---

# TODO:
 - [X] APO: Basic unit tests, [legacy](https://github.com/ajtowns/bitcoin/blob/57cb1249a20d2e09952040693eb62d04fe1f1399/src/test/sighash_tests.cpp#L247) and [taproot](https://github.com/ajtowns/bitcoin/blob/57cb1249a20d2e09952040693eb62d04fe1f1399/src/test/sighash_tests.cpp#L404)
 - [ ] APO: Review and comment on [BIP-118](https://github.com/bitcoin/bips/blob/master/bip-0118.mediawiki)
 - [X] [eltoo](https://blockstream.com/eltoo.pdf): Basic transaction tests, [simulate_eltoo.py: test_tapscript_eltoo()](https://github.com/remyers/bitcoin/blob/eltoo-anyprevout/test/functional/simulate_eltoo.py#L1623)
 - [ ] Website
 - [ ] Blog post about basic transaction tests
 - [ ] eltoo: [PTLCs](https://suredbits.com/schnorr-applications-scriptless-scripts) transaction tests
 - [ ] eltoo: [Layered Commitments](https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-January/002448.html) transaction tests
 - [ ] eltoo: [Channel Factories](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC6124062/) transaction tests
 - [ ] eltoo: add anyprevout transactions to simulation
 - [ ] eltoo: add PTLCs to simulation
 - [ ] eltoo: add Layered Commitments to simulation
 - [ ] eltoo: add Channel Factories to simulation
 - [ ] eltoo: optimize fees in simulation (eg. [fee bumping](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2021-May/019031.html), GROUP sighash)
 - [ ] eltoo: [Channel Factories](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC6124062/) transaction tests
 - [ ] eltoo: add MuSig2 to simulation

# Notes:
## Anyprevout

## eltoo

### Segwit
* [functional simulation](https://github.com/remyers/bitcoin/blob/anyprevout/test/functional/simulate_eltoo.py)

### Taproot eltoo
* [sketch by AJ Towns](https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-May/001996.html)

### Taproot PTLCs

### Layered Commitments

### Channel Factories
