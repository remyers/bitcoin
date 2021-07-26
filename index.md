---
title: "TR-eltoo"
---

I have compiled below a list of tasks and related notes that might be helpful for anyone that wants to learn more about the status and implementation details of BIP-118 (Anyprevout) and eltoo. Please get in touch if you have any questions or can help work on one of these tasks. Open an issue or PR if you think of additional tasks, notes or other changes for this page.

# Anyprevout

## Tasks:
 - [X] Basic unit tests, [legacy](https://github.com/ajtowns/bitcoin/blob/57cb1249a20d2e09952040693eb62d04fe1f1399/src/test/sighash_tests.cpp#L247) and [taproot](https://github.com/ajtowns/bitcoin/blob/57cb1249a20d2e09952040693eb62d04fe1f1399/src/test/sighash_tests.cpp#L404)
 - [ ] Review and comment on [BIP-118](https://github.com/bitcoin/bips/blob/master/bip-0118.mediawiki)
 - [ ] run a signet node
 - [ ] run a signet faucet

## Notes:

### BIP

### Signet

Faucet idea: can signet miners create a single signature and prototype transaction that can spend any coinbase output using APOAS? As long as any change goes back to the same address then the signature can be used again by others.

# eltoo

## Tasks:
 - [X] [eltoo](https://blockstream.com/eltoo.pdf): Basic transaction tests, [simulate_eltoo.py: test_tapscript_eltoo()](https://github.com/remyers/bitcoin/blob/eltoo-anyprevout/test/functional/simulate_eltoo.py#L1623)
 - [ ] [Blog post](https://bitcoin.yakshaver.org/2021/07/26/first.html) about basic transaction tests
 - [ ] [PTLCs](https://suredbits.com/schnorr-applications-scriptless-scripts) transaction tests
 - [ ] [Layered Commitments](https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-January/002448.html) transaction tests
 - [ ] [Channel Factories](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC6124062/) transaction tests
 - [ ] update simulation with APO transactions
 - [ ] add PTLCs to simulation
 - [ ] add Layered Commitments to simulation
 - [ ] add Channel Factories to simulation
 - [ ] add optimize fees to simulation (eg. [fee bumping](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2021-May/019031.html), GROUP sighash)
 - [ ] [Channel Factories](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC6124062/) transaction tests
 - [ ] add MuSig2 to simulation

## Notes:

### Segwit eltoo
* [functional simulation](https://github.com/remyers/bitcoin/blob/anyprevout/test/functional/simulate_eltoo.py)

### Taproot eltoo
* [sketch by AJ Towns](https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-May/001996.html)

### PTLCs

### Layered Commitments

### Channel Factories
