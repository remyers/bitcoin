import struct
from test_framework.messages import (
    ser_string,
    sha256,
    COutPoint,
    CScriptWitness,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    ToHex
)
from test_framework.script import (
    CScript,
    KEY_VERSION_TAPROOT,
    KEY_VERSION_ANYPREVOUT,
    LEAF_VERSION_TAPSCRIPT,
    SIGHASH_ALL,
    SIGHASH_DEFAULT,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
    SIGHASH_ANYPREVOUT,
    SIGHASH_ANYPREVOUTANYSCRIPT)
from test_framework.key import TaggedHash
def DebugTaprootSignatureHash(txTo, spent_utxos, hash_type, input_index = 0, scriptpath = False, script = CScript(), codeseparator_pos = -1, annex = None, leaf_ver = LEAF_VERSION_TAPSCRIPT, key_ver = KEY_VERSION_TAPROOT):
    SIGHASH_INMASK = 0x03
    SIGHASH_OUTMASK = 0xc0
    assert (len(txTo.vin) == len(spent_utxos))
    assert key_ver == KEY_VERSION_TAPROOT or key_ver == KEY_VERSION_ANYPREVOUT
    assert key_ver != KEY_VERSION_ANYPREVOUT or scriptpath
    assert (input_index < len(txTo.vin))
    out_type = SIGHASH_ALL if hash_type == SIGHASH_DEFAULT else hash_type & SIGHASH_INMASK
    in_type = hash_type & SIGHASH_OUTMASK
    spk = spent_utxos[input_index].scriptPubKey
    i = 0
    ss = bytes([0, hash_type]) # epoch, hash_type
    ss += struct.pack("<i", txTo.nVersion)
    ss += struct.pack("<I", txTo.nLockTime)
    print("epoch, nVersion, nLocktime: {}".format(ss.hex()))

    if in_type != SIGHASH_ANYONECANPAY and in_type != SIGHASH_ANYPREVOUT and in_type != SIGHASH_ANYPREVOUTANYSCRIPT:
        ss = sha256(b"".join(i.prevout.serialize() for i in txTo.vin))
        ss += sha256(b"".join(struct.pack("<q", u.nValue) for u in spent_utxos))
        ss += sha256(b"".join(ser_string(u.scriptPubKey) for u in spent_utxos))
        ss += sha256(b"".join(struct.pack("<I", i.nSequence) for i in txTo.vin))
        print("in_type 0x0: {}".format(ss.hex()))
    if out_type == SIGHASH_ALL:
        ss = sha256(b"".join(o.serialize() for o in txTo.vout))
        print("out_type SIGHASH_ALL: {}".format(ss.hex()))
    spend_type = 0
    if annex is not None:
        spend_type |= 1
    if (scriptpath):
        spend_type |= 2
    ss = bytes([spend_type])
    if in_type == SIGHASH_ANYONECANPAY:
        ss += txTo.vin[input_index].prevout.serialize()
        ss += struct.pack("<q", spent_utxos[input_index].nValue)
        ss += ser_string(spk)
        ss += struct.pack("<I", txTo.vin[input_index].nSequence)
        print("in_type SIGHASH_ANYONECANPAY: {}".format(ss.hex()))
    elif in_type == SIGHASH_ANYPREVOUT:
        ss += struct.pack("<q", spent_utxos[input_index].nValue)
        print("nValue: {}".format(struct.pack("<q", spent_utxos[input_index].nValue)))
        ss += ser_string(spk)
        print("scriptPubkey: {}".format(ser_string(spk).hex()))
        ss += struct.pack("<I", txTo.vin[input_index].nSequence)
        print("nSequence: {}".format(struct.pack("<I", txTo.vin[input_index].nSequence).hex()))
        print("in_type SIGHASH_ANYPREVOUT: {}".format(ss.hex()))
    elif in_type == SIGHASH_ANYPREVOUTANYSCRIPT:
        ss += struct.pack("<q", spent_utxos[input_index].nValue)
        print("nValue: {}".format(struct.pack("<q", spent_utxos[input_index].nValue).hex()))
        ss += struct.pack("<I", txTo.vin[input_index].nSequence) 
        print("nSequence: {}".format(struct.pack("<I", txTo.vin[input_index].nSequence).hex()))
        print("in_type SIGHASH_ANYPREVOUTANYSCRIPT: {}".format(ss.hex()))
    else:
        ss += struct.pack("<I", input_index)
        print("input_index: {}".format(ss.hex()))
    if (spend_type & 1):
        ss = sha256(ser_string(annex))
        print("spend_type & 1: {}".format(ss.hex()))
    if out_type == SIGHASH_SINGLE:
        if input_index < len(txTo.vout):
            ss = sha256(txTo.vout[input_index].serialize())
        else:
            ss = bytes(0 for _ in range(32))
        print("input_index == SIGHASH_SINGLE, txTo.vout[{}]: {}".format(input_index, ss.hex()))
    if (scriptpath):
        if in_type != SIGHASH_ANYPREVOUTANYSCRIPT:
            ss = TaggedHash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
        ss = bytes([key_ver])
        ss += struct.pack("<i", codeseparator_pos)
        print("scriptpath: {}".format(ss.hex()))
    if in_type not in [SIGHASH_ANYPREVOUT, SIGHASH_ANYPREVOUTANYSCRIPT]:
        assert len(ss) ==  175 - (in_type == SIGHASH_ANYONECANPAY) * 49 - (out_type != SIGHASH_ALL and out_type != SIGHASH_SINGLE) * 32 + (annex is not None) * 32 + scriptpath * 37
