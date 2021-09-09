from typing import (
    Tuple,
)
from adaptor.ecc import (
    G,
    n,
    mod_inv,
    Pubkey,
    tagged_hash,
    int_from_bytes,
    bytes_from_int,
)
from adaptor.ecdsa import (
    ECDSASig,
)
from adaptor.schnorr import (
    SchnorrSig,
    schnorr_challenge,
)
from adaptor.dleq import (
    dleq_prove,
    dleq_verify,
    DLEQProof,
)

ECDSAAdaptorSig = Tuple[Pubkey, Pubkey, int, DLEQProof]

def ecdsa_nonce(x: int, Y: Pubkey, message_hash: bytes) -> int:
    # TODO: use right one to match test vectors
    h = tagged_hash("ECDSA ADAPTOR", bytes_from_int(x) + Y.to_bytes() + message_hash)
    return int_from_bytes(h) % n

def ecdsa_adaptor_encrypt(x: int, Y: Pubkey, message_hash: bytes) -> ECDSAAdaptorSig:
    k = ecdsa_nonce(x, Y, message_hash)
    R_a = k * G
    R = k * Y
    dleq_proof = dleq_prove(k, R_a, Y, R)
    r = R.x % n
    m = int_from_bytes(message_hash)
    s_a = (mod_inv(k, n) * (m + r * x)) % n
    return R, R_a, s_a, dleq_proof

def ecdsa_adaptor_verify(X: Pubkey, Y: Pubkey, message_hash: bytes, a: ECDSAAdaptorSig) -> bool:
    R, R_a, s_a, dleq_proof = a
    if not dleq_verify(R_a, Y, R, dleq_proof):
        return False
    r = R.x % n
    m = int_from_bytes(message_hash)
    u1 = mod_inv(s_a, n) * m % n
    u2 = mod_inv(s_a, n) * r % n
    return u1*G + u2*X == R_a

def ecdsa_adaptor_decrypt(a: ECDSAAdaptorSig, y: int) -> ECDSASig:
    R, R_a, s_a, dleq_proof = a
    s = s_a * mod_inv(y, n)
    if s > (n >> 1):
        s = n - s
    r = R.x % n
    return r, s

def ecdsa_adaptor_recover(Y: Pubkey, a: ECDSAAdaptorSig, sig: ECDSASig) -> int:
    R, R_a, s_a, dleq_proof = a
    r, s = sig
    r_implied = R.x % n
    assert r == r_implied
    y = mod_inv(s, n) * s_a % n
    Y_implied = y*G
    if Y_implied == Y:
        return y
    if Y_implied == -Y:
        return n - y
    assert False

SchnorrAdaptorSig = Tuple[int, Pubkey]

def schnorr_nonce(x: int, Y: Pubkey, message_hash: bytes) -> int:
    # TODO: use right one to match test vectors
    h = tagged_hash("Schnorr ADAPTOR", bytes_from_int(x) + Y.to_bytes() + message_hash)
    return int_from_bytes(h) % n

def schnorr_adaptor_encrypt(x: int, y: int, message_hash: bytes) -> SchnorrAdaptorSig:
    Y = y * G
    k = schnorr_nonce(x, Y, message_hash)
    R = k * G
    X = x * G
    e = schnorr_challenge(X, R, message_hash)
    s_a = (k + y + e * x) % n
    return s_a, R

def schnorr_adaptor_verify(X: Pubkey, Y: Pubkey, message_hash: bytes, a: SchnorrAdaptorSig) -> bool:
    s_a, R = a
    e = schnorr_challenge(X, R, message_hash)
    return s_a * G == R + Y + e * X

def schnorr_adaptor_decrypt(a: SchnorrAdaptorSig, y: int) -> SchnorrSig:
    s_a, R = a
    return (s_a - y) % n, R

def schnorr_adaptor_recover(a: SchnorrAdaptorSig, sig: SchnorrSig) -> int:
    s_a, R_a = a
    s, R = sig
    assert R_a == R
    return (s_a - s) % n
