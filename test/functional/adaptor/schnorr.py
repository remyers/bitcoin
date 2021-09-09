from typing import (
    Optional,
    Tuple,
)
from adaptor.ecc import (
    G,
    n,
    Pubkey,
    tagged_hash,
    int_from_bytes,
    bytes_from_int,
)

SchnorrSig = Tuple[int, Pubkey]

def nonce(x: int, message_hash: bytes) -> int:
    # TODO: use right one to match test vectors
    h = tagged_hash("Schnorr nonce", bytes_from_int(x) + message_hash)
    return int_from_bytes(h) % n

def schnorr_challenge(X: Pubkey, R: Pubkey, message_hash: bytes) -> int:
    # TODO: use right one to match test vectors
    h = tagged_hash("Schnorr challenge", X.to_bytes() + R.to_bytes() + message_hash)
    return int_from_bytes(h) % n

def schnorr_sign(x: int, message_hash: bytes, k: Optional[int] = None) -> SchnorrSig:
    if not k:
        k = nonce(x, message_hash)
    R = k * G
    X = x * G
    e = schnorr_challenge(X, R, message_hash)
    s = (k + e * x) % n
    return s, R

def schnorr_verify(X: Pubkey, message_hash: bytes, sig: SchnorrSig) -> bool:
    s, R = sig
    e = schnorr_challenge(X, R, message_hash)
    return s * G == R + e * X
