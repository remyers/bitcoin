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

ECDSASig = Tuple[int, int]

def nonce(x: int, message_hash: bytes) -> int:
    # TODO: use right one to match test vectors
    h = tagged_hash("ECDSA", bytes_from_int(x) + message_hash)
    return int_from_bytes(h) % n

def ecdsa_sign(x: int, message_hash: bytes) -> ECDSASig:
    k = nonce(x, message_hash)
    R = k * G
    r = R.x % n
    m = int_from_bytes(message_hash)
    s = mod_inv(k, n) * (m + r * x) % n
    return r, s

def ecdsa_verify(X: Pubkey, message_hash: bytes, sig: ECDSASig) -> bool:
    r, s = sig
    m = int_from_bytes(message_hash)
    u1 = mod_inv(s, n) * m % n
    u2 = mod_inv(s, n) * r % n
    R_implied = u1*G + u2*X
    return R_implied.x % n == r
