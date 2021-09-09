from typing import (
    Tuple,
)
from adaptor.ecc import (
    G,
    n,
    tagged_hash,
    Pubkey,
    bytes_from_int,
    int_from_bytes,
)

DLEQProof = Tuple[int, int]

def dleq_nonce(x: int, Y: Pubkey, X: Pubkey, R: Pubkey) -> int:
    # TODO: use right one to match test vectors
    h = tagged_hash("DLEQ", bytes_from_int(x) + Y.to_bytes() + X.to_bytes() + R.to_bytes())
    return int_from_bytes(h) % n

def dleq_challenge(X: Pubkey, Y: Pubkey, R: Pubkey, A_G: Pubkey, A_Y: Pubkey) -> int:
    # TODO: use right one to match test vectors
    h = tagged_hash("DLEQ", X.to_bytes() + Y.to_bytes() + R.to_bytes() + A_G.to_bytes() + A_Y.to_bytes())
    return int_from_bytes(h) % n

def dleq_prove(x: int, X: Pubkey, Y: Pubkey, R: Pubkey) -> DLEQProof:
    """ Generate proof that exists x s.t. X=xG, R=xY """
    a = dleq_nonce(x, Y, X, R)
    A_G = a*G
    A_Y = a*Y
    b = dleq_challenge(X, Y, R, A_G, A_Y)
    c = (a + b * x) % n
    return b, c

def dleq_verify(X: Pubkey, Y: Pubkey, R: Pubkey, proof: DLEQProof) -> bool:
    """ Verify that exists x s.t. X=xG, R=xY """
    b, c = proof
    A_G = c*G - b*X
    A_Y = c*Y - b*R
    b_implied = dleq_challenge(X, Y, R, A_G, A_Y)
    return b == b_implied
