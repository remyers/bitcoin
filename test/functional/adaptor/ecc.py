# Copied and adapted from https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py

from typing import Tuple, Optional
import hashlib

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Points are tuples of X and Y coordinates and the point at infinity is
# represented by the None keyword.
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

Point = Tuple[int, int]

def is_infinity(P: Optional[Point]) -> bool:
    return P is None

def x(P: Point) -> int:
    return P[0]

def y(P: Point) -> int:
    return P[1]

def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if (x(P1) == x(P2)) and (y(P1) != y(P2)):
        return None
    if P1 == P2:
        lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
    else:
        lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
    x3 = (lam * lam - x(P1) - x(P2)) % p
    return (x3, (lam * (x(P1) - x3) - y(P1)) % p)

def point_mul(P: Optional[Point], n: int) -> Optional[Point]:
    R = None
    for i in range(256):
        if (n >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    return R

def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")

def bytes_from_point(P: Point) -> bytes:
    return (b'\x03' if y(P) % 2 else b'\x02') + bytes_from_int(x(P))

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def mod_inv(x, p):
    # p must be prime
    return pow(x, p - 2, p)

class Pubkey(object):

    def __init__(self, P: Optional[Point]):
        self.P = P

    def is_infinity(self) -> bool:
        return is_infinity(self.P)

    def __add__(self, other):
        return Pubkey(point_add(self.P, other.P))

    def __neg__(self):
        return Pubkey((self.P[0], p - self.P[1]))

    def __sub__(self, other):
        return Pubkey(point_add(self.P, (-other).P))

    def __mul__(self, k: int):
        if k > 0:
            return Pubkey(point_mul(self.P, k))
        return -Pubkey(point_mul(self.P, -k))

    def __rmul__(self, k: int):
        return self.__mul__(k)

    @property
    def x(self):
        return x(self.P)

    def __eq__(self, other):
        return self.P == other.P

    def __ne__(self, other):
        return self.P != other.P

    def to_bytes(self):
        return bytes_from_point(self.P)

    def __str__(self):
        return self.to_bytes().hex()

G = Pubkey(G)
