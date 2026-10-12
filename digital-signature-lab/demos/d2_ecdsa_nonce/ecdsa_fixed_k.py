"""
demos/d2_ecdsa_nonce/ecdsa_fixed_k.py

*** RESEARCH / TEACHING DEMO ONLY — DO NOT USE FOR REAL SIGNING ***

This is a deliberately weakened ECDSA implementation that lets the caller
supply the nonce `k` explicitly, so the nonce-reuse vulnerability can be
demonstrated end-to-end (Ánh produces the signatures, My runs the recovery
attack in attack.py).

It is a standalone, pure-Python implementation over curve secp256r1 (P-256),
kept separate on purpose from src/signatures/ecdsa.py so that the safe,
standard module is never affected by this code.

Curve + hash agreed with My for this demo:
    Curve: secp256r1 (P-256)
    Hash:  SHA-256
    s normalization: NOT enforced low-s (kept raw, so the math stays simple
                      for the attack derivation) — confirm with My before
                      changing this.
"""

import hashlib
from dataclasses import dataclass

# ---- secp256r1 (P-256) domain parameters (NIST) ----
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604D
Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _inverse_mod(x: int, m: int) -> int:
    return pow(x, -1, m)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * _inverse_mod(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inverse_mod(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _scalar_mult(k: int, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


G = (Gx, Gy)


def _hash_to_int(data: bytes) -> int:
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, "big") % N


@dataclass
class KeyPair:
    private_key: int   # d
    public_key: tuple  # (x, y) = d * G


def generate_keypair(seed: int = None) -> KeyPair:
    """Generate a demo keypair. If seed is given, it's used as a fixed
    private key for reproducible teaching examples (NOT secure practice)."""
    import secrets
    d = seed if seed is not None else secrets.randbelow(N - 1) + 1
    Q = _scalar_mult(d, G)
    return KeyPair(private_key=d, public_key=Q)


def sign_with_k(private_key: int, data: bytes, k: int) -> tuple:
    """
    *** VULNERABLE BY DESIGN ***
    Sign `data` using an explicitly supplied nonce `k`.
    Never do this in real signing code — k must be fresh random every time.

    Returns:
        (r, s)
    """
    if not (1 <= k <= N - 1):
        raise ValueError("k must be in [1, N-1]")

    z = _hash_to_int(data)
    R = _scalar_mult(k, G)
    r = R[0] % N
    if r == 0:
        raise ValueError("bad k, r == 0 — choose a different k")

    k_inv = _inverse_mod(k, N)
    s = (k_inv * (z + r * private_key)) % N
    if s == 0:
        raise ValueError("bad k, s == 0 — choose a different k")

    return (r, s)


def verify(public_key: tuple, data: bytes, signature: tuple) -> bool:
    """Standard ECDSA verification (safe, used to sanity-check the demo sigs)."""
    r, s = signature
    if not (1 <= r <= N - 1 and 1 <= s <= N - 1):
        return False
    z = _hash_to_int(data)
    w = _inverse_mod(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    X = _point_add(_scalar_mult(u1, G), _scalar_mult(u2, public_key))
    if X is None:
        return False
    return (X[0] % N) == r


if __name__ == "__main__":
    kp = generate_keypair()
    msg = b"Hello ECDSA Lab"
    k_fixed = 123456789  # deliberately fixed for the demo — do NOT reuse in real code
    sig = sign_with_k(kp.private_key, msg, k_fixed)
    assert verify(kp.public_key, msg, sig)
    print("Fixed-k ECDSA demo module OK")
