"""
ECDSA signature module — standard, correct implementation using `cryptography`.

This module is the SAFE / production-style version: nonce k is generated
internally and randomly for every signature, as it must be in real usage.

The deliberately-broken "caller supplies k" variant used ONLY for the
nonce-reuse research demo lives in a separate file:
    demos/d2_ecdsa_nonce/ecdsa_fixed_k.py
It must never be imported by the standard file-signing feature.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

DEFAULT_CURVE = ec.SECP256R1()  # a.k.a. P-256, NIST curve — agree with My if a different curve is needed


def generate_keypair(curve=DEFAULT_CURVE, **params):
    """
    Generate an ECDSA keypair.

    Args:
        curve: an `ec.EllipticCurve` instance (default SECP256R1 / P-256).

    Returns:
        (private_key, public_key)
    """
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key


def sign(private_key, data: bytes, hash_algo=hashes.SHA256(), **params) -> bytes:
    """
    Sign `data` with an ECDSA private key.
    Nonce k is generated securely and randomly inside the library — never
    exposed, never reused. This is the correct, safe behavior.

    Returns:
        DER-encoded signature bytes (r, s).
    """
    signature = private_key.sign(data, ec.ECDSA(hash_algo))
    return signature


def verify(public_key, data: bytes, signature: bytes, hash_algo=hashes.SHA256(), **params) -> bool:
    """
    Verify an ECDSA signature.

    Returns:
        True if valid, False otherwise (never raises on bad signature).
    """
    try:
        public_key.verify(signature, data, ec.ECDSA(hash_algo))
        return True
    except InvalidSignature:
        return False


def private_key_to_pem(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


if __name__ == "__main__":
    priv, pub = generate_keypair()
    msg = b"Hello ECDSA Lab"
    sig = sign(priv, msg)
    assert verify(pub, msg, sig) is True
    assert verify(pub, b"tampered", sig) is False
    print("ECDSA module OK")
