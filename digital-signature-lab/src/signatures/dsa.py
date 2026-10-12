"""
DSA signature module — standard, correct implementation using `cryptography`.

Implements the 3-function interface required by Thảo's runner:
    generate_keypair(**params)
    sign(private_key, data: bytes, **params)
    verify(public_key, data: bytes, signature: bytes, **params)
"""

from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def generate_keypair(key_size: int = 2048, **params):
    """
    Generate a DSA keypair.

    Args:
        key_size: DSA key size in bits (1024/2048/3072). Default 2048.

    Returns:
        (private_key, public_key)
    """
    private_key = dsa.generate_private_key(key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


def sign(private_key, data: bytes, hash_algo=hashes.SHA256(), **params) -> bytes:
    """
    Sign `data` with a DSA private key.

    Returns:
        DER-encoded signature bytes (r, s).
    """
    signature = private_key.sign(data, hash_algo)
    return signature


def verify(public_key, data: bytes, signature: bytes, hash_algo=hashes.SHA256(), **params) -> bool:
    """
    Verify a DSA signature.

    Returns:
        True if valid, False otherwise (never raises on bad signature).
    """
    try:
        public_key.verify(signature, data, hash_algo)
        return True
    except InvalidSignature:
        return False


# --- Optional helpers for serialization, useful for tests / CLI ---

from cryptography.hazmat.primitives import serialization


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
    # quick smoke test
    priv, pub = generate_keypair(key_size=2048)
    msg = b"Hello DSA Lab"
    sig = sign(priv, msg)
    assert verify(pub, msg, sig) is True
    assert verify(pub, b"tampered", sig) is False
    print("DSA module OK")
