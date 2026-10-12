"""
Ed25519 signature module — standard, correct implementation using `cryptography`.
"""

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def generate_keypair(**params):
    """
    Generate an Ed25519 keypair.

    Returns:
        (private_key, public_key)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign(private_key, data: bytes, **params) -> bytes:
    """
    Sign `data` with an Ed25519 private key.
    Ed25519 is deterministic by design (no external nonce needed/possible).

    Returns:
        64-byte signature.
    """
    return private_key.sign(data)


def verify(public_key, data: bytes, signature: bytes, **params) -> bool:
    """
    Verify an Ed25519 signature.

    Returns:
        True if valid, False otherwise (never raises on bad signature).
    """
    try:
        public_key.verify(signature, data)
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
    msg = b"Hello Ed25519 Lab"
    sig = sign(priv, msg)
    assert verify(pub, msg, sig) is True
    assert verify(pub, b"tampered", sig) is False
    print("Ed25519 module OK")
