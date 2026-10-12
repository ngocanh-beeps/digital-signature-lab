"""
tests/test_signatures.py

Covers the required test matrix for the three standard algorithms
(DSA, ECDSA, Ed25519):
    1. valid signature verifies
    2. tampered file (data) -> verification fails
    3. tampered signature -> verification fails
    4. wrong public key -> verification fails

Run with:  pytest tests/test_signatures.py -v
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "signatures"))

import pytest
import dsa
import ecdsa
import ed25519

MODULES = {
    "DSA": dsa,
    "ECDSA": ecdsa,
    "Ed25519": ed25519,
}


def _flip_last_byte(b: bytes) -> bytes:
    if len(b) == 0:
        return b"\x01"
    return b[:-1] + bytes([b[-1] ^ 0xFF])


@pytest.mark.parametrize("name", MODULES.keys())
def test_valid_signature_verifies(name):
    mod = MODULES[name]
    priv, pub = mod.generate_keypair()
    data = b"Hello Signature Lab"
    sig = mod.sign(priv, data)
    assert mod.verify(pub, data, sig) is True


@pytest.mark.parametrize("name", MODULES.keys())
def test_tampered_file_fails(name):
    mod = MODULES[name]
    priv, pub = mod.generate_keypair()
    data = b"Hello Signature Lab"
    sig = mod.sign(priv, data)
    tampered_data = data + b" extra bytes"
    assert mod.verify(pub, tampered_data, sig) is False


@pytest.mark.parametrize("name", MODULES.keys())
def test_tampered_signature_fails(name):
    mod = MODULES[name]
    priv, pub = mod.generate_keypair()
    data = b"Hello Signature Lab"
    sig = mod.sign(priv, data)
    bad_sig = _flip_last_byte(sig)
    assert mod.verify(pub, data, bad_sig) is False


@pytest.mark.parametrize("name", MODULES.keys())
def test_wrong_public_key_fails(name):
    mod = MODULES[name]
    priv1, pub1 = mod.generate_keypair()
    priv2, pub2 = mod.generate_keypair()
    data = b"Hello Signature Lab"
    sig = mod.sign(priv1, data)
    assert mod.verify(pub2, data, sig) is False


# --- Demo 2 sanity check: the fixed-k module itself still verifies correctly ---

def test_fixed_k_demo_module_self_consistent():
    demo_dir = os.path.join(os.path.dirname(__file__), "..", "demos", "d2_ecdsa_nonce")
    sys.path.insert(0, demo_dir)
    import ecdsa_fixed_k as fk

    kp = fk.generate_keypair()
    msg = b"Hello RSA Lab"
    k = 123456789
    sig = fk.sign_with_k(kp.private_key, msg, k)
    assert fk.verify(kp.public_key, msg, sig) is True
    assert fk.verify(kp.public_key, b"different message", sig) is False
    
