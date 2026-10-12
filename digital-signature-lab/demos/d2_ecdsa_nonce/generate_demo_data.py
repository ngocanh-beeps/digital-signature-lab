"""
demos/d2_ecdsa_nonce/generate_demo_data.py

Ánh's deliverable for Demo 2 (ECDSA nonce reuse).

What this script does:
  1. Generates one ECDSA keypair (private key d stays secret, never written out).
  2. Signs two different messages with the SAME nonce k (the vulnerability).
  3. Writes out ONLY the public data My needs for the attack:
       - public key (x, y)
       - message 1, signature (r1, s1)
       - message 2, signature (r2, s2)
       - curve name, hash name  (agreed parameters)
     -> demos/d2_ecdsa_nonce/public_handoff.json

  The private key d and the nonce k are kept in memory only (and optionally
  dumped to a LOCAL-ONLY secret file for Ánh's own later verification), so
  My must recover them purely from the public handoff data.
"""

import json
import os

from ecdsa_fixed_k import generate_keypair, sign_with_k, verify, N

HERE = os.path.dirname(os.path.abspath(__file__))
PUBLIC_HANDOFF_PATH = os.path.join(HERE, "public_handoff.json")
SECRET_PATH = os.path.join(HERE, "_answer_key_DO_NOT_SHARE.json")  # Ánh's eyes only


def main():
    kp = generate_keypair()

    message_1 = b"Hello RSA Lab"
    message_2 = b"Hello ECDSA Lab"

    # Fixed k reused across both signatures — THE vulnerability being demonstrated.
    k = 987654321987654321 % (N - 1) + 1

    sig1 = sign_with_k(kp.private_key, message_1, k)
    sig2 = sign_with_k(kp.private_key, message_2, k)

    # Sanity check both signatures verify normally before handing off.
    assert verify(kp.public_key, message_1, sig1)
    assert verify(kp.public_key, message_2, sig2)

    public_handoff = {
        "curve": "secp256r1 (P-256)",
        "hash": "SHA-256",
        "public_key": {"x": kp.public_key[0], "y": kp.public_key[1]},
        "message_1": message_1.decode(),
        "signature_1": {"r": sig1[0], "s": sig1[1]},
        "message_2": message_2.decode(),
        "signature_2": {"r": sig2[0], "s": sig2[1]},
        "note": "signature_1 and signature_2 were produced with the same nonce k. "
                "Recover k and the private key d from this data only.",
    }

    with open(PUBLIC_HANDOFF_PATH, "w") as f:
        json.dump(public_handoff, f, indent=2)

    # Local-only answer key so Ánh can confirm My's recovered d/k are correct.
    # Do NOT send this file to My.
    answer_key = {"private_key_d": kp.private_key, "k": k}
    with open(SECRET_PATH, "w") as f:
        json.dump(answer_key, f, indent=2)

    print(f"Public handoff data written to: {PUBLIC_HANDOFF_PATH}")
    print(f"(local-only) answer key written to: {SECRET_PATH}")
    print("Hand only public_handoff.json to My.")


if __name__ == "__main__":
    main()
