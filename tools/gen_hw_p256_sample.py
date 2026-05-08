"""Generate an OSGT-HW-P256-v1 .sealed sample + matching identity JSON.

Mirrors `tools/gen_hybrid_sample.py`. Self-contained: depends only on
`cryptography` (no `oqs` needed because no PQ). Writes a sample that the
viewer's `decryptSealedHwP256` (and `oversight-rust`'s
`open_sealed_with_provider`) can both consume.

Usage:
    python3 gen_hw_p256_sample.py --out-dir ./out

Outputs:
    out/tutorial-hw-p256.sealed          - viewer test fixture
    out/tutorial-hw-p256-identity.json   - recipient P-256 priv/pub
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Container constants matching oversight_core/container.py and
# oversight-rust/oversight-container.
MAGIC = b"OSGT\x01\x00"
FORMAT_VERSION = 1
SUITE_HW_P256_V1_ID = 3
SUITE_HW_P256_V1 = "OSGT-HW-P256-v1"
P256_PUBLIC_KEY_LEN = 65


# ---------- XChaCha20-Poly1305 helper (HChaCha20 + ChaCha20-Poly1305) ----------
def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
    assert len(key) == 32 and len(nonce16) == 16
    state = bytearray(64)
    state[0:4]  = b"expa"; state[4:8]  = b"nd 3"; state[8:12]  = b"2-by"; state[12:16] = b"te k"
    state[16:48] = key
    state[48:64] = nonce16
    s = list(struct.unpack("<16I", bytes(state)))

    def rotl(v, n): return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))
    def qr(a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 7)

    for _ in range(10):
        qr(0, 4,  8, 12); qr(1, 5,  9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7,  8, 13); qr(3, 4,  9, 14)
    return struct.pack("<8I", s[0], s[1], s[2], s[3], s[12], s[13], s[14], s[15])


def xchacha20poly1305_encrypt(key: bytes, nonce24: bytes, plaintext: bytes, aad: bytes) -> bytes:
    if len(key) != 32 or len(nonce24) != 24:
        raise ValueError("xchacha20poly1305 requires 32-byte key and 24-byte nonce")
    subkey = _hchacha20(key, nonce24[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce24[16:24]
    return ChaCha20Poly1305(subkey).encrypt(nonce12, plaintext, aad)


def canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def strip_none(obj):
    if isinstance(obj, dict):
        return {k: strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [strip_none(v) for v in obj if v is not None]
    return obj


def hw_p256_wrap_dek(dek: bytes, recipient_p256_pub_sec1: bytes) -> dict:
    if len(recipient_p256_pub_sec1) != P256_PUBLIC_KEY_LEN:
        raise ValueError(f"recipient pubkey must be {P256_PUBLIC_KEY_LEN} bytes")

    peer = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), recipient_p256_pub_sec1
    )
    eph = ec.generate_private_key(ec.SECP256R1())
    shared = eph.exchange(ec.ECDH(), peer)

    kek = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"oversight-hw-p256-v1-dek-wrap",
    ).derive(shared)

    nonce = os.urandom(24)
    wrapped = xchacha20poly1305_encrypt(kek, nonce, dek, aad=b"oversight-hw-p256-dek")

    eph_pub_bytes = eph.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    assert len(eph_pub_bytes) == P256_PUBLIC_KEY_LEN

    return {
        "suite": SUITE_HW_P256_V1,
        "ephemeral_pub": eph_pub_bytes.hex(),
        "nonce": nonce.hex(),
        "wrapped_dek": wrapped.hex(),
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--message", default="hello hardware-keys oversight\n")
    args = p.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    # Recipient identity (P-256)
    rx_priv = ec.generate_private_key(ec.SECP256R1())
    rx_pub_sec1 = rx_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    rx_priv_pkcs8 = rx_priv.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Also export the raw 32-byte scalar for viewers that want it.
    rx_priv_scalar = rx_priv.private_numbers().private_value.to_bytes(32, "big")

    # Issuer Ed25519
    issuer = Ed25519PrivateKey.generate()
    issuer_pub_bytes = issuer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )

    # Plaintext + DEK
    plaintext = args.message.encode("utf-8")
    content_hash = hashlib.sha256(plaintext).hexdigest()
    dek = os.urandom(32)

    # Outer AEAD (DEK encrypts plaintext, AAD = content_hash hex string ASCII)
    aead_nonce = os.urandom(24)
    ciphertext = xchacha20poly1305_encrypt(
        dek, aead_nonce, plaintext, aad=content_hash.encode("ascii")
    )

    # Wrap DEK for recipient (P-256 ECDH)
    wrapped_dek = hw_p256_wrap_dek(dek, rx_pub_sec1)

    # Manifest
    manifest = {
        "suite": SUITE_HW_P256_V1,
        "format": "oversight/v1",
        "issuer_id": "tutorial-hw-p256@oversightprotocol.dev",
        "issuer_ed25519_pub": issuer_pub_bytes.hex(),
        "issuer_ml_dsa_pub": "",
        "recipient": {
            "id": "tutorial@oversightprotocol.dev",
            "x25519_pub": "",
            "p256_pub": rx_pub_sec1.hex(),
        },
        "content_type": "text/plain",
        "content_hash": content_hash,
        "canonical_content_hash": content_hash,
        "l3_policy": {"enabled": False, "mode": "off"},
        "filename": "hello-hw-p256.txt",
        "signature_ed25519": "",
        "signature_ml_dsa": "",
    }

    manifest_for_sign = strip_none(manifest)
    manifest_for_sign["signature_ed25519"] = ""
    manifest_for_sign["signature_ml_dsa"] = ""
    sig_bytes = issuer.sign(canonical_bytes(manifest_for_sign))
    manifest["signature_ed25519"] = sig_bytes.hex()

    manifest_serialized = canonical_bytes(strip_none(manifest))
    wrapped_dek_serialized = canonical_bytes(wrapped_dek)

    container = bytearray()
    container.extend(MAGIC)
    container.extend(bytes([FORMAT_VERSION, SUITE_HW_P256_V1_ID]))
    container.extend(struct.pack(">I", len(manifest_serialized)))
    container.extend(manifest_serialized)
    container.extend(struct.pack(">I", len(wrapped_dek_serialized)))
    container.extend(wrapped_dek_serialized)
    container.extend(aead_nonce)
    container.extend(struct.pack(">I", len(ciphertext)))
    container.extend(ciphertext)

    sealed_path = args.out_dir / "tutorial-hw-p256.sealed"
    identity_path = args.out_dir / "tutorial-hw-p256-identity.json"

    sealed_path.write_bytes(bytes(container))
    identity = {
        "recipient_id": "tutorial@oversightprotocol.dev",
        "p256_priv_scalar": rx_priv_scalar.hex(),
        "p256_priv_pkcs8": rx_priv_pkcs8.hex(),
        "p256_pub": rx_pub_sec1.hex(),
        "ed25519_priv": "public-tutorial-key-does-not-sign",
        "ed25519_pub": "public-tutorial-key-does-not-sign",
        "_note": "PUBLIC TUTORIAL KEY for OSGT-HW-P256-v1. Demo-only.",
    }
    identity_path.write_text(json.dumps(identity, indent=2))

    print(f"[+] wrote {sealed_path} ({sealed_path.stat().st_size} bytes)")
    print(f"[+] wrote {identity_path}")
    print(f"    plaintext SHA-256: {content_hash}")
    print(f"    suite: {SUITE_HW_P256_V1}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
