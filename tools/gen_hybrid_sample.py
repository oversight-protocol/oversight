"""Generate a hybrid (OSGT-HYBRID-v1) .sealed sample + matching identity JSON.

Self-contained: depends on `cryptography` and `oqs` (liboqs-python). Mirrors the
binary container format from oversight_core/container.py and the hybrid wrap
construction from oversight_core/crypto.py:hybrid_wrap_dek, so the produced
sample is byte-compatible with the production reference implementation.

Usage (from any host where `oqs` is installed):
    python3 gen_hybrid_sample.py --out-dir ./out

Outputs:
    out/tutorial-hybrid.sealed          - viewer test fixture
    out/tutorial-hybrid-identity.json   - recipient X25519 + ML-KEM-768 priv/pub

The identity is a public test key, NEVER use for real content.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ---------- format constants (must match oversight_core/container.py) ----------
MAGIC = b"OSGT\x01\x00"
FORMAT_VERSION = 1
SUITE_HYBRID_V1_ID = 2
SUITE_HYBRID_V1 = "OSGT-HYBRID-v1"


# ---------- XChaCha20-Poly1305 (HChaCha20 + ChaCha20-Poly1305) -----------------
# Python's `cryptography` ships ChaCha20Poly1305 (12-byte nonce, RFC 7539) but
# not XChaCha20-Poly1305 (24-byte nonce). We derive a per-message subkey via
# HChaCha20 over the first 16 bytes of the 24-byte nonce, then run ChaCha20-
# Poly1305 with the remaining 8 bytes (zero-padded to 12). This matches the
# construction used by the reference implementation and noble/ciphers.

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


# ---------- canonical JSON (must match Python json.dumps sort_keys+compact) ----
def canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def strip_none(obj):
    if isinstance(obj, dict):
        return {k: strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [strip_none(v) for v in obj if v is not None]
    return obj


# ---------- hybrid DEK wrap (mirrors crypto.py:hybrid_wrap_dek) ----------------
def hybrid_wrap_dek(dek: bytes, x25519_pub: bytes, mlkem_pub: bytes) -> tuple[dict, bytes, bytes]:
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    peer_x = X25519PublicKey.from_public_bytes(x25519_pub)
    ss_x = eph.exchange(peer_x)

    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        mlkem_ct, ss_pq = kem.encap_secret(mlkem_pub)

    ikm = ss_x + ss_pq + eph_pub + mlkem_ct
    kek = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"oversight-hybrid-v1-dek-wrap",
    ).derive(ikm)

    nonce = os.urandom(24)
    wrapped = xchacha20poly1305_encrypt(kek, nonce, dek, aad=b"oversight-hybrid-dek")
    return ({
        "suite": SUITE_HYBRID_V1,
        "x25519_ephemeral_pub": eph_pub.hex(),
        "mlkem_ciphertext": mlkem_ct.hex(),
        "nonce": nonce.hex(),
        "wrapped_dek": wrapped.hex(),
    }, mlkem_ct, eph_pub)


# ---------- main --------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--message", default="hello hybrid post-quantum oversight\n")
    args = p.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    # Recipient identity
    rx_priv = X25519PrivateKey.generate()
    rx_priv_bytes = rx_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    rx_pub_bytes = rx_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        mlkem_pub = kem.generate_keypair()
        mlkem_priv = kem.export_secret_key()

    # Issuer Ed25519 (no ML-DSA: viewer.js verifies Ed25519 only; ML-DSA stays "")
    issuer = Ed25519PrivateKey.generate()
    issuer_pub_bytes = issuer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # Plaintext + DEK
    plaintext = args.message.encode("utf-8")
    content_hash = hashlib.sha256(plaintext).hexdigest()
    canonical_content_hash = content_hash  # 1:1 for plain text without canonicalization
    dek = os.urandom(32)

    # Outer AEAD (DEK encrypts plaintext, AAD = content_hash hex string ascii)
    aead_nonce = os.urandom(24)
    ciphertext = xchacha20poly1305_encrypt(
        dek, aead_nonce, plaintext, aad=content_hash.encode("ascii")
    )

    # Hybrid wrap of DEK
    wrapped_dek, _mlkem_ct, _eph_pub = hybrid_wrap_dek(dek, rx_pub_bytes, mlkem_pub)

    # Manifest
    manifest = {
        "suite": SUITE_HYBRID_V1,
        "format": "oversight/v1",
        "issuer_id": "tutorial-hybrid@oversightprotocol.dev",
        "issuer_ed25519_pub": issuer_pub_bytes.hex(),
        "issuer_ml_dsa_pub": "",
        "recipient": {
            "id": "tutorial@oversightprotocol.dev",
            "x25519_pub": rx_pub_bytes.hex(),
            "mlkem_pub": mlkem_pub.hex(),
        },
        "content_type": "text/plain",
        "content_hash": content_hash,
        "canonical_content_hash": canonical_content_hash,
        "l3_policy": {"enabled": False, "mode": "off"},
        "filename": "hello-hybrid.txt",
        "signature_ed25519": "",
        "signature_ml_dsa": "",
    }

    # Sign canonical bytes (with both signature fields blanked)
    manifest_for_sign = strip_none(manifest)
    manifest_for_sign["signature_ed25519"] = ""
    manifest_for_sign["signature_ml_dsa"] = ""
    sig_bytes = issuer.sign(canonical_bytes(manifest_for_sign))
    manifest["signature_ed25519"] = sig_bytes.hex()

    manifest_serialized = canonical_bytes(strip_none(manifest))
    wrapped_dek_serialized = canonical_bytes(wrapped_dek)

    # Build container per oversight_core/container.py
    container = bytearray()
    container.extend(MAGIC)
    container.extend(bytes([FORMAT_VERSION, SUITE_HYBRID_V1_ID]))
    container.extend(struct.pack(">I", len(manifest_serialized)))
    container.extend(manifest_serialized)
    container.extend(struct.pack(">I", len(wrapped_dek_serialized)))
    container.extend(wrapped_dek_serialized)
    container.extend(aead_nonce)
    container.extend(struct.pack(">I", len(ciphertext)))
    container.extend(ciphertext)

    sealed_path = args.out_dir / "tutorial-hybrid.sealed"
    identity_path = args.out_dir / "tutorial-hybrid-identity.json"

    sealed_path.write_bytes(bytes(container))
    identity = {
        "recipient_id": "tutorial@oversightprotocol.dev",
        "x25519_priv": rx_priv_bytes.hex(),
        "x25519_pub": rx_pub_bytes.hex(),
        "mlkem_priv": mlkem_priv.hex(),
        "mlkem_pub": mlkem_pub.hex(),
        "ed25519_priv": "public-tutorial-key-does-not-sign",
        "ed25519_pub": "public-tutorial-key-does-not-sign",
        "_note": "PUBLIC TUTORIAL KEY. Demo-only. Do not use for real content.",
    }
    identity_path.write_text(json.dumps(identity, indent=2))

    print(f"[+] wrote {sealed_path} ({sealed_path.stat().st_size} bytes)")
    print(f"[+] wrote {identity_path}")
    print(f"    plaintext SHA-256: {content_hash}")
    print(f"    suite: {SUITE_HYBRID_V1}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
