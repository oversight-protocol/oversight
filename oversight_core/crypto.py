"""
oversight_core.crypto
====================

Vetted primitives only. NO custom crypto.

Classical (ships today):
  - X25519 for key agreement
  - Ed25519 for signatures
  - XChaCha20-Poly1305 for AEAD
  - BLAKE2b for hashing / MAC
  - HKDF for key derivation
  - Argon2id for password-based KDF (via libsodium)

Post-quantum hooks (design-ready; enable via `use_pq=True` once liboqs is linked):
  - ML-KEM-768 for key encapsulation (hybrid with X25519)
  - ML-DSA-65 for signatures (hybrid with Ed25519)

The container format is crypto-agile: the algorithm suite is declared in the header,
so we can roll forward to full PQ without breaking existing sealed files.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
)

# Try to detect PQ availability
try:
    import oqs  # type: ignore

    PQ_AVAILABLE = True
except Exception:
    PQ_AVAILABLE = False


# ---------- constants ----------

SUITE_CLASSIC_V1 = "OSGT-CLASSIC-v1"   # X25519 + Ed25519 + XChaCha20-Poly1305
SUITE_HYBRID_V1 = "OSGT-HYBRID-v1"     # + ML-KEM-768 + ML-DSA-65

XCHACHA_NONCE_LEN = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24
XCHACHA_KEY_LEN = crypto_aead_xchacha20poly1305_ietf_KEYBYTES     # 32


# ---------- keypair wrappers ----------

@dataclass
class ClassicIdentity:
    """Recipient / issuer identity: X25519 (encryption) + Ed25519 (signing)."""
    x25519_priv: bytes  # 32 bytes
    x25519_pub: bytes   # 32 bytes
    ed25519_priv: bytes # 32 bytes (seed)
    ed25519_pub: bytes  # 32 bytes

    @classmethod
    def generate(cls) -> "ClassicIdentity":
        xsk = X25519PrivateKey.generate()
        esk = Ed25519PrivateKey.generate()
        return cls(
            x25519_priv=xsk.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            x25519_pub=xsk.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            ed25519_priv=esk.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            ed25519_pub=esk.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        )

    def public_bundle(self) -> dict:
        return {
            "x25519_pub": self.x25519_pub.hex(),
            "ed25519_pub": self.ed25519_pub.hex(),
        }


# ---------- AEAD ----------

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """
    XChaCha20-Poly1305. Returns (nonce, ciphertext_with_tag).
    24-byte nonce = safe to random-generate without coordination.
    """
    assert len(key) == XCHACHA_KEY_LEN, "XChaCha key must be 32 bytes"
    nonce = secrets.token_bytes(XCHACHA_NONCE_LEN)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return nonce, ct


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)


# ---------- key agreement: wrap the DEK for a recipient ----------

def wrap_dek_for_recipient(
    dek: bytes,
    recipient_x25519_pub: bytes,
    ephemeral_priv: Optional[X25519PrivateKey] = None,
) -> dict:
    """
    Encrypt a Data Encryption Key (DEK) for a single recipient using ECIES-style
    X25519 key agreement + HKDF-SHA256 + XChaCha20-Poly1305.

    Returns a dict with: ephemeral_pub, nonce, wrapped_dek (all hex).
    """
    eph = ephemeral_priv or X25519PrivateKey.generate()
    peer = X25519PublicKey.from_public_bytes(recipient_x25519_pub)
    shared = eph.exchange(peer)

    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"oversight-v1-dek-wrap",
    ).derive(shared)

    nonce, wrapped = aead_encrypt(kek, dek, aad=b"oversight-dek")
    eph_pub = eph.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "ephemeral_pub": eph_pub.hex(),
        "nonce": nonce.hex(),
        "wrapped_dek": wrapped.hex(),
    }


def unwrap_dek(wrapped: dict, recipient_x25519_priv: bytes) -> bytes:
    """Recover the DEK using the recipient's X25519 private key."""
    sk = X25519PrivateKey.from_private_bytes(recipient_x25519_priv)
    eph_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(wrapped["ephemeral_pub"]))
    shared = sk.exchange(eph_pub)

    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"oversight-v1-dek-wrap",
    ).derive(shared)

    return aead_decrypt(
        kek,
        bytes.fromhex(wrapped["nonce"]),
        bytes.fromhex(wrapped["wrapped_dek"]),
        aad=b"oversight-dek",
    )


# ---------- signatures ----------

def sign_manifest(manifest_bytes: bytes, ed25519_priv: bytes) -> bytes:
    sk = Ed25519PrivateKey.from_private_bytes(ed25519_priv)
    return sk.sign(manifest_bytes)


def verify_manifest(manifest_bytes: bytes, signature: bytes, ed25519_pub: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(ed25519_pub).verify(signature, manifest_bytes)
        return True
    except Exception:
        return False


# ---------- PQ hooks (activated when liboqs is installed) ----------

def pq_kem_keypair() -> tuple[bytes, bytes]:
    """Generate ML-KEM-768 keypair. Returns (priv, pub)."""
    if not PQ_AVAILABLE:
        raise RuntimeError("liboqs not available; install liboqs + liboqs-python")
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        pub = kem.generate_keypair()
        priv = kem.export_secret_key()
        return priv, pub


def pq_kem_encap(peer_pub: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret to peer_pub. Returns (ciphertext, shared_secret)."""
    if not PQ_AVAILABLE:
        raise RuntimeError("liboqs not available")
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        ct, ss = kem.encap_secret(peer_pub)
        return ct, ss


def pq_kem_decap(priv: bytes, ct: bytes) -> bytes:
    """Recover shared secret from ciphertext using private key."""
    if not PQ_AVAILABLE:
        raise RuntimeError("liboqs not available")
    with oqs.KeyEncapsulation("ML-KEM-768", secret_key=priv) as kem:
        return kem.decap_secret(ct)


def pq_sig_keypair() -> tuple[bytes, bytes]:
    """Generate ML-DSA-65 keypair. Returns (priv, pub)."""
    if not PQ_AVAILABLE:
        raise RuntimeError("liboqs not available")
    with oqs.Signature("ML-DSA-65") as sig:
        pub = sig.generate_keypair()
        priv = sig.export_secret_key()
        return priv, pub


def pq_sign(msg: bytes, priv: bytes) -> bytes:
    if not PQ_AVAILABLE:
        raise RuntimeError("liboqs not available")
    with oqs.Signature("ML-DSA-65", secret_key=priv) as sig:
        return sig.sign(msg)


def pq_verify(msg: bytes, signature: bytes, pub: bytes) -> bool:
    """Narrowly catches signature-verification failures; propagates other errors."""
    if not PQ_AVAILABLE:
        return False
    try:
        with oqs.Signature("ML-DSA-65") as ver:
            return ver.verify(msg, signature, pub)
    except (ValueError, RuntimeError):
        # liboqs surfaces failed verifies as RuntimeError in some builds, or
        # ValueError for malformed inputs. Everything else (MemoryError,
        # KeyboardInterrupt, etc.) propagates.
        return False


def hybrid_wrap_dek(dek: bytes, x25519_pub: bytes, mlkem_pub: bytes) -> dict:
    """
    Hybrid DEK wrap: combines X25519 and ML-KEM-768 shared secrets via HKDF.
    An attacker must break BOTH X25519 AND ML-KEM-768 to recover the KEK.

    KDF input (defense-in-depth; X-wing-style): the HKDF IKM includes both
    shared secrets AND both ciphertexts/ephemeral pubs, binding the KEK to
    this specific encapsulation. This prevents any future construction where
    an attacker could substitute a valid-but-different ciphertext.
    """
    if not PQ_AVAILABLE:
        raise RuntimeError("liboqs not available — cannot wrap hybrid")
    if len(x25519_pub) != 32:
        raise ValueError(f"x25519_pub must be 32 bytes, got {len(x25519_pub)}")

    eph = X25519PrivateKey.generate()
    peer_x = X25519PublicKey.from_public_bytes(x25519_pub)
    ss_x = eph.exchange(peer_x)
    mlkem_ct, ss_pq = pq_kem_encap(mlkem_pub)

    eph_pub = eph.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Bind KEK to the full encapsulation, not just the two shared secrets.
    ikm = ss_x + ss_pq + eph_pub + mlkem_ct
    kek = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"oversight-hybrid-v1-dek-wrap",
    ).derive(ikm)

    nonce, wrapped = aead_encrypt(kek, dek, aad=b"oversight-hybrid-dek")
    return {
        "suite": "OSGT-HYBRID-v1",
        "x25519_ephemeral_pub": eph_pub.hex(),
        "mlkem_ciphertext": mlkem_ct.hex(),
        "nonce": nonce.hex(),
        "wrapped_dek": wrapped.hex(),
    }


def hybrid_unwrap_dek(wrapped: dict, x25519_priv: bytes, mlkem_priv: bytes) -> bytes:
    """Recover DEK from a hybrid-wrapped envelope."""
    if not PQ_AVAILABLE:
        raise RuntimeError("liboqs not available — cannot unwrap hybrid")
    for required in ("x25519_ephemeral_pub", "mlkem_ciphertext", "nonce", "wrapped_dek"):
        if required not in wrapped:
            raise ValueError(f"hybrid envelope missing field: {required}")

    eph_pub_bytes = bytes.fromhex(wrapped["x25519_ephemeral_pub"])
    mlkem_ct = bytes.fromhex(wrapped["mlkem_ciphertext"])

    sk_x = X25519PrivateKey.from_private_bytes(x25519_priv)
    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    ss_x = sk_x.exchange(eph_pub)
    ss_pq = pq_kem_decap(mlkem_priv, mlkem_ct)

    ikm = ss_x + ss_pq + eph_pub_bytes + mlkem_ct
    kek = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"oversight-hybrid-v1-dek-wrap",
    ).derive(ikm)

    return aead_decrypt(
        kek,
        bytes.fromhex(wrapped["nonce"]),
        bytes.fromhex(wrapped["wrapped_dek"]),
        aad=b"oversight-hybrid-dek",
    )


# ---------- utility ----------

def random_dek() -> bytes:
    return secrets.token_bytes(XCHACHA_KEY_LEN)


def content_hash(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()
