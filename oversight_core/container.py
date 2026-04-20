"""
oversight_core.container
=======================

The `.sealed` container format. Binary layout:

    offset  length    field
    ------  --------  ---------------------------------------
    0       6         magic: b"OSGT\\x01\\x00"
    6       1         format_version (=1)
    7       1         suite_id (1=CLASSIC_V1, 2=HYBRID_V1)
    8       4         manifest_len (u32 big-endian)
    12      M         manifest (canonical JSON, signed)
    12+M    4         wrapped_dek_len (u32 BE)
    ...     W         wrapped_dek (JSON: ephemeral_pub, nonce, wrapped_dek)
    ...     24        aead_nonce
    ...     4         ciphertext_len (u32 BE)
    ...     C         ciphertext (XChaCha20-Poly1305(plaintext))

Invariants:
  * The manifest is signed BEFORE being inserted; signature is part of the manifest JSON.
  * The AEAD associated data (AAD) = content_hash from the manifest. This ties
    the ciphertext to the signed manifest: you can't swap ciphertexts between manifests.
  * The manifest content_hash = sha256(plaintext). So verifying the plaintext after
    decryption against the manifest closes the loop: you know the bytes you're reading
    are exactly what the issuer signed for this recipient.
"""

from __future__ import annotations

import io
import json
import struct
from dataclasses import dataclass
from typing import Optional

from . import crypto
from .manifest import Manifest


MAGIC = b"OSGT\x01\x00"
SUITE_CLASSIC_V1_ID = 1
SUITE_HYBRID_V1_ID = 2


# Hard caps to prevent DoS via attacker-controlled length fields.
MAX_MANIFEST_BYTES = 4 * 1024 * 1024           # 4 MB
MAX_WRAPPED_DEK_BYTES = 1 * 1024 * 1024        # 1 MB (multi-recipient can be large)
MAX_CIPHERTEXT_BYTES = 4 * 1024 * 1024 * 1024  # 4 GB


def _read_exact(buf: io.BytesIO, n: int, field: str) -> bytes:
    """Read exactly n bytes or raise ValueError."""
    data = buf.read(n)
    if len(data) != n:
        raise ValueError(f"truncated file: wanted {n} bytes for {field}, got {len(data)}")
    return data


@dataclass
class SealedFile:
    manifest: Manifest
    wrapped_dek: dict             # {ephemeral_pub, nonce, wrapped_dek} hex
    aead_nonce: bytes
    ciphertext: bytes
    suite_id: int = SUITE_CLASSIC_V1_ID

    # ---- serialize ----

    def to_bytes(self) -> bytes:
        buf = io.BytesIO()
        buf.write(MAGIC)
        buf.write(bytes([1, self.suite_id]))

        manifest_json = self.manifest.to_json()
        buf.write(struct.pack(">I", len(manifest_json)))
        buf.write(manifest_json)

        wrapped_json = json.dumps(
            self.wrapped_dek, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        buf.write(struct.pack(">I", len(wrapped_json)))
        buf.write(wrapped_json)

        buf.write(self.aead_nonce)
        buf.write(struct.pack(">I", len(self.ciphertext)))
        buf.write(self.ciphertext)

        return buf.getvalue()

    @classmethod
    def from_bytes(cls, data: bytes) -> "SealedFile":
        buf = io.BytesIO(data)
        magic = _read_exact(buf, 6, "magic")
        if magic != MAGIC:
            raise ValueError(f"Not a .sealed file (bad magic: {magic!r})")

        hdr = _read_exact(buf, 2, "version/suite")
        fmt_ver, suite_id = hdr[0], hdr[1]
        if fmt_ver != 1:
            raise ValueError(f"Unsupported format version: {fmt_ver}")

        (mlen,) = struct.unpack(">I", _read_exact(buf, 4, "manifest_len"))
        if mlen > MAX_MANIFEST_BYTES:
            raise ValueError(f"manifest too large: {mlen} > {MAX_MANIFEST_BYTES}")
        manifest_json = _read_exact(buf, mlen, "manifest")
        manifest = Manifest.from_json(manifest_json)

        (wlen,) = struct.unpack(">I", _read_exact(buf, 4, "wrapped_dek_len"))
        if wlen > MAX_WRAPPED_DEK_BYTES:
            raise ValueError(f"wrapped_dek too large: {wlen} > {MAX_WRAPPED_DEK_BYTES}")
        wrapped_dek = json.loads(_read_exact(buf, wlen, "wrapped_dek").decode("utf-8"))

        aead_nonce = _read_exact(buf, 24, "aead_nonce")
        (clen,) = struct.unpack(">I", _read_exact(buf, 4, "ciphertext_len"))
        if clen > MAX_CIPHERTEXT_BYTES:
            raise ValueError(f"ciphertext too large: {clen} > {MAX_CIPHERTEXT_BYTES}")
        ciphertext = _read_exact(buf, clen, "ciphertext")

        return cls(
            manifest=manifest,
            wrapped_dek=wrapped_dek,
            aead_nonce=aead_nonce,
            ciphertext=ciphertext,
            suite_id=suite_id,
        )


# ------------- high-level API -------------

def seal(
    plaintext: bytes,
    manifest: Manifest,
    issuer_ed25519_priv: bytes,
    recipient_x25519_pub: bytes,
) -> bytes:
    """
    Produce a .sealed blob for `recipient_x25519_pub`.

    Preconditions:
      manifest.content_hash must already be set to sha256(plaintext).
      manifest.size_bytes must match len(plaintext).
      manifest.recipient.x25519_pub must match recipient_x25519_pub (hex).
    """
    # NOTE: use `raise` not `assert` so `python -O` can't disable checks.
    if manifest.content_hash != crypto.content_hash(plaintext):
        raise ValueError("manifest.content_hash does not match sha256(plaintext)")
    if manifest.size_bytes != len(plaintext):
        raise ValueError("manifest.size_bytes does not match len(plaintext)")
    if manifest.recipient is None:
        raise ValueError("manifest.recipient is required for single-recipient seal")
    if manifest.recipient.x25519_pub != recipient_x25519_pub.hex():
        raise ValueError("manifest.recipient.x25519_pub does not match the provided pubkey")
    if len(recipient_x25519_pub) != 32:
        raise ValueError(f"recipient pubkey must be 32 bytes, got {len(recipient_x25519_pub)}")
    if len(issuer_ed25519_priv) != 32:
        raise ValueError(f"issuer priv key must be 32 bytes, got {len(issuer_ed25519_priv)}")

    manifest.sign(issuer_ed25519_priv)
    dek = crypto.random_dek()
    wrapped = crypto.wrap_dek_for_recipient(dek, recipient_x25519_pub)
    aad = manifest.content_hash.encode("ascii")
    nonce, ct = crypto.aead_encrypt(dek, plaintext, aad=aad)
    sf = SealedFile(
        manifest=manifest, wrapped_dek=wrapped, aead_nonce=nonce, ciphertext=ct,
    )
    return sf.to_bytes()


def open_sealed(
    blob: bytes,
    recipient_x25519_priv: bytes,
    trusted_issuer_pubs: Optional[set[str]] = None,
    policy_ctx: Optional["PolicyContext"] = None,
) -> tuple[bytes, Manifest]:
    """
    Decrypt a .sealed blob. Returns (plaintext, manifest).

    Verification order (fail-fast):
      1. Parse container, reject malformed.
      2. Verify manifest signature (Ed25519).
      3. If trusted_issuer_pubs provided, verify issuer is in set.
      4. Policy check (not_after, not_before, jurisdiction).
      5. Unwrap DEK (multi-recipient: try each slot).
      6. AEAD decrypt with AAD = content_hash (binds ciphertext to manifest).
      7. Post-decrypt SHA-256 check.
      8. Atomically check-and-bump max_opens after successful decryption.
    """
    from .policy import check_policy, record_open

    if len(recipient_x25519_priv) != 32:
        raise ValueError(
            f"recipient priv key must be 32 bytes, got {len(recipient_x25519_priv)}"
        )

    sf = SealedFile.from_bytes(blob)

    if not sf.manifest.verify():
        raise ValueError("Manifest signature invalid")

    if trusted_issuer_pubs is not None:
        if sf.manifest.issuer_ed25519_pub not in trusted_issuer_pubs:
            raise ValueError(
                f"Issuer not trusted: {sf.manifest.issuer_ed25519_pub[:16]}..."
            )

    # Cheap, read-only policy checks (may raise PolicyViolation)
    check_policy(sf.manifest, policy_ctx)

    # Recover DEK. For multi-recipient files, wrapped_dek contains a 'slots'
    # list; we try each slot in turn. A "wrong key" exception is expected when
    # trying non-matching slots; we only bail if NO slot decrypts.
    dek = None
    if "slots" in sf.wrapped_dek:
        last_exc: Optional[Exception] = None
        for slot in sf.wrapped_dek["slots"]:
            try:
                dek = crypto.unwrap_dek(slot, recipient_x25519_priv)
                break
            except Exception as e:
                last_exc = e
                continue
        if dek is None:
            raise ValueError(
                f"No decryptable slot found for this recipient "
                f"(tried {len(sf.wrapped_dek['slots'])} slots): {last_exc}"
            )
    else:
        dek = crypto.unwrap_dek(sf.wrapped_dek, recipient_x25519_priv)

    aad = sf.manifest.content_hash.encode("ascii")
    plaintext = crypto.aead_decrypt(dek, sf.aead_nonce, sf.ciphertext, aad=aad)

    if crypto.content_hash(plaintext) != sf.manifest.content_hash:
        raise ValueError("Plaintext hash does not match manifest")

    # Count only successful opens by an authenticated recipient.
    record_open(sf.manifest, policy_ctx)

    return plaintext, sf.manifest


def seal_multi(
    plaintext: bytes,
    manifest: Manifest,
    issuer_ed25519_priv: bytes,
    recipient_x25519_pubs: list[bytes],
) -> bytes:
    """
    Seal a single file for multiple recipients. Each recipient gets a unique
    wrap of the same DEK. See top-of-module docstring for attribution notes.
    """
    if manifest.content_hash != crypto.content_hash(plaintext):
        raise ValueError("manifest.content_hash does not match sha256(plaintext)")
    if manifest.size_bytes != len(plaintext):
        raise ValueError("manifest.size_bytes does not match len(plaintext)")
    if len(recipient_x25519_pubs) < 1:
        raise ValueError("need at least one recipient")
    if len(issuer_ed25519_priv) != 32:
        raise ValueError(f"issuer priv key must be 32 bytes, got {len(issuer_ed25519_priv)}")
    for i, pub in enumerate(recipient_x25519_pubs):
        if len(pub) != 32:
            raise ValueError(f"recipient[{i}] pubkey must be 32 bytes, got {len(pub)}")

    manifest.sign(issuer_ed25519_priv)
    dek = crypto.random_dek()
    slots = [crypto.wrap_dek_for_recipient(dek, pub) for pub in recipient_x25519_pubs]
    aad = manifest.content_hash.encode("ascii")
    nonce, ct = crypto.aead_encrypt(dek, plaintext, aad=aad)
    sf = SealedFile(
        manifest=manifest,
        wrapped_dek={"slots": slots},
        aead_nonce=nonce,
        ciphertext=ct,
    )
    return sf.to_bytes()
