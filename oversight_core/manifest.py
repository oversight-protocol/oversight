"""
oversight_core.manifest
======================

The manifest is the signed metadata that binds a sealed file to its recipient,
its watermarks, its beacons, and its policy. It's the artifact a registry stores
and a verifier checks.

Wire format (v1): canonical JSON (sorted keys, no whitespace), UTF-8, Ed25519-signed.
Post-quantum: ML-DSA signature slot reserved in the envelope.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional

from .crypto import sign_manifest, verify_manifest, SUITE_CLASSIC_V1


@dataclass
class Recipient:
    recipient_id: str                # stable identifier (email hash, user UUID, etc.)
    x25519_pub: str                  # hex
    ed25519_pub: Optional[str] = None  # hex, for verifying recipient acks


@dataclass
class WatermarkRef:
    layer: str        # 'L1_zero_width' | 'L2_whitespace' | 'L3_synonyms'
    mark_id: str      # hex


@dataclass
class Manifest:
    # identifiers
    file_id: str                       # uuid4
    issued_at: int                     # unix seconds
    version: str = "OVERSIGHT-v1"
    suite: str = SUITE_CLASSIC_V1

    # file properties
    original_filename: str = ""
    content_hash: str = ""             # sha256 of plaintext
    content_type: str = "application/octet-stream"
    size_bytes: int = 0

    # issuer (who sealed this)
    issuer_id: str = ""
    issuer_ed25519_pub: str = ""       # hex — used to verify the signature

    # recipient binding
    recipient: Optional[Recipient] = None

    # per-recipient marks + beacons
    watermarks: list[WatermarkRef] = field(default_factory=list)
    beacons: list[dict] = field(default_factory=list)

    # policy
    policy: dict = field(default_factory=dict)
    # policy fields (opt):
    #   not_after: int (unix)
    #   max_opens: int
    #   jurisdiction: str (e.g., "EU", "US", "GLOBAL")
    #   require_attestation: bool
    #   registry_url: str

    # signature slot (filled in after canonical-serialize)
    signature_ed25519: str = ""        # hex
    signature_ml_dsa: str = ""         # hex, reserved for PQ

    # ---- lifecycle ----

    @classmethod
    def new(
        cls,
        original_filename: str,
        content_hash: str,
        size_bytes: int,
        issuer_id: str,
        issuer_ed25519_pub_hex: str,
        recipient: Recipient,
        registry_url: str,
        content_type: str = "application/octet-stream",
        not_after: Optional[int] = None,
        max_opens: Optional[int] = None,
        jurisdiction: str = "GLOBAL",
    ) -> "Manifest":
        policy = {
            "registry_url": registry_url,
            "jurisdiction": jurisdiction,
        }
        if not_after:
            policy["not_after"] = not_after
        if max_opens:
            policy["max_opens"] = max_opens

        return cls(
            file_id=str(uuid.uuid4()),
            issued_at=int(time.time()),
            original_filename=original_filename,
            content_hash=content_hash,
            content_type=content_type,
            size_bytes=size_bytes,
            issuer_id=issuer_id,
            issuer_ed25519_pub=issuer_ed25519_pub_hex,
            recipient=recipient,
            policy=policy,
        )

    # ---- canonical serialization ----

    def to_dict(self, include_signatures: bool = True) -> dict:
        d = asdict(self)
        if not include_signatures:
            d["signature_ed25519"] = ""
            d["signature_ml_dsa"] = ""
        return d

    @staticmethod
    def _strip_none(obj):
        """Recursively drop None values from dicts.

        Canonical JSON for Oversight: omit null-valued fields rather than
        emit `"field": null`. Matches the Rust reference's `serde(skip_serializing_if)`
        and the broader industry convention (Sigstore et al.).
        """
        if isinstance(obj, dict):
            return {k: Manifest._strip_none(v) for k, v in obj.items() if v is not None}
        if isinstance(obj, list):
            return [Manifest._strip_none(x) for x in obj]
        return obj

    def canonical_bytes(self) -> bytes:
        """Canonical serialization excluding signatures (what we actually sign).

        Rules:
          - Exclude the two signature fields (replace with empty string sentinel).
          - Drop None-valued fields recursively.
          - Sort keys lexicographically.
          - UTF-8 encoded, no whitespace.
        """
        d = self.to_dict(include_signatures=False)
        d = self._strip_none(d)
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_json(self) -> bytes:
        d = self._strip_none(self.to_dict())
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> "Manifest":
        d = json.loads(data.decode("utf-8"))
        rec = d.pop("recipient", None)
        wms = d.pop("watermarks", [])
        m = cls(**d)
        if rec:
            m.recipient = Recipient(**rec)
        m.watermarks = [WatermarkRef(**w) for w in wms]
        return m

    # ---- signing & verification ----

    def sign(self, issuer_ed25519_priv: bytes) -> None:
        sig = sign_manifest(self.canonical_bytes(), issuer_ed25519_priv)
        self.signature_ed25519 = sig.hex()

    def verify(self) -> bool:
        if not self.signature_ed25519 or not self.issuer_ed25519_pub:
            return False
        return verify_manifest(
            self.canonical_bytes(),
            bytes.fromhex(self.signature_ed25519),
            bytes.fromhex(self.issuer_ed25519_pub),
        )
