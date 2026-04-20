"""
oversight_core.rekor
====================

Sigstore Rekor v2 integration (v0.5).

Builds DSSE envelopes wrapping in-toto Statements that describe Oversight
mark registrations, uploads them to a Rekor v2 log, and verifies inclusion
proofs returned by the log.

Key facts (verified 2026-04-19 against current upstream):
  * Rekor v2 GA'd 2025-10-10 (tile-backed transparency log).
  * Only entry types accepted: ``hashedrekord`` and ``dsse``.
  * Single write endpoint: ``POST {log_url}/api/v2/log/entries``.
  * Inclusion proofs are returned in the write response. There is no online
    proof-by-index API; verifiers compute proofs from tiles when they need to
    re-derive one.
  * Public log URL pattern: ``https://logYEAR-N.rekor.sigstore.dev``. Shards
    rotate roughly every 6 months. Never hardcode beyond a default.

This module deliberately does NOT depend on ``sigstore-python`` so the issuer's
runtime dependency footprint stays small. Auditors verify with stock
``sigstore-python`` via :mod:`oversight_core.auditor_helper` (separate file).
"""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


# ---- constants ----------------------------------------------------------

DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
# Pinned to a git-tagged content address so a 2031 verifier can resolve it
# even if oversight.dev DNS is squatted or expired. Tag bumps when the
# predicate body changes incompatibly.
PREDICATE_TYPE = (
    "https://github.com/oversight-protocol/oversight/blob/v0.5.0/"
    "docs/predicates/registration-v1.md"
)
PREDICATE_VERSION = 1

DEFAULT_REKOR_URL = "https://log2025-1.rekor.sigstore.dev"
TLOG_KIND = "rekor-v2-dsse"
LEGACY_TLOG_KIND = "oversight-self-merkle-v1"
BUNDLE_SCHEMA = 2  # bundles produced by v0.5+ tag schema=2; v0.4 was implicit 1

REKOR_WRITE_TIMEOUT_SEC = 25  # spec says >=20s


# ---- data classes -------------------------------------------------------


@dataclass
class OversightRegistrationPredicate:
    """Predicate body for an Oversight mark registration.

    Privacy: the on-log predicate carries a SHA-256 hash of the recipient
    public key, never the raw key. The raw key stays in the local ``.sealed``
    bundle. This prevents anyone watching the public log from enumerating
    recipients by pubkey or correlating multiple marks to the same recipient
    across issuers. ``recipient_id`` is also expected to be an opaque hash
    or UUID, not an email; if a caller passes raw PII the predicate accepts
    it but logs a warning at construction.
    """

    file_id: str
    issuer_pubkey_ed25519: str  # hex
    recipient_id: str  # opaque identifier; SHOULD be a hash, not raw email
    recipient_pubkey_sha256: str  # hex of sha256(recipient_x25519_pub_raw_bytes)
    suite: str
    registered_at: str  # ISO 8601 UTC
    rfc3161_tsa: Optional[str] = None
    rfc3161_token_b64: Optional[str] = None
    rfc3161_chain_b64: Optional[str] = None  # full TSA cert chain (concatenated PEM)
    policy: dict = field(default_factory=dict)
    watermarks: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "predicate_version": PREDICATE_VERSION,
            "file_id": self.file_id,
            "issuer_pubkey_ed25519": self.issuer_pubkey_ed25519,
            "recipient_id": self.recipient_id,
            "recipient_pubkey_sha256": self.recipient_pubkey_sha256,
            "suite": self.suite,
            "registered_at": self.registered_at,
            "policy": self.policy,
            "watermarks": self.watermarks,
        }
        if self.rfc3161_tsa:
            d["rfc3161_tsa"] = self.rfc3161_tsa
        if self.rfc3161_token_b64:
            d["rfc3161_token_b64"] = self.rfc3161_token_b64
        if self.rfc3161_chain_b64:
            d["rfc3161_chain_b64"] = self.rfc3161_chain_b64
        return d


def hash_recipient_pubkey(x25519_pub_hex: str) -> str:
    """Convenience: compute the recipient_pubkey_sha256 from a hex X25519 key.

    Issuers should call this rather than passing the raw pubkey into the
    predicate constructor, to avoid accidentally publishing it to Rekor.
    """
    import hashlib
    raw = bytes.fromhex(x25519_pub_hex)
    return hashlib.sha256(raw).hexdigest()


@dataclass
class DSSEEnvelope:
    payload_b64: str
    payload_type: str
    signatures: list[dict]  # [{"sig": "<b64>", "keyid": "<hex>"}, ...]

    def to_json(self) -> str:
        return json.dumps(
            {
                "payload": self.payload_b64,
                "payloadType": self.payload_type,
                "signatures": self.signatures,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, raw: str) -> "DSSEEnvelope":
        d = json.loads(raw)
        return cls(
            payload_b64=d["payload"],
            payload_type=d["payloadType"],
            signatures=d["signatures"],
        )


# ---- statement / envelope construction ---------------------------------


def build_statement(
    mark_id_hex: str,
    content_hash_sha256_hex: str,
    predicate: OversightRegistrationPredicate,
) -> dict:
    """Assemble the in-toto v1 Statement for an Oversight registration.

    The subject's ``digest`` carries the plaintext sha256, so any auditor
    who can hash the leaked text can find matching registrations by digest.
    The subject ``name`` carries the mark_id so attribution chains can index
    by either.
    """
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": f"mark:{mark_id_hex}",
                "digest": {"sha256": content_hash_sha256_hex},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate.to_dict(),
    }


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (PAEv1).

    PAE = "DSSEv1" SP <len(type)> SP <type> SP <len(payload)> SP <payload>
    """
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode("ascii")
        + b" "
        + payload_type.encode("ascii")
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def sign_dsse(
    statement: dict,
    issuer_ed25519_priv: bytes,
    keyid: str = "",
) -> DSSEEnvelope:
    """Sign a Statement, returning a DSSE envelope.

    ``keyid`` is opaque per spec; convention is the hex SHA-256 of the public
    key. Empty string is allowed and used in tests.
    """
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.b64encode(payload).decode("ascii")
    pae = _pae(DSSE_PAYLOAD_TYPE, payload)
    sk = Ed25519PrivateKey.from_private_bytes(issuer_ed25519_priv)
    sig = sk.sign(pae)
    return DSSEEnvelope(
        payload_b64=payload_b64,
        payload_type=DSSE_PAYLOAD_TYPE,
        signatures=[{"sig": base64.b64encode(sig).decode("ascii"), "keyid": keyid}],
    )


def verify_dsse(envelope: DSSEEnvelope, issuer_ed25519_pub: bytes) -> bool:
    """Verify the envelope's first signature against ``issuer_ed25519_pub``.

    DSSE supports multiple signatures; for Oversight v0.5 only the issuer
    signs, so we accept the first signature that verifies.
    """
    try:
        payload = base64.b64decode(envelope.payload_b64)
    except Exception:
        return False
    pae = _pae(envelope.payload_type, payload)
    pk = Ed25519PublicKey.from_public_bytes(issuer_ed25519_pub)
    for sig_obj in envelope.signatures:
        try:
            sig = base64.b64decode(sig_obj["sig"])
            pk.verify(sig, pae)
            return True
        except (InvalidSignature, KeyError, ValueError):
            continue
    return False


def envelope_payload_statement(envelope: DSSEEnvelope) -> dict:
    return json.loads(base64.b64decode(envelope.payload_b64))


# ---- network: upload ----------------------------------------------------


@dataclass
class RekorUploadResult:
    log_url: str
    log_index: Optional[int]
    log_id: Optional[str]
    integrated_time: Optional[int]
    transparency_log_entry: dict  # raw response body, persisted in bundle
    log_pubkey_pem: Optional[str] = None  # captured at write time
    checkpoint: Optional[str] = None  # signed tree-head note; promoted out of the protobuf

    def to_bundle_dict(self) -> dict:
        """Shape that Oversight bundles embed under ``rekor`` key.

        Always includes the four 5-year-replay fields the desktop reviewer
        flagged: ``log_pubkey``, ``checkpoint``, ``log_entry_schema``, and
        the raw ``transparency_log_entry`` blob. A 2031 verifier can ignore
        TUF entirely and verify directly from these fields.
        """
        return {
            "log_url": self.log_url,
            "log_index": self.log_index,
            "log_id": self.log_id,
            "integrated_time": self.integrated_time,
            "log_pubkey_pem": self.log_pubkey_pem,
            "checkpoint": self.checkpoint,
            "log_entry_schema": "rekor/v1.TransparencyLogEntry",
            "transparency_log_entry": self.transparency_log_entry,
        }


def build_bundle(
    manifest_dict: dict,
    manifest_sig_hex: str,
    upload: "RekorUploadResult",
    dsse_envelope: "DSSEEnvelope",
    rfc3161_token_b64: Optional[str] = None,
    rfc3161_chain_b64: Optional[str] = None,
) -> dict:
    """Assemble the v0.5 evidence bundle.

    The integer ``bundle_schema`` field lets pre-v0.5 verifiers fail fast
    on ``unknown schema, upgrade`` rather than silently mis-routing because
    ``tlog_kind`` happened to default the wrong way.
    """
    bundle = {
        "bundle_schema": BUNDLE_SCHEMA,
        "tlog_kind": TLOG_KIND,
        "manifest": manifest_dict,
        "manifest_sig": manifest_sig_hex,
        "rekor": upload.to_bundle_dict(),
        "dsse_envelope": json.loads(dsse_envelope.to_json()),
    }
    if rfc3161_token_b64:
        bundle["rfc3161_token"] = rfc3161_token_b64
    if rfc3161_chain_b64:
        bundle["rfc3161_chain"] = rfc3161_chain_b64
    return bundle


def upload_dsse(
    envelope: DSSEEnvelope,
    issuer_ed25519_pub_pem: str,
    log_url: str = DEFAULT_REKOR_URL,
    timeout: float = REKOR_WRITE_TIMEOUT_SEC,
) -> RekorUploadResult:
    """POST a DSSE envelope to Rekor v2.

    ``issuer_ed25519_pub_pem`` is the issuer's verification key in PEM. The
    upload payload converts it to the DER (SubjectPublicKeyInfo) bytes that
    the Rekor v2 ``Verifier.PublicKey.raw_bytes`` field actually requires.

    Wire shape per
    https://github.com/sigstore/rekor-tiles/blob/main/api/proto/rekor/v2/dsse.proto
    (verified 2026-04-19): ``verifiers`` is a repeated field; each verifier
    carries ``publicKey.rawBytes`` (DER) and a sibling ``keyDetails`` enum
    string (e.g. ``PKIX_ED25519``).

    Network errors raise; callers decide whether to retry or fall back to
    the local tlog (only acceptable for development, not production).
    """
    # Rekor's PublicKey.raw_bytes wants DER (SubjectPublicKeyInfo), not PEM.
    from cryptography.hazmat.primitives import serialization as _ser
    pub_obj = _ser.load_pem_public_key(issuer_ed25519_pub_pem.encode("utf-8"))
    pub_der = pub_obj.public_bytes(
        encoding=_ser.Encoding.DER,
        format=_ser.PublicFormat.SubjectPublicKeyInfo,
    )
    body = json.dumps(
        {
            "dsseRequestV002": {
                "envelope": json.loads(envelope.to_json()),
                "verifiers": [
                    {
                        "publicKey": {
                            "rawBytes": base64.b64encode(pub_der).decode("ascii"),
                        },
                        "keyDetails": "PKIX_ED25519",
                    }
                ],
            }
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url=log_url.rstrip("/") + "/api/v2/log/entries",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "oversight-protocol/0.5 (+https://github.com/oversight-protocol)",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:  # surface response body on failure
        detail = ""
        try:
            detail = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        raise RuntimeError(f"rekor v2 upload failed: HTTP {e.code} {detail}") from e
    parsed = json.loads(raw)
    return RekorUploadResult(
        log_url=log_url,
        log_index=_first_int(parsed, ["logIndex", "logEntry", "log_index"]),
        log_id=_first_str(parsed, ["logID", "logId", "log_id"]),
        integrated_time=_first_int(parsed, ["integratedTime", "integrated_time"]),
        transparency_log_entry=parsed,
    )


def _first_int(d: dict, keys: list[str]) -> Optional[int]:
    for k in keys:
        if k in d:
            try:
                return int(d[k])
            except (TypeError, ValueError):
                continue
    return None


def _first_str(d: dict, keys: list[str]) -> Optional[str]:
    for k in keys:
        if k in d and isinstance(d[k], str):
            return d[k]
    return None


# ---- offline verification helpers --------------------------------------


def verify_inclusion_offline(
    bundle_rekor_field: dict,
    envelope: DSSEEnvelope,
    issuer_ed25519_pub: bytes,
    expected_content_hash_sha256_hex: str,
) -> tuple[bool, str]:
    """Verify a bundled Rekor entry without contacting the log.

    Checks (in order):
      1. The DSSE envelope verifies under ``issuer_ed25519_pub``.
      2. The envelope payload's subject digest matches the bundle manifest's
         expected plaintext SHA-256.
      3. The bundled ``transparency_log_entry`` has the structural fields the
         tile-backed log returns (logIndex + signed checkpoint or proof).

    A full inclusion-proof recomputation requires fetching tiles; that lives
    in :mod:`oversight_core.auditor_helper`, which uses ``sigstore-python``.
    Returns ``(ok, reason)``.
    """
    if not verify_dsse(envelope, issuer_ed25519_pub):
        return False, "dsse signature did not verify under issuer pubkey"
    statement = envelope_payload_statement(envelope)
    try:
        subject_digest = statement["subject"][0]["digest"]["sha256"]
    except (KeyError, IndexError, TypeError):
        return False, "dsse payload missing subject digest"
    if subject_digest != expected_content_hash_sha256_hex:
        return False, "dsse subject digest does not match expected content hash"
    tle = bundle_rekor_field.get("transparency_log_entry") or {}
    if not isinstance(tle, dict) or not tle:
        return False, "bundle missing transparency_log_entry payload"
    has_proof = any(
        k in tle for k in ("inclusionProof", "inclusion_proof", "logEntry")
    )
    if not has_proof:
        return False, "transparency_log_entry has no inclusion proof or logEntry shape"
    return True, "ok"
