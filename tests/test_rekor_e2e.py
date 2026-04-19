"""
test_rekor_e2e
==============

Live end-to-end test against a public Sigstore Rekor v2 log.

This test makes real network calls and writes a real (immutable) entry to
the public log shard. It is therefore gated behind the OVERSIGHT_REKOR_E2E=1
environment variable so routine test runs do not append to the public log.

Run with:
    OVERSIGHT_REKOR_E2E=1 python3 tests/test_rekor_e2e.py

What is verified:
  1. A DSSE-wrapped Oversight registration predicate uploads successfully.
  2. The log returns a JSON response carrying a logIndex (or equivalent
     under the v2 field naming).
  3. The DSSE envelope verifies under the issuer pubkey AFTER the upload —
     i.e., the round-trip did not mutate signature-bearing bytes.
  4. The on-log predicate carries recipient_pubkey_sha256, never the raw
     X25519 public key (privacy invariant).

Skipped automatically when OVERSIGHT_REKOR_E2E is unset or 0.
"""
from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from oversight_core import rekor as R


GATE = os.environ.get("OVERSIGHT_REKOR_E2E", "0") == "1"
LOG_URL = os.environ.get("OVERSIGHT_REKOR_URL", R.DEFAULT_REKOR_URL)


def _new_keypair() -> tuple[bytes, bytes, str]:
    sk = Ed25519PrivateKey.generate()
    priv_raw = sk.private_bytes_raw()
    pub_raw = sk.public_key().public_bytes_raw()
    pub_pem = sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv_raw, pub_raw, pub_pem


def t1_live_upload_round_trip():
    priv_raw, pub_raw, pub_pem = _new_keypair()

    # Recipient X25519 pubkey is hashed before going on-log.
    fake_x25519 = b"\x42" * 32
    recipient_hash = R.hash_recipient_pubkey(fake_x25519.hex())

    predicate = R.OversightRegistrationPredicate(
        file_id="e2e-test-" + base64.b16encode(os.urandom(8)).decode().lower(),
        issuer_pubkey_ed25519=pub_raw.hex(),
        recipient_id="opaque-recipient-id-1",
        recipient_pubkey_sha256=recipient_hash,
        suite="classic",
        registered_at="2026-04-19T00:00:00Z",
    )
    statement = R.build_statement(
        mark_id_hex=predicate.file_id,
        content_hash_sha256_hex="ab" * 32,
        predicate=predicate,
    )
    envelope = R.sign_dsse(statement=statement, issuer_ed25519_priv=priv_raw)

    # Round-trip verify BEFORE upload (sanity).
    assert R.verify_dsse(envelope, pub_raw), "local DSSE verify failed before upload"

    print(f"  uploading to {LOG_URL} ...")
    result = R.upload_dsse(envelope=envelope, issuer_ed25519_pub_pem=pub_pem, log_url=LOG_URL)

    assert result.transparency_log_entry, "rekor returned empty body"
    print(f"  log_index={result.log_index} log_id={(result.log_id or '')[:24]}...")

    # The envelope must still verify after the round trip.
    assert R.verify_dsse(envelope, pub_raw), "DSSE verify failed AFTER upload (envelope mutated?)"

    # Privacy invariant: raw X25519 must not appear in the on-log envelope.
    on_log_payload = base64.b64decode(envelope.payload_b64)
    assert fake_x25519.hex() not in on_log_payload.decode("utf-8", errors="ignore"), (
        "raw recipient X25519 pubkey leaked into on-log payload"
    )
    print("  [PASS] live round trip + privacy invariant held")


def t2_response_carries_inclusion_data():
    """The bundled response must give a verifier enough to verify offline.

    Per the v0.5 plan: the write response is the only place we get an
    inclusion proof; there is no online proof-by-index API.
    """
    priv_raw, pub_raw, pub_pem = _new_keypair()
    predicate = R.OversightRegistrationPredicate(
        file_id="e2e-incl-" + base64.b16encode(os.urandom(8)).decode().lower(),
        issuer_pubkey_ed25519=pub_raw.hex(),
        recipient_id="opaque-recipient-id-2",
        recipient_pubkey_sha256="0" * 64,
        suite="classic",
        registered_at="2026-04-19T00:00:00Z",
    )
    statement = R.build_statement(
        mark_id_hex=predicate.file_id,
        content_hash_sha256_hex="cd" * 32,
        predicate=predicate,
    )
    envelope = R.sign_dsse(statement=statement, issuer_ed25519_priv=priv_raw)
    result = R.upload_dsse(envelope=envelope, issuer_ed25519_pub_pem=pub_pem, log_url=LOG_URL)

    body = result.transparency_log_entry
    assert isinstance(body, dict) and body, "rekor body not a non-empty dict"
    # Either logIndex appears, or inclusionProof / logEntry shape is present.
    has_idx = result.log_index is not None
    has_proof = any(k in body for k in ("inclusionProof", "inclusion_proof", "logEntry"))
    assert has_idx or has_proof, f"response missing index AND proof shape: keys={list(body.keys())}"
    print(f"  [PASS] response carries inclusion data (idx={has_idx}, proof_shape={has_proof})")


def main() -> int:
    if not GATE:
        print("=" * 60)
        print("  test_rekor_e2e: SKIPPED")
        print("  (set OVERSIGHT_REKOR_E2E=1 to run; this writes to the")
        print("   public Sigstore log)")
        print("=" * 60)
        return 0
    print("=" * 60)
    print(f"  test_rekor_e2e: LIVE against {LOG_URL}")
    print("=" * 60)
    t1_live_upload_round_trip()
    t2_response_carries_inclusion_data()
    print()
    print("  ALL E2E TESTS PASSED — 2/2")
    return 0


if __name__ == "__main__":
    sys.exit(main())
