"""
test_registry_unit
==================

Focused registry checks around Rekor attestation construction.
"""
from __future__ import annotations

import base64
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

import registry.server as registry_server


def _new_identity() -> dict:
    sk = Ed25519PrivateKey.generate()
    return {
        "ed25519_priv": sk.private_bytes_raw().hex(),
        "ed25519_pub": sk.public_key().public_bytes_raw().hex(),
    }


def t1_rekor_attestation_uses_real_mark_id_and_digest():
    original_identity = registry_server.IDENTITY
    original_enabled = registry_server.REKOR_ENABLED
    original_upload = registry_server.rekor_mod.upload_dsse
    registry_server.IDENTITY = _new_identity()
    registry_server.REKOR_ENABLED = True
    captured = {}

    def fake_upload(envelope, issuer_ed25519_pub_pem, log_url):
        captured["statement"] = json.loads(
            base64.b64decode(envelope.payload_b64).decode("utf-8")
        )
        serialization.load_pem_public_key(issuer_ed25519_pub_pem.encode("ascii"))
        return type(
            "FakeResult",
            (),
            {
                "log_url": log_url,
                "log_index": 7,
                "log_id": "rekor-log",
                "integrated_time": 1776643200,
            },
        )()

    registry_server.rekor_mod.upload_dsse = fake_upload
    try:
        result = registry_server._attest_to_rekor(
            file_id="file-123",
            issuer_pub_hex="aa" * 32,
            recipient_id="recipient-1",
            recipient_pubkey_hex="11" * 32,
            suite="OSGT-CLASSIC-v1",
            content_hash_sha256_hex="bb" * 32,
            watermarks=[
                {"layer": "L1_zero_width", "mark_id": "10" * 16},
                {"layer": "L2_whitespace", "mark_id": "20" * 16},
            ],
            mark_id_hex="10" * 16,
        )
    finally:
        registry_server.IDENTITY = original_identity
        registry_server.REKOR_ENABLED = original_enabled
        registry_server.rekor_mod.upload_dsse = original_upload

    statement = captured["statement"]
    assert statement["subject"][0]["name"] == "mark:" + ("10" * 16)
    assert statement["subject"][0]["digest"]["sha256"] == "bb" * 32
    assert statement["predicate"]["watermarks"] == {
        "L1_zero_width": "10" * 16,
        "L2_whitespace": "20" * 16,
    }
    assert result["log_index"] == 7
    print("  [PASS] registry attests using a real mark_id and content_hash")


def main():
    print("=" * 60)
    print("  registry.server - focused unit tests")
    print("=" * 60)
    t1_rekor_attestation_uses_real_mark_id_and_digest()
    print()
    print("  ALL TESTS PASSED - 1/1")


if __name__ == "__main__":
    main()
