"""
test_registry_unit
==================

Focused registry checks around Rekor attestation construction.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import sys
import uuid
from types import SimpleNamespace

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

import registry.server as registry_server
from fastapi import HTTPException
from oversight_core.tlog import TransparencyLog


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


def t2_register_rejects_unsigned_sidecar_mismatch():
    manifest = {
        "beacons": [
            {"token_id": "tok-1", "kind": "http_img", "url": "https://b.example/p/tok-1.png"},
        ],
        "watermarks": [
            {"layer": "L1_zero_width", "mark_id": "10" * 16},
        ],
    }
    try:
        registry_server._signed_registration_artifacts(
            manifest,
            req_beacons=[
                {"token_id": "tok-evil", "kind": "http_img", "url": "https://b.example/p/tok-evil.png"},
            ],
            req_watermarks=manifest["watermarks"],
        )
    except HTTPException as exc:
        assert exc.status_code == 400
        assert "beacons do not match" in exc.detail
    else:
        raise AssertionError("unsigned request beacons should be rejected")

    try:
        registry_server._signed_registration_artifacts(
            manifest,
            req_beacons=manifest["beacons"],
            req_watermarks=[
                {"layer": "L2_whitespace", "mark_id": "20" * 16},
            ],
        )
    except HTTPException as exc:
        assert exc.status_code == 400
        assert "watermarks do not match" in exc.detail
    else:
        raise AssertionError("unsigned request watermarks should be rejected")
    print("  [PASS] register rejects unsigned beacon/watermark sidecars")


def _fake_request(host: str, headers: dict[str, str] | None = None):
    return SimpleNamespace(
        client=SimpleNamespace(host=host),
        headers=headers or {},
    )


def t3_dns_event_requires_secret_for_non_loopback():
    original_secret = registry_server.DNS_EVENT_SECRET
    try:
        registry_server.DNS_EVENT_SECRET = ""
        registry_server._verify_dns_event_auth(_fake_request("127.0.0.1"))
        try:
            registry_server._verify_dns_event_auth(_fake_request("203.0.113.10"))
        except HTTPException as exc:
            assert exc.status_code == 503
            assert "OVERSIGHT_DNS_EVENT_SECRET" in exc.detail
        else:
            raise AssertionError("public DNS callbacks should fail closed without a secret")

        registry_server.DNS_EVENT_SECRET = "shared-secret"
        registry_server._verify_dns_event_auth(
            _fake_request("203.0.113.10", {"x-oversight-dns-secret": "shared-secret"})
        )
        try:
            registry_server._verify_dns_event_auth(
                _fake_request("203.0.113.10", {"x-oversight-dns-secret": "wrong"})
            )
        except HTTPException as exc:
            assert exc.status_code == 401
        else:
            raise AssertionError("wrong DNS callback secret should be rejected")
    finally:
        registry_server.DNS_EVENT_SECRET = original_secret
    print("  [PASS] dns_event rejects unauthenticated non-loopback callbacks")


def t4_evidence_bundle_can_attach_tlog_proofs():
    original_tlog = registry_server.TLOG
    td = os.path.join(ROOT, ".tmp-tests", f"registry-tlog-{uuid.uuid4().hex}")
    os.makedirs(td, exist_ok=False)
    try:
        registry_server.TLOG = TransparencyLog(td)
        first = registry_server.TLOG.append({"event": "register", "file_id": "f"})
        second = registry_server.TLOG.append({"event": "beacon", "file_id": "f"})
        proofs = registry_server._tlog_proofs_for_events([
            {"kind": "register", "tlog_index": first},
            {"kind": "beacon", "tlog_index": second},
            {"kind": "offline", "tlog_index": -1},
        ])
    finally:
        registry_server.TLOG = original_tlog
        shutil.rmtree(td, ignore_errors=True)

    assert [p["event_row"] for p in proofs] == [0, 1]
    assert [p["tlog_index"] for p in proofs] == [first, second]
    assert all(p["proof"]["root"] for p in proofs)
    print("  [PASS] evidence bundles attach tlog inclusion proofs for events")


def t5_operator_token_gates_write_side_apis_when_configured():
    original_token = registry_server.OPERATOR_TOKEN
    try:
        registry_server.OPERATOR_TOKEN = ""
        registry_server._require_operator_auth(_fake_request("203.0.113.10"))

        registry_server.OPERATOR_TOKEN = "operator-secret"
        registry_server._require_operator_auth(
            _fake_request("203.0.113.10", {"authorization": "Bearer operator-secret"})
        )
        registry_server._require_operator_auth(
            _fake_request("203.0.113.10", {"x-oversight-operator-token": "operator-secret"})
        )
        try:
            registry_server._require_operator_auth(
                _fake_request("203.0.113.10", {"authorization": "Bearer wrong"})
            )
        except HTTPException as exc:
            assert exc.status_code == 401
        else:
            raise AssertionError("wrong operator token should be rejected")
    finally:
        registry_server.OPERATOR_TOKEN = original_token
    print("  [PASS] optional operator token gates write-side APIs")


def main():
    print("=" * 60)
    print("  registry.server - focused unit tests")
    print("=" * 60)
    t1_rekor_attestation_uses_real_mark_id_and_digest()
    t2_register_rejects_unsigned_sidecar_mismatch()
    t3_dns_event_requires_secret_for_non_loopback()
    t4_evidence_bundle_can_attach_tlog_proofs()
    t5_operator_token_gates_write_side_apis_when_configured()
    print()
    print("  ALL TESTS PASSED - 5/5")


if __name__ == "__main__":
    main()
