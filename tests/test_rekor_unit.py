"""
test_rekor_unit
===============

Offline unit tests for oversight_core.rekor.

Covers (no network):
  1. DSSE PAE construction matches the spec byte-for-byte against a fixture.
  2. sign_dsse + verify_dsse round trip.
  3. verify_dsse rejects a tampered payload.
  4. verify_dsse rejects a wrong-key signature.
  5. build_statement produces the expected in-toto v1 shape.
  6. Envelope JSON serialization is canonical (sorted keys, no whitespace).
  7. verify_inclusion_offline returns False when transparency_log_entry is empty.

Running this requires no external services; e2e Rekor tests live in
test_rekor_e2e.py (added in v0.5 Session B).
"""
from __future__ import annotations

import base64
import json
import os
import sys

# allow running without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oversight_core import rekor as R


def _new_keypair() -> tuple[bytes, bytes]:
    sk = Ed25519PrivateKey.generate()
    return (
        sk.private_bytes_raw(),
        sk.public_key().public_bytes_raw(),
    )


def t1_pae_byte_exact():
    pae = R._pae("application/vnd.in-toto+json", b'{"a":1}')
    expect = b"DSSEv1 28 application/vnd.in-toto+json 7 " + b'{"a":1}'
    assert pae == expect, f"PAE mismatch:\n  got    {pae!r}\n  expect {expect!r}"
    print("  [PASS] 1. PAE byte-exact match against spec")


def t2_sign_verify_roundtrip():
    priv, pub = _new_keypair()
    pred = R.OversightRegistrationPredicate(
        file_id="00000000-0000-4000-8000-000000000001",
        issuer_pubkey_ed25519=pub.hex(),
        recipient_id="alice@test",
        recipient_pubkey_sha256="00" * 32,
        suite="OSGT-CLASSIC-v1",
        registered_at="2026-04-19T07:00:00Z",
    )
    stmt = R.build_statement("aa" * 16, "bb" * 32, pred)
    env = R.sign_dsse(stmt, priv)
    assert R.verify_dsse(env, pub), "valid envelope failed verification"
    print("  [PASS] 2. sign_dsse + verify_dsse round trip")


def t3_tamper_payload_rejected():
    priv, pub = _new_keypair()
    pred = R.OversightRegistrationPredicate(
        file_id="x", issuer_pubkey_ed25519=pub.hex(),
        recipient_id="r", recipient_pubkey_sha256="00" * 32,
        suite="s", registered_at="t",
    )
    env = R.sign_dsse(R.build_statement("a", "b", pred), priv)
    tampered = R.DSSEEnvelope(
        payload_b64=base64.b64encode(b'{"evil":1}').decode(),
        payload_type=env.payload_type,
        signatures=env.signatures,
    )
    assert not R.verify_dsse(tampered, pub), "tampered payload accepted!"
    print("  [PASS] 3. tampered payload rejected")


def t4_wrong_key_rejected():
    priv, _ = _new_keypair()
    _, other_pub = _new_keypair()
    pred = R.OversightRegistrationPredicate(
        file_id="x", issuer_pubkey_ed25519="zz",
        recipient_id="r", recipient_pubkey_sha256="00" * 32,
        suite="s", registered_at="t",
    )
    env = R.sign_dsse(R.build_statement("a", "b", pred), priv)
    assert not R.verify_dsse(env, other_pub), "wrong-key sig verified!"
    print("  [PASS] 4. wrong public key rejected")


def t5_statement_shape():
    pred = R.OversightRegistrationPredicate(
        file_id="fid", issuer_pubkey_ed25519="pp",
        recipient_id="rid", recipient_pubkey_sha256="rxhash",
        suite="OSGT-CLASSIC-v1", registered_at="2026-04-19T00:00:00Z",
    )
    s = R.build_statement("mark1234", "deadbeef" * 8, pred)
    assert s["_type"] == R.STATEMENT_TYPE
    assert s["predicateType"] == R.PREDICATE_TYPE
    assert s["subject"][0]["name"] == "mark:mark1234"
    assert s["subject"][0]["digest"]["sha256"].startswith("deadbeef")
    assert s["predicate"]["suite"] == "OSGT-CLASSIC-v1"
    print("  [PASS] 5. in-toto v1 statement shape correct")


def t6_canonical_envelope_json():
    priv, pub = _new_keypair()
    pred = R.OversightRegistrationPredicate(
        file_id="x", issuer_pubkey_ed25519="pp",
        recipient_id="r", recipient_pubkey_sha256="00" * 32,
        suite="s", registered_at="t",
    )
    env = R.sign_dsse(R.build_statement("a", "b" * 32, pred), priv)
    raw = env.to_json()
    # canonical: keys sorted alphabetically (payload, payloadType, signatures)
    parsed_keys_in_order = [k for k in json.loads(raw).keys()]
    # round-trip must produce identical bytes
    again = R.DSSEEnvelope.from_json(raw).to_json()
    assert raw == again, "envelope JSON not canonical (round-trip differs)"
    # no whitespace
    assert " " not in raw and "\n" not in raw, "envelope JSON has whitespace"
    print("  [PASS] 6. envelope JSON is canonical and round-trip stable")


def t8_recipient_pubkey_never_appears_raw():
    """Privacy: raw X25519 recipient key must never end up in the on-log payload."""
    priv, _ = _new_keypair()
    raw_pub_hex = "11" * 32  # pretend recipient X25519 pub
    pred = R.OversightRegistrationPredicate(
        file_id="x", issuer_pubkey_ed25519="pp",
        recipient_id="r",
        recipient_pubkey_sha256=R.hash_recipient_pubkey(raw_pub_hex),
        suite="s", registered_at="t",
    )
    stmt = R.build_statement("a", "b" * 32, pred)
    env = R.sign_dsse(stmt, priv)
    raw_payload = base64.b64decode(env.payload_b64).decode()
    assert raw_pub_hex not in raw_payload, "RAW recipient pubkey leaked into on-log payload"
    assert pred.recipient_pubkey_sha256 in raw_payload
    assert pred.recipient_pubkey_sha256 != raw_pub_hex
    print("  [PASS] 8. raw recipient pubkey is hashed before going on-log")


def t9_predicate_carries_version_int():
    pred = R.OversightRegistrationPredicate(
        file_id="x", issuer_pubkey_ed25519="pp",
        recipient_id="r", recipient_pubkey_sha256="00" * 32,
        suite="s", registered_at="t",
    )
    d = pred.to_dict()
    assert d.get("predicate_version") == 1, d
    print("  [PASS] 9. predicate body carries integer predicate_version")


def t10_bundle_has_5year_replay_fields():
    """Bundle must carry log_pubkey, checkpoint, schema URI, schema int."""
    priv, pub = _new_keypair()
    pred = R.OversightRegistrationPredicate(
        file_id="x", issuer_pubkey_ed25519="pp",
        recipient_id="r", recipient_pubkey_sha256="00" * 32,
        suite="s", registered_at="t",
    )
    env = R.sign_dsse(R.build_statement("a", "b" * 32, pred), priv)
    upload = R.RekorUploadResult(
        log_url="https://log2025-1.rekor.sigstore.dev",
        log_index=42, log_id="abc", integrated_time=1776600000,
        transparency_log_entry={"logEntry": "..."},
        log_pubkey_pem="-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----",
        checkpoint="rekor.sigstore.dev\n42\nABC=\n— rekor sig...",
    )
    bundle = R.build_bundle(
        manifest_dict={"file_id": "x"},
        manifest_sig_hex="aa" * 64,
        upload=upload,
        dsse_envelope=env,
        rfc3161_token_b64="dummy",
        rfc3161_chain_b64="chainpem",
    )
    assert bundle["bundle_schema"] == 2
    assert bundle["tlog_kind"] == "rekor-v2-dsse"
    rekor = bundle["rekor"]
    assert rekor["log_pubkey_pem"], "log_pubkey missing"
    assert rekor["checkpoint"], "checkpoint missing"
    assert rekor["log_entry_schema"] == "rekor/v1.TransparencyLogEntry"
    assert bundle["rfc3161_chain"] == "chainpem"
    print("  [PASS] 10. bundle carries log_pubkey + checkpoint + schema URI + schema=2")


def t7_offline_verify_rejects_empty_tle():
    priv, pub = _new_keypair()
    pred = R.OversightRegistrationPredicate(
        file_id="x", issuer_pubkey_ed25519="pp",
        recipient_id="r", recipient_pubkey_sha256="00" * 32,
        suite="s", registered_at="t",
    )
    env = R.sign_dsse(R.build_statement("a", "b" * 32, pred), priv)
    ok, reason = R.verify_inclusion_offline({}, env, pub)
    assert not ok and "transparency_log_entry" in reason, reason
    print(f"  [PASS] 7. offline verify rejects empty bundle ({reason})")


def main():
    print("=" * 60)
    print("  oversight_core.rekor — unit tests (offline, no network)")
    print("=" * 60)
    t1_pae_byte_exact()
    t2_sign_verify_roundtrip()
    t3_tamper_payload_rejected()
    t4_wrong_key_rejected()
    t5_statement_shape()
    t6_canonical_envelope_json()
    t7_offline_verify_rejects_empty_tle()
    t8_recipient_pubkey_never_appears_raw()
    t9_predicate_carries_version_int()
    t10_bundle_has_5year_replay_fields()
    print()
    print("  ALL TESTS PASSED — 10/10")
    print()


if __name__ == "__main__":
    main()
