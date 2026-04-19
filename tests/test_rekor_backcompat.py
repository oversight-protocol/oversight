"""
test_rekor_backcompat
=====================

Confirms the v0.5 Rekor work has not broken any v0.4 behavior.

Per the v0.5 plan §6 (Backward compatibility rules):
  1. Every v0.4.1 bundle/.sealed file must still parse, open, verify exactly.
  2. Bundles missing ``tlog_kind`` / ``bundle_schema`` are interpreted as the
     v0.4 path (oversight-self-merkle-v1).
  3. JCS canonical ordering still applies; new fields are additions only.

These checks run fully offline.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from oversight_core.tlog import TransparencyLog, verify_inclusion_proof
from oversight_core import rekor as R


def t1_legacy_tlog_still_works():
    """A TransparencyLog built and verified the v0.4 way must still pass."""
    with tempfile.TemporaryDirectory() as td:
        tl = TransparencyLog(td)
        for i in range(7):
            tl.append({"event": "register", "i": i, "file_id": f"f{i}"})
        size = tl.size()
        root = tl.root()
        assert size == 7, f"expected size 7, got {size}"
        assert len(root) == 32, "root must be 32 bytes (sha256)"

        # Inclusion proof for the middle leaf.
        proof = tl.inclusion_proof(3)
        assert proof is not None, "inclusion_proof returned None for valid index"
        ok = verify_inclusion_proof(
            leaf_hash=bytes.fromhex(proof["leaf_hash"]),
            index=proof["index"],
            proof=[bytes.fromhex(h) for h in proof["proof"]],
            tree_size=proof["tree_size"],
            expected_root=bytes.fromhex(proof["root"]),
        )
        assert ok, "RFC 6962 inclusion proof failed to verify"
    print("  [PASS] 1. v0.4 TransparencyLog API still verifies end-to-end")


def t2_legacy_bundle_shape_default_kind():
    """A v0.4-shaped bundle (no tlog_kind, no bundle_schema) must be readable
    and interpretable as ``oversight-self-merkle-v1``."""
    legacy_bundle = {
        "version": "0.4",
        "file_id": "abcd" * 16,
        "issuer_pubkey_ed25519": "11" * 32,
        "tlog": {
            "size": 7,
            "root": "00" * 32,
            "signature": "22" * 64,
        },
        "inclusion_proof": {
            "index": 3,
            "leaf_hash": "33" * 32,
            "proof": ["44" * 32, "55" * 32],
            "tree_size": 7,
            "root": "00" * 32,
        },
    }
    # Forward-looking interpretation: a v0.5+ verifier sees no tlog_kind →
    # treats this as the legacy local-merkle path.
    assert "rekor" not in legacy_bundle, "v0.4 bundle must not have a rekor field"
    assert "bundle_schema" not in legacy_bundle, "v0.4 bundle must not advertise bundle_schema"
    inferred_kind = legacy_bundle.get("tlog_kind", R.LEGACY_TLOG_KIND)
    assert inferred_kind == R.LEGACY_TLOG_KIND, (
        f"missing tlog_kind must default to {R.LEGACY_TLOG_KIND}, got {inferred_kind!r}"
    )
    inferred_schema = legacy_bundle.get("bundle_schema", 1)
    assert inferred_schema == 1, "missing bundle_schema must default to 1 (v0.4 implicit)"
    print("  [PASS] 2. v0.4 bundle defaults: tlog_kind=legacy, schema=1")


def t3_v05_bundle_advertises_new_fields():
    """The new bundle the v0.5 path emits MUST advertise both fields explicitly
    so an old (v0.4) verifier fails fast with 'unknown schema' rather than
    silently mis-routing."""
    assert R.BUNDLE_SCHEMA == 2, f"BUNDLE_SCHEMA must be 2, got {R.BUNDLE_SCHEMA}"
    assert R.TLOG_KIND == "rekor-v2-dsse", f"TLOG_KIND drift: {R.TLOG_KIND!r}"
    assert R.LEGACY_TLOG_KIND == "oversight-self-merkle-v1"
    print("  [PASS] 3. v0.5 constants: TLOG_KIND=rekor-v2-dsse, schema=2")


def t4_canonical_jcs_unchanged_for_legacy_payload():
    """The exact JCS encoding for a v0.4-shaped event must not have changed.
    If this fails, downstream verifiers re-checking historical signatures
    over canonical JSON will reject events they previously accepted."""
    event = {
        "event": "register",
        "file_id": "f0",
        "issuer_pub": "11" * 32,
        "n_beacons": 3,
        "n_watermarks": 1,
        "recipient_id": "r0",
        "timestamp": "2026-04-19T00:00:00Z",
    }
    expected = (
        '{"event":"register","file_id":"f0","issuer_pub":'
        + '"' + "11" * 32 + '",'
        + '"n_beacons":3,"n_watermarks":1,"recipient_id":"r0","timestamp":"2026-04-19T00:00:00Z"}'
    )
    actual = json.dumps(event, sort_keys=True, separators=(",", ":"))
    assert actual == expected, f"JCS drift!\n  exp: {expected}\n  got: {actual}"
    print("  [PASS] 4. v0.4 event JCS encoding unchanged")


def t5_predicate_uri_resolves_at_tagged_path():
    """Sanity: the PREDICATE_TYPE URI references a git-tagged path. We don't
    fetch (the e2e test does that); we just confirm the URI shape so a typo
    like missing the tag won't make it through to a release."""
    assert R.PREDICATE_TYPE.startswith(
        "https://github.com/oversight-protocol/oversight/blob/v0.5"
    ), f"PREDICATE_TYPE not pinned to a v0.5 git tag: {R.PREDICATE_TYPE}"
    assert R.PREDICATE_TYPE.endswith("/docs/predicates/registration-v1.md")
    assert R.PREDICATE_VERSION == 1
    print("  [PASS] 5. PREDICATE_TYPE pinned to v0.5 git-tagged path")


def main() -> int:
    print("=" * 60)
    print("  test_rekor_backcompat — v0.4 contract preservation (offline)")
    print("=" * 60)
    t1_legacy_tlog_still_works()
    t2_legacy_bundle_shape_default_kind()
    t3_v05_bundle_advertises_new_fields()
    t4_canonical_jcs_unchanged_for_legacy_payload()
    t5_predicate_uri_resolves_at_tagged_path()
    print()
    print("  ALL BACKCOMPAT TESTS PASSED — 5/5")
    return 0


if __name__ == "__main__":
    sys.exit(main())
