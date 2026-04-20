#!/usr/bin/env python3
"""Focused tests for L3 safety policy."""

import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from oversight_core import l3_policy, watermark


def ok(msg: str) -> None:
    print(f"  [PASS] {msg}")


def t1_risky_documents_default_l3_off():
    text = "The system MUST verify every request. SELECT * FROM users;"
    decision = l3_policy.decide_l3(
        filename="api-spec.md",
        content_type="text/markdown",
        text=text,
        requested_mode="auto",
    )
    assert not decision.enabled
    assert decision.document_class == "technical_spec"
    ok("technical/spec content disables L3 by default")


def t2_full_l3_requires_ack_metadata():
    decision = l3_policy.decide_l3(
        filename="brief.txt",
        content_type="text/plain",
        text="This report will begin with a large review and explain the issue.",
        requested_mode="full",
    )
    assert decision.enabled
    assert decision.requires_ack
    assert decision.mode == "full"
    ok("explicit full L3 returns acknowledgement-required decision")


def t3_safe_l3_preserves_protected_lines():
    mark_id = watermark.new_mark_id()
    original = (
        "The Vendor MUST provide 5 kg by Friday.\n"
        "This report will begin with a large review and explain the issue for Alice.\n"
        "    SELECT * FROM users;\n"
    )
    marked = l3_policy.apply_l3_safe(original, mark_id, mode="full")
    assert "The Vendor MUST provide 5 kg by Friday." in marked
    assert "Alice" in marked
    assert "    SELECT * FROM users;" in marked
    assert marked != original
    ok("safe L3 preserves RFC2119/numeric/code lines while marking prose")


if __name__ == "__main__":
    print("=" * 60)
    print("oversight_core.l3_policy - focused unit tests")
    print("=" * 60)
    t1_risky_documents_default_l3_off()
    t2_full_l3_requires_ack_metadata()
    t3_safe_l3_preserves_protected_lines()
    print("\n  ALL TESTS PASSED - 3/3")
