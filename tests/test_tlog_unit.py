"""
test_tlog_unit
==============

Focused transparency-log checks around RFC 6962 behavior.
"""
from __future__ import annotations

import hashlib
import shutil
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oversight_core.tlog import TransparencyLog


def ok(msg):
    print(f"  [PASS] {msg}")


def t1_empty_tree_root_matches_rfc6962():
    td = ROOT / ".tmp-tests" / f"tlog-{uuid.uuid4().hex}"
    td.mkdir(parents=True, exist_ok=False)
    try:
        tlog = TransparencyLog(td)
        assert tlog.size() == 0
        assert tlog.root() == hashlib.sha256(b"").digest()
    finally:
        shutil.rmtree(td, ignore_errors=True)
    ok("empty transparency log root matches RFC 6962")


def main():
    tmp_root = ROOT / ".tmp-tests"
    tmp_root.mkdir(exist_ok=True)
    print("=" * 60)
    print("  oversight_core.tlog - focused unit tests")
    print("=" * 60)
    t1_empty_tree_root_matches_rfc6962()
    print()
    print("  ALL TESTS PASSED - 1/1")


if __name__ == "__main__":
    main()
