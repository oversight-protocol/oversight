"""
oversight_core.policy
====================

Policy enforcement at open time.

The manifest carries a `policy` dict with optional fields:
    not_after        : unix seconds; decryption refused after this time
    not_before       : unix seconds; decryption refused before this time (defer release)
    max_opens        : int; decryption refused after this many successful opens
    jurisdiction     : str; required jurisdiction profile (enforced against opener config)
    require_attestation : bool; reserved for TEE integration
    registry_url     : str; used for open-counter increments

Enforcement modes:
    LOCAL_ONLY   : policy_state is read/written in a local file (single-user, stub)
    REGISTRY     : policy_state kept in registry; increments require a network roundtrip
    HYBRID       : prefer registry; fall back to local if offline (with auditable note)

The LOCAL_ONLY mode is not secure against a determined attacker who tampers with
the state file. It exists for MVP plumbing. REGISTRY is the real answer.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .manifest import Manifest


class PolicyViolation(Exception):
    """Raised when a .sealed file's policy forbids the attempted open."""


@dataclass
class PolicyContext:
    """State the opener needs to enforce policy. Typically constructed from env/config."""
    jurisdiction: str = "GLOBAL"
    state_dir: Optional[Path] = None  # for LOCAL_ONLY open-counter persistence
    registry_url: Optional[str] = None  # for REGISTRY mode
    mode: str = "LOCAL_ONLY"           # LOCAL_ONLY | REGISTRY | HYBRID

    def __post_init__(self):
        if self.state_dir:
            self.state_dir = Path(self.state_dir)
            self.state_dir.mkdir(parents=True, exist_ok=True)


def _local_counter_path(ctx: PolicyContext, file_id: str) -> Path:
    if ctx.state_dir is None:
        raise ValueError("PolicyContext.state_dir is required for LOCAL_ONLY mode")
    # file_id is a UUID string — defense against path traversal:
    if "/" in file_id or "\\" in file_id or ".." in file_id:
        raise ValueError(f"invalid file_id for counter filename: {file_id!r}")
    return ctx.state_dir / f"{file_id}.opens.json"


def _local_read_count(ctx: PolicyContext, file_id: str) -> int:
    p = _local_counter_path(ctx, file_id)
    if not p.exists():
        return 0
    try:
        return int(json.loads(p.read_text()).get("count", 0))
    except (OSError, ValueError, TypeError):
        return 0


def _local_check_and_bump(ctx: PolicyContext, file_id: str, max_opens: int) -> int:
    """
    Atomically: check count < max_opens AND bump. Uses an OS file lock
    on a sidecar .lock file to serialize concurrent openers of the same file,
    plus write-to-temp-then-rename for crash-consistency.
    Raises PolicyViolation if max_opens reached.
    Returns the new count.
    """
    import fcntl  # POSIX only; Windows would need msvcrt.locking.
    import tempfile

    p = _local_counter_path(ctx, file_id)
    lock_path = p.with_suffix(".lock")
    # Open/create lock file, acquire exclusive lock for the critical section.
    with open(lock_path, "a+") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            cur = _local_read_count(ctx, file_id)
            if cur >= max_opens:
                raise PolicyViolation(
                    f"Open limit reached: max_opens={max_opens}, already opened {cur} times"
                )
            new_count = cur + 1
            # Atomic write: write to a temp file in the same directory, then rename.
            fd, tmp = tempfile.mkstemp(
                prefix=f".{file_id}.opens.",
                suffix=".tmp",
                dir=str(ctx.state_dir),
            )
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump({"count": new_count, "last": int(time.time())}, f)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, p)
            except Exception:
                # Clean up temp if rename failed
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            return new_count
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def check_policy(manifest: Manifest, ctx: Optional[PolicyContext] = None) -> None:
    """
    Raise PolicyViolation if the manifest's policy forbids the current open.
    Called BEFORE decryption to fail-fast.

    Note: open-counter enforcement is SKIPPED here and done atomically in
    record_open to prevent TOCTOU races. check_policy only does cheap
    read-only checks (time, jurisdiction).
    """
    policy = manifest.policy or {}
    now = int(time.time())

    na = policy.get("not_after")
    if na is not None and now > int(na):
        raise PolicyViolation(
            f"File expired: not_after={na}, now={now} "
            f"({(now - int(na))//3600}h ago)"
        )
    nb = policy.get("not_before")
    if nb is not None and now < int(nb):
        raise PolicyViolation(
            f"File not yet released: not_before={nb}, now={now} "
            f"(available in {(int(nb) - now)//60}m)"
        )

    required = policy.get("jurisdiction")
    if required and required != "GLOBAL" and ctx is not None:
        if required != ctx.jurisdiction:
            raise PolicyViolation(
                f"Jurisdiction mismatch: file requires '{required}', "
                f"opener is in '{ctx.jurisdiction}'"
            )

    # max_opens is enforced atomically in record_open, not here.


def record_open(manifest: Manifest, ctx: Optional[PolicyContext]) -> int:
    """
    Atomically check-and-bump the open counter (if policy has max_opens).
    Raises PolicyViolation if the limit is exceeded. Returns new count.
    """
    if ctx is None:
        return 0
    policy = manifest.policy or {}
    mx = policy.get("max_opens")
    if mx is None:
        return 0
    if ctx.mode == "LOCAL_ONLY":
        return _local_check_and_bump(ctx, manifest.file_id, int(mx))
    # REGISTRY/HYBRID — caller should POST to registry /policy/open
    return _local_check_and_bump(ctx, manifest.file_id, int(mx))
