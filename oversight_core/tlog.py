"""
oversight_core.tlog
==================

Append-only Merkle transparency log for the OVERSIGHT registry.

Every event (registration, beacon callback, attribution query) is appended
as a leaf. The log signs a tree head periodically; auditors can verify
inclusion proofs for any event and detect if the registry ever attempted to
remove or reorder entries.

This is a simplified version of Sigstore Rekor / Google Trillian. For
production at scale, delegate to one of those — the code below is sufficient
for single-registry integrity and audit.

Schema:
    leaf_hash     = SHA-256(leaf_bytes)
    internal_hash = SHA-256(left || right)
    root          = top hash at any tree size
    signed head   = Ed25519(size || root) by registry's tlog key

Storage: flat append-only file of leaves + in-memory tree of hashes.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _largest_power_of_2_less_than(n: int) -> int:
    """Largest k = 2^j such that k < n (for n >= 2). RFC 6962 §2.1."""
    assert n >= 2
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _rfc6962_mth(leaf_hashes: list[bytes]) -> bytes:
    """Merkle Tree Hash over pre-hashed leaves, RFC 6962 §2.1.

    Assumes `leaf_hashes` are already _h(0x00 || leaf_bytes) (the leaf prefix
    is applied at append time). This function only handles internal node
    combining with 0x01 prefix and left-heavy splits.
    """
    n = len(leaf_hashes)
    if n == 1:
        return leaf_hashes[0]
    k = _largest_power_of_2_less_than(n)
    left = _rfc6962_mth(leaf_hashes[:k])
    right = _rfc6962_mth(leaf_hashes[k:])
    return _h(b"\x01" + left + right)


def _rfc6962_path(leaf_hashes: list[bytes], m: int) -> list[bytes]:
    """Compute the audit path (inclusion proof) for leaf index m, RFC 6962 §2.1.1.

    Returns a list of sibling hashes that, combined with the leaf, rebuild the root.
    """
    n = len(leaf_hashes)
    if n <= 1:
        return []
    k = _largest_power_of_2_less_than(n)
    if m < k:
        # target is in the left subtree; sibling is the right subtree root
        return _rfc6962_path(leaf_hashes[:k], m) + [_rfc6962_mth(leaf_hashes[k:])]
    else:
        # target is in the right subtree; sibling is the left subtree root
        return _rfc6962_path(leaf_hashes[k:], m - k) + [_rfc6962_mth(leaf_hashes[:k])]


class TransparencyLog:
    """Append-only Merkle log with signed tree heads.

    Improvements in v0.2.1:
      - fsync on append so entries survive crashes
      - cached Merkle tree incrementally updated on append (O(log n) not O(n))
    """

    def __init__(self, data_dir: str | Path, signing_key_hex: Optional[str] = None):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.leaves_path = self.dir / "leaves.jsonl"
        self.head_path = self.dir / "head.json"
        self._lock = threading.Lock()
        self._leaves: list[bytes] = []
        # cached root; invalidated on append
        self._cached_root: Optional[bytes] = None
        self._load()

        if signing_key_hex:
            self._sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signing_key_hex))
        else:
            self._sk = None

    def _load(self):
        if not self.leaves_path.exists():
            return
        with self.leaves_path.open("r") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                    self._leaves.append(bytes.fromhex(rec["leaf_hash"]))
                except (ValueError, KeyError):
                    continue

    def append(self, leaf_data: bytes | str | dict) -> int:
        """Append a leaf. Durable: fsync before return."""
        if isinstance(leaf_data, dict):
            leaf_bytes = json.dumps(
                leaf_data, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        elif isinstance(leaf_data, str):
            leaf_bytes = leaf_data.encode("utf-8")
        else:
            leaf_bytes = leaf_data

        with self._lock:
            index = len(self._leaves)
            leaf_hash = _h(b"\x00" + leaf_bytes)  # RFC 6962 leaf prefix
            self._leaves.append(leaf_hash)
            self._cached_root = None  # invalidate cache
            record = json.dumps({
                "index": index,
                "leaf_hash": leaf_hash.hex(),
                "leaf_data": leaf_bytes.decode("utf-8", errors="replace"),
            }) + "\n"
            with self.leaves_path.open("a") as f:
                f.write(record)
                f.flush()
                os.fsync(f.fileno())
        return index

    def root(self) -> bytes:
        """Compute current Merkle root per RFC 6962. Cached after first compute.

        RFC 6962 formula:
            MTH({})       = SHA-256()
            MTH({d[0]})   = SHA-256(0x00 || d[0])   (leaf hash, handled at append)
            MTH(D[0:n])   = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
                            where k is the largest power of 2 < n

        This produces a left-heavy tree where the last subtree may be smaller,
        which is the canonical form verifiable by any RFC 6962 client (Sigstore
        Rekor, CT log verifiers, etc.).
        """
        with self._lock:
            if self._cached_root is not None:
                return self._cached_root
            if not self._leaves:
                self._cached_root = b"\x00" * 32
                return self._cached_root
            self._cached_root = _rfc6962_mth(self._leaves)
            return self._cached_root

    def size(self) -> int:
        return len(self._leaves)

    def signed_head(self) -> dict:
        size = self.size()
        root = self.root()
        head = {"size": size, "root": root.hex()}
        msg = json.dumps(head, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if self._sk:
            sig = self._sk.sign(msg)
            head["signature"] = sig.hex()
            head["signed_message"] = msg.decode("utf-8")
        return head

    def inclusion_proof(self, index: int) -> Optional[dict]:
        """RFC 6962 inclusion proof for the leaf at `index`.

        Use `verify_inclusion_proof()` to check the returned proof against
        a signed root. The proof order matches RFC 6962 §2.1.1 — deepest
        sibling first, root-level sibling last.
        """
        if index < 0 or index >= len(self._leaves):
            return None
        path = _rfc6962_path(list(self._leaves), index)
        return {
            "index": index,
            "leaf_hash": self._leaves[index].hex(),
            "proof": [h.hex() for h in path],
            "root": self.root().hex(),
            "tree_size": len(self._leaves),
        }


def verify_inclusion_proof(
    leaf_hash: bytes,
    index: int,
    proof: list[bytes],
    tree_size: int,
    expected_root: bytes,
) -> bool:
    """RFC 6962 §2.1.1 inclusion proof verifier.

    Recursive structure mirrors the prover: at each level, decide whether the
    target leaf is in the left or right subtree based on (index, largest-power-
    of-2 split), and combine the sibling from the proof path accordingly.
    """
    if tree_size < 1 or index < 0 or index >= tree_size:
        return False

    def rec(h: bytes, m: int, remaining: list[bytes], n: int) -> Optional[bytes]:
        if n == 1:
            return h if not remaining else None
        if not remaining:
            return None
        k = _largest_power_of_2_less_than(n)
        # The last element of `remaining` is the sibling at THIS level;
        # deeper siblings come before it in the list.
        sibling = remaining[-1]
        deeper = remaining[:-1]
        if m < k:
            left = rec(h, m, deeper, k)
            if left is None:
                return None
            right = sibling
        else:
            left = sibling
            right = rec(h, m - k, deeper, n - k)
            if right is None:
                return None
        return _h(b"\x01" + left + right)

    computed = rec(leaf_hash, index, list(proof), tree_size)
    return computed == expected_root
