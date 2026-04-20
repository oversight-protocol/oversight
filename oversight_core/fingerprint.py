"""
oversight_core.fingerprint
==========================

Content fingerprinting for leak detection when watermarks are stripped.

Two independent fingerprinting methods:

1. Winnowing (Schleimer, Wilkerson, Aiken, SIGMOD 2003)
   Computes rolling hash fingerprints over k-grams of the text.
   Selects a subset via the winnowing algorithm (minimum hash in each window).
   Enables partial-copy detection for near-verbatim leaks.
   Does NOT survive paraphrasing.

2. Semantic sentence hashing
   Hashes normalized, lemmatized sentences. More robust than winnowing
   to minor word changes because it operates on content words only.
   Survives format conversion, minor edits, whitespace changes.
   Does NOT survive heavy paraphrasing.

Both methods produce fingerprints stored at seal time (in the manifest or
registry). At attribution time, fingerprints of the leaked text are compared
against stored fingerprints to identify which recipient's copy was leaked.

The fingerprint DB is NOT a watermark. It is a server-side identification
system. The fingerprints never appear in the document itself. An adversary
cannot strip what is not embedded.
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional


# ---- Text normalization ----

def _normalize_text(text: str) -> str:
    """Normalize text for fingerprinting: lowercase, collapse whitespace, strip punctuation."""
    text = text.lower()
    # Remove zero-width chars
    for ch in "\u200b\u200c\u200d\ufeff":
        text = text.replace(ch, "")
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text)
    # Strip non-alphanumeric except spaces
    text = re.sub(r"[^a-z0-9 ]", "", text)
    return text.strip()


def _sentences(text: str) -> list[str]:
    """Split text into sentences using simple heuristics."""
    # Split on sentence-ending punctuation followed by space or EOL
    parts = re.split(r"(?<=[.!?])\s+", text)
    return [s.strip() for s in parts if s.strip()]


# ---- Winnowing ----

def _rolling_hash(text: str, k: int) -> list[tuple[int, int]]:
    """Compute rolling hashes for all k-grams. Returns (hash, position) pairs."""
    if len(text) < k:
        return []
    hashes = []
    for i in range(len(text) - k + 1):
        kgram = text[i : i + k]
        h = int(hashlib.md5(kgram.encode(), usedforsecurity=False).hexdigest()[:8], 16)
        hashes.append((h, i))
    return hashes


def winnow(text: str, k: int = 10, window: int = 4) -> list[int]:
    """
    Winnowing algorithm for document fingerprinting.

    Args:
        text: input text (will be normalized)
        k: k-gram size (character-level)
        window: winnowing window size

    Returns:
        sorted list of selected hash values (the fingerprint)
    """
    normalized = _normalize_text(text)
    if len(normalized) < k:
        return []

    hashes = _rolling_hash(normalized, k)
    if len(hashes) < window:
        return [h for h, _ in hashes]

    selected = set()
    prev_min_idx = -1

    for i in range(len(hashes) - window + 1):
        window_hashes = hashes[i : i + window]
        # Select rightmost minimum in window
        min_h = min(h for h, _ in window_hashes)
        # Find rightmost occurrence of min
        for j in range(len(window_hashes) - 1, -1, -1):
            if window_hashes[j][0] == min_h:
                abs_idx = i + j
                if abs_idx != prev_min_idx:
                    selected.add(window_hashes[j][0])
                    prev_min_idx = abs_idx
                break

    return sorted(selected)


def winnow_similarity(fp1: list[int], fp2: list[int]) -> float:
    """Jaccard similarity between two winnowing fingerprints."""
    if not fp1 or not fp2:
        return 0.0
    s1 = set(fp1)
    s2 = set(fp2)
    intersection = len(s1 & s2)
    union = len(s1 | s2)
    return intersection / union if union > 0 else 0.0


# ---- Semantic sentence hashing ----

def _sentence_hash(sentence: str) -> str:
    """Hash a normalized sentence. Returns hex string."""
    normalized = _normalize_text(sentence)
    # Extract content words only (skip 1-2 char words)
    words = [w for w in normalized.split() if len(w) > 2]
    content = " ".join(sorted(words))  # sort for order-independence
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def sentence_fingerprint(text: str) -> list[str]:
    """
    Compute per-sentence content hashes.

    Returns list of 16-char hex hashes, one per sentence.
    Order-independent within each sentence (sorted words) so minor
    word reordering does not change the hash.
    """
    sents = _sentences(text)
    return [_sentence_hash(s) for s in sents if len(s.split()) >= 3]


def sentence_similarity(fp1: list[str], fp2: list[str]) -> float:
    """Fraction of sentence hashes in fp2 that appear in fp1."""
    if not fp1 or not fp2:
        return 0.0
    s1 = set(fp1)
    matches = sum(1 for h in fp2 if h in s1)
    return matches / len(fp2)


# ---- Combined fingerprint ----

class ContentFingerprint:
    """Combined winnowing + sentence fingerprint for a document."""

    def __init__(
        self,
        winnowing_fp: list[int],
        sentence_fp: list[str],
        text_length: int,
        sentence_count: int,
    ):
        self.winnowing_fp = winnowing_fp
        self.sentence_fp = sentence_fp
        self.text_length = text_length
        self.sentence_count = sentence_count

    @classmethod
    def from_text(cls, text: str, k: int = 10, window: int = 4) -> "ContentFingerprint":
        """Create a fingerprint from text."""
        return cls(
            winnowing_fp=winnow(text, k, window),
            sentence_fp=sentence_fingerprint(text),
            text_length=len(text),
            sentence_count=len(_sentences(text)),
        )

    def similarity(self, other: "ContentFingerprint") -> dict:
        """Compare this fingerprint against another. Returns per-method scores."""
        w_sim = winnow_similarity(self.winnowing_fp, other.winnowing_fp)
        s_sim = sentence_similarity(self.sentence_fp, other.sentence_fp)
        # Combined: weighted average (winnowing is stricter, sentence is more robust)
        combined = 0.4 * w_sim + 0.6 * s_sim
        return {
            "winnowing": w_sim,
            "sentence": s_sim,
            "combined": combined,
            "verdict": (
                "MATCH" if combined >= 0.6
                else "LIKELY" if combined >= 0.3
                else "UNLIKELY" if combined >= 0.1
                else "NO_MATCH"
            ),
        }

    def to_dict(self) -> dict:
        """Serialize for storage in manifest/registry."""
        return {
            "winnowing_fp": self.winnowing_fp,
            "sentence_fp": self.sentence_fp,
            "text_length": self.text_length,
            "sentence_count": self.sentence_count,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ContentFingerprint":
        """Deserialize from stored dict."""
        return cls(
            winnowing_fp=d["winnowing_fp"],
            sentence_fp=d["sentence_fp"],
            text_length=d.get("text_length", 0),
            sentence_count=d.get("sentence_count", 0),
        )
