"""
oversight_core.watermark
=======================

Per-recipient watermarking. The point is attribution after plaintext escape:
if a sealed file is decrypted and leaked, the recovered plaintext still contains
marks that identify WHICH recipient's copy it was.

This MVP ships three mark layers. Each is independently keyed, so an attacker
stripping one doesn't defeat the others. The `mark_id` is a random per-recipient
tag registered in the manifest — matching it in leaked content proves the source.

Layers:
  L1 (zero-width unicode stego):
      Embeds mark_id bits as ZWSP / ZWNJ / ZWJ in text content. Survives copy-paste
      and most format conversions. Defeated by "normalize/strip invisibles" passes.

  L2 (whitespace pattern):
      Encodes bits as trailing space vs tab at line endings. Survives more aggressive
      cleaning than L1 because linters often don't touch trailing whitespace in
      content-bearing fields.

  L3 (synonym rotation + punctuation):
      Semantic watermarking via synonym-class rotation (151 classes in v2) and
      punctuation-style fingerprinting (Oxford comma, em dash, curly quotes).
      Survives format conversion, invisible-char stripping, and whitespace
      normalization because the marks are in the words and punctuation chosen.
      Implementation in oversight_core.semantic; wired in here via apply_all.

Future (not in MVP):
  - Visual DCT-domain watermarks for images (robust to recompression + screenshot)
  - Layout perturbation for PDFs (micro-kerning, line-spacing)
  - Structural marks for code files (whitespace + comment ordering)

All mark IDs are random per-recipient. Decoder returns the first matching ID
from the registry — that's your attribution.
"""

from __future__ import annotations

import secrets
from typing import Iterable, Optional


# Zero-width characters used for L1
ZW_SPACE = "\u200b"   # bit 0
ZW_NONJOIN = "\u200c" # bit 1
ZW_JOIN = "\u200d"    # separator / frame
ZW_ALL = (ZW_SPACE, ZW_NONJOIN, ZW_JOIN)


def _bits_of(data: bytes) -> list[int]:
    out = []
    for byte in data:
        for i in range(8):
            out.append((byte >> (7 - i)) & 1)
    return out


def _bytes_from_bits(bits: Iterable[int]) -> bytes:
    bits = list(bits)
    # truncate to whole-byte boundary
    n = (len(bits) // 8) * 8
    bits = bits[:n]
    out = bytearray()
    for i in range(0, n, 8):
        b = 0
        for j in range(8):
            b = (b << 1) | (bits[i + j] & 1)
        out.append(b)
    return bytes(out)


def new_mark_id(n_bytes: int = 8) -> bytes:
    """A per-recipient mark ID. 8 bytes = 64 bits = plenty for attribution."""
    return secrets.token_bytes(n_bytes)


# ---------------- L1: zero-width unicode ----------------

def embed_zw(text: str, mark_id: bytes, density: int = 40) -> str:
    """
    Embed mark_id into text as zero-width unicode characters.
    density = approx chars between mark insertions (so 1000-char doc gets 25 mark copies).

    Encoding: a frame of [ZW_JOIN] [bits of mark_id as ZWSP/ZWNJ] [ZW_JOIN].
    Multiple redundant frames are scattered through the text.
    """
    bits = _bits_of(mark_id)
    frame = ZW_JOIN + "".join(ZW_SPACE if b == 0 else ZW_NONJOIN for b in bits) + ZW_JOIN

    if len(text) < density:
        return text + frame  # too short to scatter; just append

    out = []
    for i, ch in enumerate(text):
        out.append(ch)
        # insert full frame at each density-boundary
        if i > 0 and i % density == 0:
            out.append(frame)
    return "".join(out)


def extract_zw(text: str, mark_len_bytes: int = 8) -> list[bytes]:
    """
    Recover all candidate mark_ids from zero-width marks in text.
    Returns a list (may have repeats if multiple frames survived).
    """
    marks = []
    expected_bits = mark_len_bytes * 8
    i = 0
    while i < len(text):
        if text[i] == ZW_JOIN:
            # start of frame
            bits = []
            j = i + 1
            while j < len(text) and text[j] in (ZW_SPACE, ZW_NONJOIN):
                bits.append(0 if text[j] == ZW_SPACE else 1)
                j += 1
            if j < len(text) and text[j] == ZW_JOIN and len(bits) == expected_bits:
                marks.append(_bytes_from_bits(bits))
            i = j + 1
        else:
            i += 1
    return marks


# ---------------- L2: trailing whitespace ----------------

def embed_ws(text: str, mark_id: bytes) -> str:
    """
    Encode bits as trailing space (bit 0) vs trailing tab (bit 1) on the first N lines.
    Non-destructive: only affects lines that end in the natural way.
    """
    bits = _bits_of(mark_id)
    lines = text.split("\n")
    out_lines = []
    bi = 0
    for line in lines:
        if bi < len(bits) and line.rstrip() == line:  # no existing trailing ws
            suffix = " " if bits[bi] == 0 else "\t"
            out_lines.append(line + suffix)
            bi += 1
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


def extract_ws(text: str, mark_len_bytes: int = 8) -> Optional[bytes]:
    """Read the whitespace mark back out. Returns None if incomplete."""
    needed = mark_len_bytes * 8
    bits: list[int] = []
    for line in text.split("\n"):
        if line.endswith(" "):
            bits.append(0)
        elif line.endswith("\t"):
            bits.append(1)
        if len(bits) >= needed:
            break
    if len(bits) < needed:
        return None
    return _bytes_from_bits(bits[:needed])


# ---------------- L3: semantic watermarking ----------------

# Real implementation lives in oversight_core.semantic. We import it here
# so the watermark module is the single entry point for all three layers.
try:
    from . import semantic as _semantic
    _L3_AVAILABLE = True
except ImportError:
    _L3_AVAILABLE = False


# ---------------- L2: partial recovery ----------------

def extract_ws_partial(
    text: str, mark_len_bytes: int = 8
) -> tuple[Optional[bytes], float, int, int]:
    """
    Like extract_ws but returns partial results with confidence.

    Returns:
      (best_candidate, confidence, bits_recovered, bits_needed)

    If all bits are recovered, confidence = 1.0 and best_candidate is exact.
    If partial, best_candidate has recovered bits filled in and unknown bits
    set to 0, confidence = bits_recovered / bits_needed.
    """
    needed = mark_len_bytes * 8
    bits: list[int] = []
    for line in text.split("\n"):
        if line.endswith(" "):
            bits.append(0)
        elif line.endswith("\t"):
            bits.append(1)
        if len(bits) >= needed:
            break

    recovered = len(bits)
    if recovered == 0:
        return None, 0.0, 0, needed

    # Pad with zeros if incomplete
    padded = bits[:needed] + [0] * max(0, needed - recovered)
    candidate = _bytes_from_bits(padded[:needed])
    confidence = min(recovered, needed) / needed
    return candidate, confidence, min(recovered, needed), needed


# ---------------- high-level apply/recover ----------------

def apply_all(
    text: str,
    mark_id: bytes,
    *,
    include_l3: bool = False,
    l3_mode: str = "full",
) -> str:
    """
    Apply all available watermark layers to text.

    Layer order matters: L3 (synonym rotation) runs FIRST because it rewrites
    words. L2 (trailing whitespace) runs second. L1 (zero-width unicode) runs
    last because it inserts invisible characters that could fragment synonym
    words if applied earlier.
    """
    if include_l3 and _L3_AVAILABLE:
        from . import l3_policy
        t = l3_policy.apply_l3_safe(text, mark_id, mode=l3_mode)
    else:
        t = text
    t = embed_ws(t, mark_id)
    t = embed_zw(t, mark_id)
    return t


def recover_marks(text: str, mark_len_bytes: int = 8) -> dict:
    """
    Try every layer; return a dict of {layer: [candidate_mark_bytes]} for the registry
    to match against known recipient IDs.
    """
    return {
        "L1_zero_width": extract_zw(text, mark_len_bytes),
        "L2_whitespace": [m for m in [extract_ws(text, mark_len_bytes)] if m],
        "L3_synonyms": [],  # L3 requires candidate-based verification; see verify_l3
    }


def verify_l3(
    text: str,
    candidate_mark_ids: list[bytes],
    threshold: float = 0.70,
) -> list[tuple[bytes, float, dict]]:
    """
    Test candidate mark_ids against the semantic marks in text.

    Returns a list of (mark_id, score, detail_dict) for candidates that
    score above the threshold. Results are sorted by score descending.
    """
    if not _L3_AVAILABLE:
        return []

    hits = []
    for mid in candidate_mark_ids:
        detail = _semantic.verify_semantic(text, mid)
        if detail["overall_match"]:
            hits.append((mid, detail["synonyms_score"], detail))
    hits.sort(key=lambda x: x[1], reverse=True)
    return hits


def recover_marks_v2(
    text: str,
    candidate_mark_ids: list[bytes] | None = None,
    mark_len_bytes: int = 8,
) -> dict:
    """
    Enhanced recovery with partial L2, L3 verification, and per-layer diagnostics.

    Returns a dict with:
      - layers: per-layer results with confidence
      - candidates: fused candidate list
      - diagnostics: human-readable per-layer status strings
    """
    # L1: zero-width extraction
    l1_marks = extract_zw(text, mark_len_bytes)
    l1_unique = list(set(l1_marks))

    # L2: partial recovery
    l2_candidate, l2_confidence, l2_bits, l2_needed = extract_ws_partial(
        text, mark_len_bytes
    )
    l2_marks = [l2_candidate] if l2_candidate and l2_confidence >= 0.5 else []

    # L3: candidate-based verification
    l3_hits: list[tuple[bytes, float, dict]] = []
    if candidate_mark_ids and _L3_AVAILABLE:
        l3_hits = verify_l3(text, candidate_mark_ids)

    # Build diagnostics
    diagnostics = []
    if l1_unique:
        diagnostics.append(
            f"L1: {len(l1_marks)} frames found, "
            f"{len(l1_unique)} unique mark(s): "
            + ", ".join(m.hex() for m in l1_unique)
        )
    else:
        diagnostics.append(
            "L1: 0 zero-width frames found (invisible chars stripped?)"
        )

    if l2_confidence >= 1.0:
        diagnostics.append(
            f"L2: {l2_bits}/{l2_needed} bits recovered (100%), "
            f"mark: {l2_candidate.hex()}"
        )
    elif l2_confidence > 0:
        diagnostics.append(
            f"L2: {l2_bits}/{l2_needed} bits recovered "
            f"({l2_confidence:.0%} confidence), "
            f"partial candidate: {l2_candidate.hex()}"
        )
    else:
        diagnostics.append(
            "L2: 0 trailing whitespace marks found (whitespace stripped?)"
        )

    if not _L3_AVAILABLE:
        diagnostics.append("L3: semantic module not available")
    elif not candidate_mark_ids:
        diagnostics.append(
            "L3: no candidate mark_ids provided (query registry first)"
        )
    elif l3_hits:
        for mid, score, detail in l3_hits:
            diagnostics.append(
                f"L3: mark {mid.hex()} matched with score "
                f"{score:.2f} (synonyms) / "
                f"{detail['punctuation_hits']} (punctuation), "
                f"dict={detail['dict_version']}"
            )
    else:
        diagnostics.append(
            f"L3: {len(candidate_mark_ids)} candidate(s) tested, "
            "none matched above threshold"
        )

    # Fuse candidates across layers
    all_candidates = _fuse_candidates(
        l1_unique, l2_candidate, l2_confidence, l3_hits
    )

    return {
        "layers": {
            "L1_zero_width": l1_unique,
            "L2_whitespace": l2_marks,
            "L2_confidence": l2_confidence,
            "L3_semantic": [(m, s) for m, s, _ in l3_hits],
        },
        "candidates": all_candidates,
        "diagnostics": diagnostics,
    }


def _fuse_candidates(
    l1_marks: list[bytes],
    l2_candidate: bytes | None,
    l2_confidence: float,
    l3_hits: list[tuple[bytes, float, dict]],
) -> list[tuple[bytes, float, str]]:
    """
    Multi-layer Bayesian fusion: combine evidence from all layers into a
    single ranked candidate list.

    Returns list of (mark_id, combined_score, evidence_summary).

    Scoring:
      - L1 exact match: 0.95 (high, but not 1.0 because of frame corruption)
      - L2 exact match: 0.90 (slightly lower, whitespace is fragile)
      - L2 partial: l2_confidence * 0.60 (scaled down for uncertainty)
      - L3 match: l3_score * 0.85 (probabilistic, weighted by synonym score)

    When multiple layers agree on the same mark_id, scores combine:
      combined = 1 - (1-s1)(1-s2)...(1-sN)
    This is a standard independence-assumption combination.
    """
    # Collect per-candidate evidence
    evidence: dict[bytes, list[tuple[float, str]]] = {}

    for m in l1_marks:
        evidence.setdefault(m, []).append((0.95, "L1"))

    if l2_candidate and l2_confidence >= 0.5:
        l2_score = min(l2_confidence, 1.0) * 0.90
        evidence.setdefault(l2_candidate, []).append((l2_score, "L2"))

    for m, s, _ in l3_hits:
        evidence.setdefault(m, []).append((s * 0.85, "L3"))

    # Combine scores per candidate
    results = []
    for mark_id, scores in evidence.items():
        if len(scores) == 1:
            combined = scores[0][0]
        else:
            # 1 - product(1 - s_i)
            combined = 1.0
            for s, _ in scores:
                combined *= (1.0 - s)
            combined = 1.0 - combined
        layers_hit = "+".join(lbl for _, lbl in scores)
        results.append((mark_id, combined, layers_hit))

    results.sort(key=lambda x: x[1], reverse=True)
    return results
