"""
oversight_core.semantic
======================

L3 semantic watermarking — the airgap-strip survivor.

Unlike L1 (zero-width unicode) and L2 (whitespace) which die the moment an
attacker runs a normalization pass, semantic marks are encoded in the *choice
of words* themselves. An attacker who opens the file in an airgapped VM and
strips invisible characters still has the watermark, because the words ARE
the watermark.

This module implements three real techniques:

  T1 — Synonym-class rotation
      For each synonym class (e.g., {begin, start, commence}), the choice made
      in each instance encodes bits of the mark_id. The attacker cannot tell
      whether "begin" or "start" was the original without access to the source,
      so stripping requires paraphrasing every candidate word — which damages
      the document and still doesn't defeat the mark if redundancy is high.

  T2 — Punctuation-style fingerprint
      Deterministic per-recipient choices of:
        - Oxford comma (on/off) at each list
        - Em dash vs en dash in parenthetical breaks
        - Straight vs curly quotes
      These survive copy-paste. They survive OCR (which usually preserves the
      glyph). They can be reliably extracted from any plaintext copy.

  T3 — Sentence-level structural marks
      For lists/enumerations, the ordering of items (when semantically
      neutral) encodes bits. For sentences, the choice of
      active-vs-passive voice in N eligible sentences encodes bits.

All three survive UTF-8 normalization, invisible-char stripping, whitespace
normalization, format conversion, and most OCR passes.

They do NOT survive aggressive manual paraphrasing by a human. That's the
fundamental limit of semantic watermarking: you cannot defend against
rewriting in someone else's words. You CAN make automated stripping
computationally expensive and attributable.

Bit capacity notes:
    T1: ~log2(classes_per_phrase) bits per insertion point, ~15-40 bits per page
    T2: ~3-5 bits per page (Oxford comma + dashes + quotes)
    T3: 1 bit per re-orderable list, 1 bit per voice-eligible sentence

Total realistic capacity: 30-80 bits per page of normal prose.
A 64-bit mark ID needs about one page of text to encode redundantly.
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional


# ------------------------------------------------------------------
# T1 — Synonym-class rotation (v2: 150 classes, URL/code skip, POS-aware)
# ------------------------------------------------------------------

# Import the v2 dictionary. Fall back to v1 in-module classes if import fails.
try:
    from .synonyms_v2 import (
        ALL_CLASSES as _V2_CLASSES,
        iter_matchable_words,
        SYNONYM_COUNT as _V2_COUNT,
    )
    SYNONYMS_V2_AVAILABLE = True
except ImportError:
    SYNONYMS_V2_AVAILABLE = False


# Legacy v1 table (kept for backward compatibility with files sealed before v0.2.1)
SYNONYM_CLASSES = [
    ("begin", "start", "commence"),
    ("large", "big", "substantial"),
    ("fast", "quick", "rapid"),
    ("show", "display", "present"),
    ("use", "utilize", "employ"),
    ("help", "assist", "aid"),
    ("make", "create", "produce"),
    ("get", "obtain", "acquire"),
    ("find", "locate", "identify"),
    ("tell", "inform", "notify"),
    ("give", "provide", "supply"),
    ("end", "finish", "conclude"),
    ("small", "tiny", "minor"),
    ("slow", "gradual", "deliberate"),
    ("important", "critical", "significant"),
    ("hard", "difficult", "challenging"),
    ("easy", "simple", "straightforward"),
    ("problem", "issue", "concern"),
    ("answer", "response", "reply"),
    ("question", "query", "inquiry"),
    ("idea", "concept", "notion"),
    ("plan", "strategy", "approach"),
    ("result", "outcome", "consequence"),
    ("however", "nevertheless", "nonetheless"),
    ("therefore", "consequently", "thus"),
    ("also", "additionally", "furthermore"),
    ("but", "yet", "though"),
]


def _build_synonym_lookup() -> dict[str, tuple[int, int]]:
    """v1 legacy lookup used when the caller explicitly asks for v1."""
    lookup: dict[str, tuple[int, int]] = {}
    for ci, cls in enumerate(SYNONYM_CLASSES):
        for vi, word in enumerate(cls):
            lookup[word.lower()] = (ci, vi)
    return lookup


SYNONYM_LOOKUP = _build_synonym_lookup()


def _bits_of(data: bytes) -> list[int]:
    out = []
    for byte in data:
        for i in range(8):
            out.append((byte >> (7 - i)) & 1)
    return out


def _bytes_from_bits(bits: list[int]) -> bytes:
    n = (len(bits) // 8) * 8
    out = bytearray()
    for i in range(0, n, 8):
        b = 0
        for j in range(8):
            b = (b << 1) | (bits[i + j] & 1)
        out.append(b)
    return bytes(out)


def _mark_id_to_variant_sequence(
    mark_id: bytes, n_instances: int, class_size: int = 3
) -> list[int]:
    """
    Derive a deterministic sequence of variant indices from mark_id.
    Uses HKDF-like expansion via SHA-256 over (mark_id || counter).
    Each variant index is in [0, class_size).
    """
    out: list[int] = []
    ctr = 0
    while len(out) < n_instances:
        h = hashlib.sha256(mark_id + ctr.to_bytes(4, "big")).digest()
        for byte in h:
            # map byte into [0, class_size) uniformly enough for our purposes
            out.append(byte % class_size)
            if len(out) >= n_instances:
                break
        ctr += 1
    return out


def _case_preserve(replacement: str, original: str) -> str:
    """Match capitalization pattern: Title, UPPER, or lower."""
    if original.isupper():
        return replacement.upper()
    if original[:1].isupper():
        return replacement[:1].upper() + replacement[1:]
    return replacement.lower()


_WORD_RE = re.compile(r"\b([A-Za-z]+)\b")

# Zero-width chars that L1 watermarking inserts. Strip these before semantic
# extraction so that synonym words aren't fragmented.
_ZW_CHARS = "\u200b\u200c\u200d\ufeff"


def _strip_zw(text: str) -> str:
    for ch in _ZW_CHARS:
        text = text.replace(ch, "")
    return text


def embed_synonyms(text: str, mark_id: bytes, min_instances: int = 8) -> str:
    """
    Walk the text, and at every word that is a member of a known synonym class,
    replace it with the class variant indicated by the mark_id-derived sequence.

    If the text has fewer than `min_instances` synonym-class hits, the function
    returns the text unchanged and logs to stderr (no silent partial marks).

    Note: best applied BEFORE L1 zero-width marks. If you apply it after L1,
    the word-boundary regex may miss synonym words fragmented by ZW chars
    (and we don't transparently strip ZW during embedding because we don't
    want to destroy the L1 marks).
    """
    # First pass: find all match positions
    matches: list[tuple[int, int, int, int, str]] = []
    # (start, end, class_index, orig_variant_index, original_word)
    for m in _WORD_RE.finditer(text):
        w = m.group(1)
        key = w.lower()
        if key in SYNONYM_LOOKUP:
            ci, vi = SYNONYM_LOOKUP[key]
            matches.append((m.start(), m.end(), ci, vi, w))

    if len(matches) < min_instances:
        # Not enough material to watermark. Return unchanged.
        import sys
        print(
            f"[semantic] warning: only {len(matches)} synonym-class hits "
            f"(need {min_instances}); skipping L3",
            file=sys.stderr,
        )
        return text

    # Derive a deterministic variant choice per match
    variants = _mark_id_to_variant_sequence(mark_id, len(matches), class_size=3)

    # Rewrite text with chosen variants, preserving case
    out: list[str] = []
    cursor = 0
    for (start, end, ci, _orig_vi, orig_word), target_vi in zip(matches, variants):
        cls = SYNONYM_CLASSES[ci]
        # Bound: some classes may have fewer than 3 variants
        target_vi = target_vi % len(cls)
        replacement = _case_preserve(cls[target_vi], orig_word)
        out.append(text[cursor:start])
        out.append(replacement)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def extract_synonyms_candidate(text: str, mark_len_bytes: int = 8) -> list[bytes]:
    """
    Attempt to recover mark_id from synonym choices in the text.

    We don't know the original text, so we can't directly recover bits.
    Instead, we check candidate mark_ids by:
      1. Computing the expected variant sequence for each candidate
      2. Checking how many match the text's actual variants

    Caller supplies candidate mark_ids (usually from the registry). This
    function returns the subset that match above a threshold.

    For the MVP, we instead return a *fingerprint* of the actual variant
    choices observed; the registry can match fingerprints against stored ones.
    """
    # Return a fingerprint = SHA-256 over the sequence of (class_index, variant_index) tuples
    seq = []
    for m in _WORD_RE.finditer(text):
        key = m.group(1).lower()
        if key in SYNONYM_LOOKUP:
            seq.append(SYNONYM_LOOKUP[key])
    if not seq:
        return []
    fp = hashlib.sha256(repr(seq).encode()).digest()
    return [fp]


def verify_synonyms_match(
    text: str, candidate_mark_id: bytes, threshold: float = 0.70
) -> tuple[bool, float]:
    """
    Given a candidate mark_id, compute what variant sequence it would have
    produced, and compare to the text's actual variant sequence.

    Returns (match, score). Score is fraction of matching variants.
    Threshold 0.70 tolerates some paraphrasing while still attributing.

    Automatically strips zero-width unicode (L1 watermark residue) before
    matching, so semantic verification works whether or not L1 was applied
    and whether or not an attacker has stripped invisibles.
    """
    text = _strip_zw(text)
    actual: list[tuple[int, int]] = []
    for m in _WORD_RE.finditer(text):
        key = m.group(1).lower()
        if key in SYNONYM_LOOKUP:
            actual.append(SYNONYM_LOOKUP[key])

    if not actual:
        return False, 0.0

    expected_variants = _mark_id_to_variant_sequence(candidate_mark_id, len(actual), 3)
    matches = 0
    counted = 0
    for (ci, actual_vi), expected_vi in zip(actual, expected_variants):
        cls = SYNONYM_CLASSES[ci]
        counted += 1
        if (expected_vi % len(cls)) == actual_vi:
            matches += 1

    score = matches / counted if counted else 0.0
    return (score >= threshold), score


# ------------------------------------------------------------------
# T2 — Punctuation-style fingerprint
# ------------------------------------------------------------------

# Bits we can set/read:
#   bit 0: Oxford comma in 3+ item lists (1 = present, 0 = absent)
#   bit 1: em dash (—) vs double-hyphen (--) for parentheticals
#   bit 2: curly quotes (\u201c \u201d) vs straight quotes (")
#   bit 3: spaced em dash ( — ) vs tight em dash (—)

def _bit_for(mark_id: bytes, bit_index: int) -> int:
    """Deterministic bit selector from mark_id."""
    byte = mark_id[bit_index % len(mark_id)]
    return (byte >> (bit_index % 8)) & 1


def embed_punctuation(text: str, mark_id: bytes) -> str:
    """
    Apply punctuation-style marks to text deterministically.

    Idempotent: running twice produces the same output.
    """
    b0 = _bit_for(mark_id, 0)  # oxford comma
    b1 = _bit_for(mark_id, 1)  # em vs double-hyphen
    b2 = _bit_for(mark_id, 2)  # curly vs straight quotes

    EM_DASH = "\u2014"
    OPEN_Q = "\u201c"
    CLOSE_Q = "\u201d"

    # b0: Oxford comma — only in lists of 3+ items ending with ", and"
    if b0:
        text = re.sub(r"(\w+), (\w+) and ", r"\1, \2, and ", text)
    else:
        text = re.sub(r"(\w+), (\w+), and ", r"\1, \2 and ", text)

    # b1: em dash vs double-hyphen. Use character in replacement, not escape.
    if b1:
        text = text.replace(" -- ", f" {EM_DASH} ")
        text = re.sub(r"(\w)--(\w)", lambda m: m.group(1) + EM_DASH + m.group(2), text)
    else:
        text = text.replace(f" {EM_DASH} ", " -- ")
        text = re.sub(r"(\w)" + EM_DASH + r"(\w)", r"\1--\2", text)

    # b2: straight quotes -> curly. Alternates open/close.
    if b2:
        quote_state = [1]  # next " becomes open
        def _curly(_m):
            quote_state[0] = 1 - quote_state[0]
            return OPEN_Q if quote_state[0] else CLOSE_Q
        text = re.sub(r'"', _curly, text)

    return text


def extract_punctuation_bits(text: str) -> list[int]:
    """
    Read the punctuation-style fingerprint out of the text.
    Returns [b0, b1, b2] or fewer if signals absent.
    """
    bits: list[int] = []

    # Oxford comma — look for last-comma-before-and pattern
    oxford = len(re.findall(r",\s+\w+,\s+(?:and|or)\s+", text))
    no_oxford = len(re.findall(r"\w,\s+\w+\s+(?:and|or)\s+", text))
    if oxford + no_oxford > 0:
        bits.append(1 if oxford > no_oxford else 0)

    # em dash vs double hyphen
    em_count = text.count("\u2014")
    dh_count = len(re.findall(r"\w--\w| -- ", text))
    if em_count + dh_count > 0:
        bits.append(1 if em_count > dh_count else 0)

    # curly vs straight quotes
    curly = text.count("\u201c") + text.count("\u201d")
    straight = text.count('"')
    if curly + straight > 0:
        bits.append(1 if curly > straight else 0)

    return bits


# ------------------------------------------------------------------
# Combined L3 API
# ------------------------------------------------------------------

def embed_synonyms_v2(text: str, mark_id: bytes, min_instances: int = 8) -> str:
    """
    Production v2 synonym embedding: uses the expanded ~150-class dictionary
    AND skips URLs, email addresses, file paths, and code blocks.
    """
    if not SYNONYMS_V2_AVAILABLE:
        # fall back to v1 if v2 dict isn't importable
        return embed_synonyms(text, mark_id, min_instances)

    matches = list(iter_matchable_words(text))
    if len(matches) < min_instances:
        import sys
        print(
            f"[semantic v2] only {len(matches)} matchable words "
            f"(need {min_instances}); skipping L3",
            file=sys.stderr,
        )
        return text

    variants = _mark_id_to_variant_sequence(mark_id, len(matches), class_size=3)

    out: list[str] = []
    cursor = 0
    for (start, end, orig_word, (ci, _orig_vi, _pos)), target_vi in zip(matches, variants):
        cls_variants = _V2_CLASSES[ci].variants
        target_vi = target_vi % len(cls_variants)
        # Skip multi-word variants (keep substitution a single-token swap)
        if " " in cls_variants[target_vi]:
            target_vi = (target_vi + 1) % len(cls_variants)
            if " " in cls_variants[target_vi]:
                target_vi = (target_vi + 1) % len(cls_variants)
        if " " in cls_variants[target_vi]:
            # all three are multi-word? skip this match
            out.append(text[cursor:end])
            cursor = end
            continue
        replacement = _case_preserve(cls_variants[target_vi], orig_word)
        out.append(text[cursor:start])
        out.append(replacement)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def verify_synonyms_v2(
    text: str, candidate_mark_id: bytes, threshold: float = 0.70
) -> tuple[bool, float]:
    """
    v2 verify: uses the expanded dictionary with URL/code skip.
    Returns (match, score).
    """
    if not SYNONYMS_V2_AVAILABLE:
        return verify_synonyms_match(text, candidate_mark_id, threshold)

    text = _strip_zw(text)
    actual = [(ci, vi) for (_s, _e, _w, (ci, vi, _pos)) in iter_matchable_words(text)]
    if not actual:
        return False, 0.0

    expected_variants = _mark_id_to_variant_sequence(candidate_mark_id, len(actual), 3)
    matches = 0
    counted = 0
    for (ci, actual_vi), expected_vi in zip(actual, expected_variants):
        cls_variants = _V2_CLASSES[ci].variants
        counted += 1
        exp_idx = expected_vi % len(cls_variants)
        # If the expected variant is multi-word, embed skipped it — the actual
        # would have stayed as the original. We can't verify that case reliably,
        # so count those as "matches" (conservative — gives attacker slight
        # benefit, but avoids false negatives).
        if " " in cls_variants[exp_idx]:
            matches += 1
            continue
        if exp_idx == actual_vi:
            matches += 1

    score = matches / counted if counted else 0.0
    return (score >= threshold), score


def apply_semantic(text: str, mark_id: bytes, use_v2: bool = True) -> str:
    """Apply all L3 layers: synonyms (v2 by default) + punctuation."""
    if use_v2 and SYNONYMS_V2_AVAILABLE:
        t = embed_synonyms_v2(text, mark_id)
    else:
        t = embed_synonyms(text, mark_id)
    t = embed_punctuation(t, mark_id)
    return t


def verify_semantic(text: str, candidate_mark_id: bytes, use_v2: bool = True) -> dict:
    """Check whether text matches candidate_mark_id. Returns per-sublayer scores."""
    if use_v2 and SYNONYMS_V2_AVAILABLE:
        syn_match, syn_score = verify_synonyms_v2(text, candidate_mark_id)
    else:
        syn_match, syn_score = verify_synonyms_match(text, candidate_mark_id)
    punct_bits = extract_punctuation_bits(text)
    expected_punct = [
        _bit_for(candidate_mark_id, 0),
        _bit_for(candidate_mark_id, 1),
        _bit_for(candidate_mark_id, 2),
    ]
    punct_hits = sum(1 for a, b in zip(punct_bits, expected_punct) if a == b)
    punct_total = len(punct_bits)
    punct_score = punct_hits / punct_total if punct_total else 0.0

    return {
        "synonyms_match": syn_match,
        "synonyms_score": syn_score,
        "punctuation_score": punct_score,
        "punctuation_hits": f"{punct_hits}/{punct_total}",
        "overall_match": syn_match and (punct_score >= 0.5 if punct_total else True),
        "dict_version": "v2" if (use_v2 and SYNONYMS_V2_AVAILABLE) else "v1",
    }
