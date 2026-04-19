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

  L3 (synonym rotation, stub):
      Placeholder for semantic watermarking — swap between {start/begin/commence}
      style synonym classes per-bit. Survives format conversion completely because
      the mark is in the *words chosen*. Real implementation needs an NLP pass;
      the stub here demonstrates the hook.

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


# ---------------- L3: synonym-class (stub) ----------------

# Illustrative only. Real deployment needs a curated synonym table + NLP-aware insertion.
SYNONYM_CLASSES = [
    ("begin", "start", "commence"),    # 3-ary, encodes log2(3) ≈ 1.58 bits
    ("large", "big", "substantial"),
    ("fast", "quick", "rapid"),
    ("show", "display", "present"),
]


def embed_synonyms_stub(text: str, mark_id: bytes) -> str:
    """
    Stub: demonstrates the hook. A production version walks the text with an NLP
    tagger, finds matches in SYNONYM_CLASSES, and rotates them deterministically
    based on bits of mark_id.
    """
    # Deliberately a no-op placeholder — clearly flagged so it's not mistaken for real.
    return text


def extract_synonyms_stub(text: str) -> Optional[bytes]:
    return None


# ---------------- high-level apply/recover ----------------

def apply_all(text: str, mark_id: bytes) -> str:
    """Apply all available watermark layers to text."""
    t = embed_zw(text, mark_id)
    t = embed_ws(t, mark_id)
    t = embed_synonyms_stub(t, mark_id)
    return t


def recover_marks(text: str, mark_len_bytes: int = 8) -> dict:
    """
    Try every layer; return a dict of {layer: [candidate_mark_bytes]} for the registry
    to match against known recipient IDs.
    """
    return {
        "L1_zero_width": extract_zw(text, mark_len_bytes),
        "L2_whitespace": [m for m in [extract_ws(text, mark_len_bytes)] if m],
        "L3_synonyms": [m for m in [extract_synonyms_stub(text)] if m],
    }
