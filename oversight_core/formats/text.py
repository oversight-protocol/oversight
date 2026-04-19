"""
oversight_core.formats.text — text format adapter.

Wraps the three watermark layers:
    L1 zero-width unicode    (watermark.py)
    L2 trailing whitespace   (watermark.py)
    L3 semantic              (semantic.py)

into a single apply/recover API.
"""

from __future__ import annotations

from .. import watermark, semantic


def apply(text: str, mark_id: bytes, layers: tuple[str, ...] = ("L1", "L2", "L3")) -> str:
    """Apply all requested watermark layers to UTF-8 text."""
    t = text
    if "L1" in layers:
        t = watermark.embed_zw(t, mark_id)
    if "L2" in layers:
        t = watermark.embed_ws(t, mark_id)
    if "L3" in layers:
        t = semantic.apply_semantic(t, mark_id)
    return t


def recover(text: str, candidate_mark_ids: list[bytes] = None) -> dict:
    """
    Recover attribution from text.

    Returns:
      {
        "L1_hits": [mark_id_hex, ...],
        "L2_hits": [mark_id_hex, ...],
        "L3_matches": [{"mark_id": ..., "score": ..., "match": True/False}, ...]
      }

    L1 and L2 recover the mark_id directly from invisible content.
    L3 requires candidate_mark_ids (usually from the registry) to verify against.
    """
    out = {
        "L1_hits": [m.hex() for m in watermark.extract_zw(text)],
        "L2_hits": [],
        "L3_matches": [],
    }
    ws = watermark.extract_ws(text)
    if ws:
        out["L2_hits"].append(ws.hex())

    if candidate_mark_ids:
        for cm in candidate_mark_ids:
            result = semantic.verify_semantic(text, cm)
            if result["overall_match"]:
                out["L3_matches"].append({
                    "mark_id": cm.hex(),
                    "syn_score": result["synonyms_score"],
                    "punct_score": result["punctuation_score"],
                })
    return out
