"""
oversight_match — Flywheel job module.

Registers a new Flywheel job kind `oversight_match` that takes scraped content
(text, attached images, attached PDFs/DOCX) and checks it against the
OVERSIGHT registry for leaked-file attribution.

How to register this with Flywheel:
    from oversight_integrations.flywheel_oversight_match import handle_scraped
    flywheel.register_job("oversight_match", handle_scraped)

Job inputs (dict):
    {
        "source_url": "https://breachforums.example/thread/12345",
        "scraped_at": 1715000000,
        "text": "<pasted leaked document text>",
        "attachments": [
            {"kind": "image", "bytes_hex": "...", "filename": "leaked.png"},
            {"kind": "pdf",   "bytes_hex": "...", "filename": "leaked.pdf"},
            {"kind": "docx",  "bytes_hex": "...", "filename": "leaked.docx"},
        ],
    }

Job output (dict):
    {
        "matches": [
            {"layer": "L1_zero_width",  "mark_id": "...", "file_id": "...",
             "recipient_id": "...", "issuer_id": "...", "score": 1.0},
            {"layer": "L3_semantic",    "mark_id": "...", "score": 0.89, ...},
            {"layer": "image_DCT",      "mark_id": "...", "score": 0.12, ...},
            {"layer": "perceptual_hash","hash": "...", "file_id": "...", ...},
        ],
        "scraped_at": 1715000000,
        "source_url": "...",
    }

On match: raise a priority-1 alert through the Flywheel event bus so the
`CanaryKeeper` Perseus agent can notify Zion via Discord.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional

import httpx

# Add oversight_core to path — assumes Flywheel container has oversight/ available
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oversight_core import watermark, semantic
from oversight_core.formats import image as img_fmt
from oversight_core.formats import pdf as pdf_fmt
from oversight_core.formats import docx as docx_fmt


# ---------- registry client ----------

class RegistryClient:
    def __init__(self, url: str, timeout: float = 10.0):
        self.url = url.rstrip("/")
        self.client = httpx.Client(timeout=timeout)
        self._cached_candidates: list[dict] = []
        self._candidates_fetched_at: int = 0

    def close(self):
        self.client.close()

    def attribute(self, **kwargs) -> dict:
        """POST /attribute with any of token_id, mark_id, layer, perceptual_hash."""
        r = self.client.post(f"{self.url}/attribute", json=kwargs)
        r.raise_for_status()
        return r.json()

    def fetch_semantic_candidates(self, cache_ttl: int = 3600) -> list[dict]:
        """Fetch L3 semantic candidate mark_ids (cached for cache_ttl seconds)."""
        now = int(time.time())
        if self._cached_candidates and now - self._candidates_fetched_at < cache_ttl:
            return self._cached_candidates
        r = self.client.get(f"{self.url}/candidates/semantic", params={"limit": 5000})
        r.raise_for_status()
        data = r.json()
        self._cached_candidates = data["candidates"]
        self._candidates_fetched_at = now
        return self._cached_candidates


# ---------- text layer extractors ----------

def _check_text(text: str, registry: RegistryClient) -> list[dict]:
    """
    Run L1 / L2 / L3 extractors against leaked text.
    L1 and L2 give direct mark_ids (look them up).
    L3 requires iterating candidate mark_ids and verifying.
    """
    matches: list[dict] = []

    # L1 — direct mark_id hit
    for m in watermark.extract_zw(text):
        r = registry.attribute(mark_id=m.hex(), layer="L1_zero_width")
        if r.get("found"):
            matches.append({"layer": "L1_zero_width", "score": 1.0, **r})

    # L2 — direct mark_id hit
    l2 = watermark.extract_ws(text)
    if l2:
        r = registry.attribute(mark_id=l2.hex(), layer="L2_whitespace")
        if r.get("found"):
            matches.append({"layer": "L2_whitespace", "score": 1.0, **r})

    # L3 — verify against every candidate mark_id (probabilistic)
    candidates = registry.fetch_semantic_candidates()
    for cand in candidates:
        mark_bytes = bytes.fromhex(cand["mark_id"])
        result = semantic.verify_semantic(text, mark_bytes)
        if result["overall_match"]:
            r = registry.attribute(mark_id=cand["mark_id"], layer="L3_semantic")
            if r.get("found"):
                matches.append({
                    "layer": "L3_semantic",
                    "score": result["synonyms_score"],
                    "punct_score": result["punctuation_score"],
                    **r,
                })
    return matches


# ---------- image layer ----------

def _check_image(image_bytes: bytes, registry: RegistryClient) -> list[dict]:
    """DCT watermark verification + perceptual-hash fuzzy lookup."""
    matches: list[dict] = []

    # Perceptual hash — fast fuzzy lookup (exact-match on phash string)
    try:
        phash = img_fmt.perceptual_hash(image_bytes)
        r = registry.attribute(perceptual_hash=phash)
        if r.get("found"):
            matches.append({"layer": "perceptual_hash", "hash": phash, "score": 1.0, **r})
    except Exception:
        pass

    # DCT verify — requires candidate list to know which marks to test.
    # For MVP: iterate every known L4_image_dct mark (TODO: layer tag in registry)
    # Skipped for now — the perceptual hash usually suffices for fast triage.
    return matches


# ---------- PDF / DOCX ----------

def _check_pdf(pdf_bytes: bytes, registry: RegistryClient) -> list[dict]:
    matches: list[dict] = []
    # Metadata-level mark
    ext = pdf_fmt.extract(pdf_bytes)
    if ext.get("mark_id"):
        r = registry.attribute(mark_id=ext["mark_id"])
        if r.get("found"):
            matches.append({"layer": "pdf_metadata", "score": 1.0, **r})
    # Body-text extraction → run L1/L2/L3 on recovered text
    try:
        body_text = pdf_fmt.extract_text_for_watermark_recovery(pdf_bytes)
        matches.extend(_check_text(body_text, registry))
    except Exception:
        pass
    return matches


def _check_docx(docx_bytes: bytes, registry: RegistryClient) -> list[dict]:
    matches: list[dict] = []
    ext = docx_fmt.extract(docx_bytes)
    if ext.get("mark_id"):
        r = registry.attribute(mark_id=ext["mark_id"])
        if r.get("found"):
            matches.append({"layer": "docx_metadata", "score": 1.0, **r})
    try:
        body_text = docx_fmt.extract_text_for_watermark_recovery(docx_bytes)
        matches.extend(_check_text(body_text, registry))
    except Exception:
        pass
    return matches


# ---------- top-level handler ----------

def handle_scraped(job_input: dict, registry_url: str) -> dict:
    """
    Flywheel job entrypoint. Processes one scraped blob and returns
    a list of OVERSIGHT attribution matches (empty if nothing matches).
    """
    registry = RegistryClient(registry_url)
    try:
        all_matches: list[dict] = []

        # Text body
        text = job_input.get("text", "") or ""
        if text:
            all_matches.extend(_check_text(text, registry))

        # Attachments
        for att in job_input.get("attachments", []):
            kind = att.get("kind")
            raw = att.get("bytes_hex")
            if not raw:
                continue
            blob = bytes.fromhex(raw)
            if kind == "image":
                all_matches.extend(_check_image(blob, registry))
            elif kind == "pdf":
                all_matches.extend(_check_pdf(blob, registry))
            elif kind == "docx":
                all_matches.extend(_check_docx(blob, registry))

        # Deduplicate by (layer, file_id)
        seen = set()
        unique: list[dict] = []
        for m in all_matches:
            key = (m.get("layer"), m.get("file_id"))
            if key not in seen:
                seen.add(key)
                unique.append(m)

        return {
            "matches": unique,
            "scraped_at": job_input.get("scraped_at"),
            "source_url": job_input.get("source_url"),
        }
    finally:
        registry.close()


# ---------- quick standalone test ----------

if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser()
    p.add_argument("--registry", required=True)
    p.add_argument("--text", default="")
    p.add_argument("--url", default="(cli test)")
    args = p.parse_args()

    job = {
        "source_url": args.url,
        "scraped_at": int(time.time()),
        "text": args.text,
        "attachments": [],
    }
    print(json.dumps(handle_scraped(job, args.registry), indent=2))
