"""
oversight_core.decoy
===================

LLM-powered decoy document generator.

Generates N plausible-looking decoy files that sit alongside real sensitive
content. Every decoy is sealed for a "trap" recipient whose beacons all fire
when accessed. Any open of a decoy is a high-confidence signal of intrusion —
no legitimate user should touch them, because the decoys are filenames
engineered to be interesting to an attacker browsing.

This is the Thinkst canary pattern applied at scale with LLM-generated
realism. Recent research (SPADE 2025, HoneyGPT) shows this is an open area
with no strong commercial shipment.

Backend options (pick via `backend` arg or OVERSIGHT_DECOY_BACKEND env):
  - "ollama"   — POST to a local Ollama server (recommended)
  - "openai"   — OpenAI-compatible API (for testing)
  - "static"   — hardcoded templates (works offline; lowest quality)

Override the Ollama endpoint and model with the ``OLLAMA_URL`` and
``OVERSIGHT_DECOY_MODEL`` environment variables. Defaults target a
loopback Ollama install.
"""

from __future__ import annotations

import json
import os
import random
from dataclasses import dataclass
from typing import Optional

import httpx


DEFAULT_OLLAMA = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
DEFAULT_MODEL = os.environ.get("OVERSIGHT_DECOY_MODEL", "llama3.1:8b")


# Realistic decoy filenames. These are deliberately interesting to an attacker
# skimming a compromised folder.
DEFAULT_DECOY_NAMES = [
    "Q4-board-deck-FINAL-v3.docx",
    "acquisition-targets-2026.xlsx",
    "legal-hold-privileged.pdf",
    "compensation-bands-confidential.xlsx",
    "incident-response-playbook-internal.docx",
    "vendor-contracts-summary.pdf",
    "cto-1on1-notes.docx",
    "layoff-planning-tier1.xlsx",
    "customer-churn-risk-2026.xlsx",
    "M&A-pipeline-confidential.pptx",
    "security-audit-findings-Q3.pdf",
    "api-keys-rotation-plan.txt",
    "lawsuit-draft-settlement.docx",
    "executive-bonus-structure.xlsx",
    "strategic-partnership-nda-drafts.pdf",
]


# Prompt template. The system prompt steers the model toward plausibility
# without generating anything actually sensitive or real.
DECOY_SYSTEM_PROMPT = """You are a corporate document generator for a security
research system. You produce plausible-looking but entirely fictional business
documents that will be used as decoys in an intrusion-detection system. All
names, numbers, and claims must be invented — never use real company names,
real people, or real data. The goal is realism of form, not content.

Rules:
- All dollar figures are fake.
- All people are fictional (use generic names like "A. Smith", "J. Chen").
- All company names are fake (use "Acme Industries", "Meridian Partners").
- Avoid dates in the near past (the document should look "current" as of 2026).
- Tone: dry, corporate, slightly bureaucratic. No irony.
- Length: 250-600 words for text documents.
"""


@dataclass
class DecoyRequest:
    """A request to generate one decoy."""
    filename: str
    # Brief description of the kind of document to produce
    topic_hint: str
    # Additional context (e.g., industry, team)
    context: Optional[str] = None


def _prompt_for(req: DecoyRequest) -> str:
    ctx = f"\nOrganizational context: {req.context}" if req.context else ""
    return (
        f"Produce a realistic but entirely fictional document that would "
        f"plausibly be saved as the filename '{req.filename}'. The topic is: "
        f"{req.topic_hint}.{ctx}\n\n"
        f"Write the full document body. No preamble, no meta-commentary. "
        f"Begin the document directly."
    )


def _topic_from_filename(name: str) -> str:
    """Heuristic: guess topic from filename when not otherwise specified."""
    n = name.lower()
    if "board" in n or "deck" in n:
        return "quarterly board meeting update"
    if "acquisition" in n or "m&a" in n or "pipeline" in n:
        return "shortlist of acquisition targets with preliminary valuations"
    if "legal" in n or "lawsuit" in n:
        return "legal memo with privileged work-product notation"
    if "comp" in n or "bonus" in n or "bands" in n:
        return "executive compensation band summary"
    if "incident" in n or "playbook" in n:
        return "internal incident response playbook"
    if "audit" in n or "findings" in n:
        return "internal security audit findings summary"
    if "api" in n or "key" in n:
        return "API key rotation plan with endpoint references"
    if "layoff" in n:
        return "workforce reduction planning notes"
    if "churn" in n:
        return "customer churn risk analysis"
    if "partnership" in n or "nda" in n:
        return "strategic partnership NDA draft negotiation notes"
    if "1on1" in n or "notes" in n:
        return "executive one-on-one meeting notes"
    if "vendor" in n or "contract" in n:
        return "vendor contract summary with renewal dates"
    return "internal business memo"


# ---------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------

def _generate_ollama(
    req: DecoyRequest,
    ollama_url: str = DEFAULT_OLLAMA,
    model: str = DEFAULT_MODEL,
    timeout: float = 120.0,
) -> str:
    prompt = _prompt_for(req)
    r = httpx.post(
        f"{ollama_url.rstrip('/')}/api/generate",
        json={
            "model": model,
            "prompt": prompt,
            "system": DECOY_SYSTEM_PROMPT,
            "stream": False,
            "options": {"temperature": 0.8, "top_p": 0.9, "num_predict": 800},
        },
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()["response"]


def _generate_static(req: DecoyRequest) -> str:
    """Offline fallback. Good enough for testing; not production."""
    lines = [
        f"INTERNAL — {req.filename}",
        f"Topic: {req.topic_hint}",
        "",
        "Summary",
        "-------",
        f"This document covers the {req.topic_hint}. It is distributed to a",
        "limited group and should not be shared externally. Figures cited below",
        "are preliminary and subject to revision.",
        "",
        "Key points",
        "----------",
        "- Reviewed by: A. Smith, J. Chen",
        "- Next review: Q3 2026",
        "- Distribution: executive leadership only",
        "- Classification: CONFIDENTIAL - RESTRICTED",
        "",
        "Background",
        "----------",
    ]
    for i in range(30):
        lines.append(
            f"Paragraph {i+1}: standard corporate filler content for the "
            f"{req.topic_hint} topic, written to give plausible body to a "
            f"decoy document."
        )
    return "\n".join(lines)


def generate_decoy(
    req: DecoyRequest,
    backend: str = None,
    ollama_url: str = DEFAULT_OLLAMA,
    model: str = DEFAULT_MODEL,
) -> str:
    """Generate a single decoy document body. Returns the text content."""
    backend = backend or os.environ.get("OVERSIGHT_DECOY_BACKEND", "ollama")

    try:
        if backend == "ollama":
            return _generate_ollama(req, ollama_url=ollama_url, model=model)
    except Exception as e:
        # Fall back to static template on LLM failure.
        print(f"[decoy] backend '{backend}' failed ({e}); falling back to static")

    return _generate_static(req)


def generate_decoy_set(
    n: int = 5,
    filenames: Optional[list[str]] = None,
    context: Optional[str] = None,
    backend: str = None,
) -> list[tuple[str, str]]:
    """
    Generate N decoys. Returns list of (filename, body) tuples.
    """
    names = filenames or random.sample(DEFAULT_DECOY_NAMES, min(n, len(DEFAULT_DECOY_NAMES)))
    out = []
    for name in names[:n]:
        req = DecoyRequest(
            filename=name,
            topic_hint=_topic_from_filename(name),
            context=context,
        )
        body = generate_decoy(req, backend=backend)
        out.append((name, body))
    return out
