"""
L3 semantic-watermark safety policy.

L3 is powerful because it changes visible prose. That also makes it unsafe for
classes where exact wording is the evidence: contracts, filings, code, logs,
structured data, and technical specifications. This module decides when L3 is
allowed and applies it only to conservative prose regions.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import re
from typing import Optional

from . import semantic


RISKY_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".css", ".go", ".h", ".hpp", ".java",
    ".js", ".jsx", ".kt", ".lua", ".php", ".py", ".rb", ".rs", ".sh",
    ".sql", ".swift", ".ts", ".tsx",
    ".json", ".jsonl", ".yaml", ".yml", ".toml", ".xml", ".csv", ".tsv",
    ".ini", ".conf", ".cfg", ".lock", ".env",
    ".log",
}
LEGAL_EXTENSIONS = {".contract", ".filing", ".nda", ".msa", ".sow"}
STRUCTURED_MIME_PREFIXES = (
    "application/json",
    "application/xml",
    "application/x-yaml",
    "text/csv",
    "text/tab-separated-values",
)
SOURCE_MIME_HINTS = ("source", "script", "sql", "json", "yaml", "xml")
RFC2119 = {
    "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
    "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", "OPTIONAL",
}


@dataclass
class L3Decision:
    enabled: bool
    mode: str
    document_class: str
    requires_ack: bool
    reason: str
    warnings: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def classify_document(
    *,
    filename: str = "",
    content_type: str = "",
    text: str = "",
    declared_class: str = "auto",
) -> tuple[str, list[str]]:
    """Classify a document for L3 safety decisions."""
    if declared_class and declared_class != "auto":
        return declared_class, [f"declared document class: {declared_class}"]

    suffix = Path(filename).suffix.lower()
    ctype = (content_type or "").lower()
    sample = text[:8192]
    reasons: list[str] = []

    if suffix in LEGAL_EXTENSIONS:
        return "legal", [f"legal-sensitive extension {suffix}"]
    if suffix in RISKY_EXTENSIONS:
        if suffix in {".sql"}:
            return "sql", [f"SQL extension {suffix}"]
        if suffix == ".log":
            return "log", [f"log extension {suffix}"]
        if suffix in {".json", ".jsonl", ".yaml", ".yml", ".toml", ".xml", ".csv", ".tsv", ".ini", ".conf", ".cfg", ".lock", ".env"}:
            return "structured_data", [f"structured-data extension {suffix}"]
        return "source_code", [f"source-code extension {suffix}"]

    if any(ctype.startswith(p) for p in STRUCTURED_MIME_PREFIXES):
        return "structured_data", [f"structured MIME type {content_type}"]
    if any(h in ctype for h in SOURCE_MIME_HINTS):
        return "source_code", [f"code-like MIME type {content_type}"]

    upper_hits = sum(1 for kw in RFC2119 if re.search(rf"\b{re.escape(kw)}\b", sample))
    if upper_hits >= 3:
        return "technical_spec", ["multiple RFC 2119 requirement keywords"]
    if re.search(r"\b(SEC|FDA|FINRA|10-K|10-Q|8-K|S-1|regulation|compliance filing)\b", sample, re.I):
        return "regulatory", ["regulatory/filing language detected"]
    if re.search(r"\b(agreement|whereas|hereby|indemnif|governing law|jurisdiction|party|parties)\b", sample, re.I):
        return "legal", ["contract/legal language detected"]
    if re.search(r"```|^\s{4,}\S|SELECT\s+.+\s+FROM|CREATE\s+TABLE", sample, re.I | re.M):
        return "technical_spec", ["code block or specification-like syntax detected"]

    reasons.append("no high-risk L3 signals detected")
    return "prose", reasons


def decide_l3(
    *,
    filename: str = "",
    content_type: str = "",
    text: str = "",
    declared_class: str = "auto",
    requested_mode: str = "auto",
) -> L3Decision:
    """Return whether L3 should run and how."""
    doc_class, reasons = classify_document(
        filename=filename,
        content_type=content_type,
        text=text,
        declared_class=declared_class,
    )
    risky = doc_class in {
        "legal", "regulatory", "technical_spec", "source_code", "sql",
        "log", "structured_data",
    }
    warnings: list[str] = []

    if requested_mode == "off":
        return L3Decision(False, "off", doc_class, False, "L3 disabled by user", reasons)
    if requested_mode == "boilerplate":
        return L3Decision(True, "boilerplate", doc_class, True, "boilerplate-only L3 requested", reasons)
    if requested_mode == "full":
        if risky:
            warnings.append(
                "L3 full mode was explicitly requested for a wording-sensitive document class."
            )
        return L3Decision(True, "full", doc_class, True, "full L3 explicitly requested", reasons + warnings)

    if risky:
        return L3Decision(
            False,
            "off",
            doc_class,
            False,
            "L3 defaults off for wording-sensitive document classes",
            reasons,
        )

    return L3Decision(True, "full", doc_class, True, "L3 auto-enabled for prose", reasons)


def apply_l3_safe(text: str, mark_id: bytes, mode: str = "full") -> str:
    """Apply L3 only to conservative prose regions."""
    if mode == "off":
        return text

    lines = text.splitlines(keepends=True)
    code_fence = False
    out: list[str] = []
    total = len(lines)

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("```"):
            code_fence = not code_fence
            out.append(line)
            continue
        if code_fence or _line_is_protected(line):
            out.append(line)
            continue
        if mode == "boilerplate" and not _is_boilerplate_line(line, idx, total):
            out.append(line)
            continue
        out.append(_apply_l3_to_unquoted_segments(line, mark_id))
    return "".join(out)


def _line_is_protected(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if line.startswith(("    ", "\t", ">>> ", "... ")):
        return True
    if re.match(r"^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\b", line, re.I):
        return True
    if re.search(r"`[^`]+`", line):
        return True
    if re.search(r"\b(?:MUST|SHOULD|MAY|SHALL|REQUIRED|OPTIONAL)(?:\s+NOT)?\b", line):
        return True
    if re.search(r"\b\d+(?:\.\d+)?\s*(?:%|percent|kg|g|mg|lb|oz|m|cm|mm|km|ft|in|ms|s|sec|min|h|hr|USD|EUR|GBP|MB|GB|TB)\b", line, re.I):
        return True
    if re.search(r"\b[A-Z][A-Z0-9_-]{2,}\b", line):
        return True
    return False


def _is_boilerplate_line(line: str, idx: int, total: int) -> bool:
    if idx < 6 or idx >= max(0, total - 6):
        return True
    return bool(re.search(r"\b(confidential|proprietary|notice|copyright|footer|header|cover page)\b", line, re.I))


def _apply_l3_to_unquoted_segments(line: str, mark_id: bytes) -> str:
    parts = re.split(r"((?:\"[^\"]*\")|(?:'[^']*')|(?:“[^”]*”))", line)
    for i in range(0, len(parts), 2):
        segment = parts[i]
        if not segment.strip():
            continue
        # Safe L3 avoids number-format marks entirely and only transforms prose
        # segments that passed the line-level guards.
        segment = (
            semantic.embed_synonyms_v2(segment, mark_id, min_instances=1)
            if semantic.SYNONYMS_V2_AVAILABLE
            else semantic.embed_synonyms(segment, mark_id, min_instances=1)
        )
        segment = semantic.embed_spelling(segment, mark_id)
        segment = semantic.embed_contractions(segment, mark_id)
        parts[i] = segment
    return "".join(parts)
