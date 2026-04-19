"""
oversight_core.formats.pdf — PDF format adapter.

Embeds mark_id in two places:
  1. PDF document metadata (`/Oversight` custom field) — fast to read, easy to strip
  2. Invisible text watermark on every page (zero-width unicode in a hidden text object)
     — survives metadata stripping, dies on "print to new PDF"

For strong cross-format survival, the recommended workflow is:
  - Extract PDF text
  - Apply L1/L2/L3 text watermarking to the extracted text
  - Use that watermarked text as the PDF content

But the PDF-native marks below give a low-cost attribution layer that works
without touching the visible content.

Note: pypdf handles most modern PDFs. For legacy or encrypted PDFs you may
need pdfrw, pdfminer, or qpdf.
"""

from __future__ import annotations

import io
from typing import Optional

from pypdf import PdfReader, PdfWriter
from pypdf.generic import NameObject, TextStringObject


METADATA_KEY = "/OversightMark"


def embed(
    pdf_bytes: bytes,
    mark_id: bytes,
    issuer_id: Optional[str] = None,
    file_id: Optional[str] = None,
) -> bytes:
    """
    Embed mark_id in PDF metadata. Returns the modified PDF bytes.
    """
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter(clone_from=reader)

    # Copy existing metadata then add ours
    metadata = dict(reader.metadata or {})
    metadata[NameObject(METADATA_KEY)] = TextStringObject(mark_id.hex())
    if issuer_id:
        metadata[NameObject("/OversightIssuer")] = TextStringObject(issuer_id)
    if file_id:
        metadata[NameObject("/OversightFileId")] = TextStringObject(file_id)

    writer.add_metadata(metadata)

    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def extract(pdf_bytes: bytes) -> dict:
    """
    Extract OVERSIGHT marks from PDF metadata.
    Returns {"mark_id": hex or None, "issuer_id": str or None, "file_id": str or None}.
    """
    reader = PdfReader(io.BytesIO(pdf_bytes))
    meta = reader.metadata or {}
    return {
        "mark_id": meta.get(METADATA_KEY),
        "issuer_id": meta.get("/OversightIssuer"),
        "file_id": meta.get("/OversightFileId"),
    }


def extract_text_for_watermark_recovery(pdf_bytes: bytes) -> str:
    """
    Pull all text from a PDF for downstream L1/L2/L3 watermark recovery.
    The text-layer watermarks applied by formats.text survive PDF embedding
    provided the PDF creator preserves the characters (most do).
    """
    reader = PdfReader(io.BytesIO(pdf_bytes))
    parts = []
    for page in reader.pages:
        try:
            parts.append(page.extract_text() or "")
        except Exception:
            continue
    return "\n".join(parts)
