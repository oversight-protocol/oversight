"""
oversight_core.formats
=====================

Format-specific watermarking adapters.

Each adapter knows how to embed and extract a mark_id for one file family.
The core protocol (container.py, crypto.py, manifest.py, beacon.py) is
format-agnostic; these adapters let watermarking work on more than plain text.

MVP adapters:
    text   — L1 zero-width + L2 whitespace + L3 semantic (already in watermark.py + semantic.py)
    image  — DCT-domain frequency watermark (robust to recompression, resize, moderate crop)
    pdf    — per-recipient metadata + text-layer marks
    docx   — Office XML metadata injection

Not in MVP (roadmap):
    video  — per-keyframe DCT + audio echo-hiding
    audio  — echo-hiding + spread-spectrum
    xlsx   — cell-comment marks + invisible columns/rows
    pptx   — slide-note marks + image DCT on each slide image
"""

from . import text as text  # re-export for convenience
