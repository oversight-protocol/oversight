"""
OVERSIGHT — Sealed Entity, Notarized Trust, Integrity & Evidence Layer.

Open protocol for data provenance, attribution, and leak detection.

Core:
  - container       sealed file format (binary)
  - crypto          vetted primitives + PQ hooks
  - manifest        signed metadata
  - watermark       per-recipient attribution marks
  - beacon          passive callback tokens
"""

from .container import seal, open_sealed, SealedFile
from .manifest import Manifest, Recipient, WatermarkRef
from .crypto import ClassicIdentity, random_dek, content_hash
from . import watermark, beacon, l3_policy

__all__ = [
    "seal",
    "open_sealed",
    "SealedFile",
    "Manifest",
    "Recipient",
    "WatermarkRef",
    "ClassicIdentity",
    "random_dek",
    "content_hash",
    "watermark",
    "beacon",
    "l3_policy",
]

__version__ = "0.4.8"
