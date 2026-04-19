"""
oversight_core.beacon
====================

Beacon / canary token generation.

Per-file, per-recipient passive callbacks. When a sealed file is opened (or even
its metadata inspected), one or more beacons fire to the attribution registry.

Design principles:
  - PASSIVE ONLY. No code execution on the reader. No RAT. No "active" payloads.
    Beacons are network callbacks that standard document readers make naturally
    during rendering (image fetch, URL resolution, font load, license check).
  - DIVERSITY. Multiple beacon types per file. Stripping one doesn't defeat the others.
  - PER-RECIPIENT. Each recipient's copy has unique beacon URLs.
    A callback identifies not just "the file leaked" but "whose copy leaked".
  - LEGAL. Beacons only phone home to the registry operator's infrastructure;
    they do not exfiltrate data from the reader's machine beyond what any
    standard web request reveals (IP, UA, timestamp).

Beacon types in this MVP:
  - DNS beacon (subdomain resolution — fires before HTTP)
  - HTTP beacon (image-fetch URL suitable for embedding in Office/PDF docs)
  - OCSP-style beacon (cert revocation check — survives very restrictive environments)
  - "License check" beacon (HEAD request to a policy endpoint)

Each beacon is tagged with:
  - token_id    : unique, unguessable, ties callback -> (file_id, recipient_id)
  - beacon_kind : type of callback
  - first_seen  : to be populated by the registry on receipt
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Beacon:
    token_id: str          # 128-bit unguessable
    kind: str              # 'dns' | 'http_img' | 'ocsp' | 'license'
    url: str               # what the reader calls
    dns_name: Optional[str] = None  # for dns kind

    def to_dict(self) -> dict:
        return asdict(self)


def _token() -> str:
    return secrets.token_hex(16)  # 128 bits


def gen_beacons(
    registry_domain: str,
    file_id: str,
    recipient_id: str,
    include: Optional[list[str]] = None,
) -> list[Beacon]:
    """
    Generate a set of beacons for a specific (file, recipient) pair.

    The registry_domain must be under the control of the sealing operator.
    The token_id is the lookup key — the registry maps token_id -> (file_id, recipient_id).
    """
    kinds = include or ["dns", "http_img", "ocsp", "license"]
    out: list[Beacon] = []

    for kind in kinds:
        tid = _token()
        if kind == "dns":
            host = f"{tid}.t.{registry_domain}"
            out.append(Beacon(
                token_id=tid,
                kind="dns",
                url=f"dns://{host}",
                dns_name=host,
            ))
        elif kind == "http_img":
            # 1x1 PNG endpoint, suitable for <img src> in HTML/Office/PDF
            out.append(Beacon(
                token_id=tid,
                kind="http_img",
                url=f"https://b.{registry_domain}/p/{tid}.png",
            ))
        elif kind == "ocsp":
            # OCSP-style POST; readers doing cert checks will hit this
            out.append(Beacon(
                token_id=tid,
                kind="ocsp",
                url=f"https://ocsp.{registry_domain}/r/{tid}",
            ))
        elif kind == "license":
            out.append(Beacon(
                token_id=tid,
                kind="license",
                url=f"https://lic.{registry_domain}/v/{tid}",
            ))
    return out


def beacon_to_img_tag(b: Beacon) -> str:
    """HTML snippet that many office/PDF renderers will fetch on open."""
    return f'<img src="{b.url}" width="1" height="1" alt=""/>'


def beacons_html_block(beacons: list[Beacon]) -> str:
    imgs = "\n".join(beacon_to_img_tag(b) for b in beacons if b.kind == "http_img")
    return f'<div style="display:none">\n{imgs}\n</div>'
