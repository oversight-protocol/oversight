#!/usr/bin/env python3
"""
Live demo: integration with the OVERSIGHT registry.

Flow:
  1. Seal a document for Alice and register it with the registry
  2. Simulate the document being opened (triggering image/OCSP/license beacons)
  3. Query the registry for attribution via the beacon token_id
  4. Simulate the plaintext leaking; recover watermarks and attribute via the registry
  5. Pull a full evidence bundle for the file
"""

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx

from oversight_core import (
    ClassicIdentity, Manifest, Recipient, WatermarkRef,
    content_hash, seal, open_sealed, beacon, watermark,
)

REG = "http://127.0.0.1:8765"


def banner(m): print(f"\n{'='*64}\n  {m}\n{'='*64}")


def main():
    banner("1. Generate identities")
    issuer = ClassicIdentity.generate()
    alice = ClassicIdentity.generate()

    banner("2. Prepare watermarked plaintext")
    lines = [f"Acme Q3 forecast - line {i}: confidential projections." for i in range(80)]
    original = "\n".join(lines)
    mark_zw = watermark.new_mark_id()
    mark_ws = watermark.new_mark_id()
    wm_text = watermark.embed_ws(watermark.embed_zw(original, mark_zw), mark_ws)
    plaintext = wm_text.encode("utf-8")
    print(f"  L1 mark = {mark_zw.hex()}")
    print(f"  L2 mark = {mark_ws.hex()}")

    banner("3. Build manifest + beacons, then seal")
    beacons = beacon.gen_beacons("oversight.local", "pending", "alice@acme.corp")
    recipient = Recipient(
        recipient_id="alice@acme.corp",
        x25519_pub=alice.x25519_pub.hex(),
        ed25519_pub=alice.ed25519_pub.hex(),
    )
    m = Manifest.new(
        original_filename="q3_forecast.txt",
        content_hash=content_hash(plaintext),
        size_bytes=len(plaintext),
        issuer_id="acme.corp.legal",
        issuer_ed25519_pub_hex=issuer.ed25519_pub.hex(),
        recipient=recipient,
        registry_url=REG,
        content_type="text/plain",
    )
    m.watermarks = [
        WatermarkRef(layer="L1_zero_width", mark_id=mark_zw.hex()),
        WatermarkRef(layer="L2_whitespace", mark_id=mark_ws.hex()),
    ]
    m.beacons = [b.to_dict() for b in beacons]

    blob = seal(plaintext, m, issuer.ed25519_priv, alice.x25519_pub)
    print(f"  sealed = {len(blob)} bytes")
    print(f"  file_id = {m.file_id}")

    banner("4. Register with registry")
    r = httpx.post(f"{REG}/register", json={
        "manifest": m.to_dict(),
        "beacons": [b.to_dict() for b in beacons],
        "watermarks": [{"mark_id": w.mark_id, "layer": w.layer} for w in m.watermarks],
    })
    print(f"  POST /register -> {r.status_code} {r.json()}")

    banner("5. Simulate reader opening the document (triggers HTTP beacons)")
    # In real life the office/PDF reader fetches <img> beacons automatically
    # against the beacon domain, which resolves to the registry operator's
    # infrastructure. Here we rewrite beacon URLs to the local registry.
    def local_url(b):
        if b.kind == "http_img":
            return f"{REG}/p/{b.token_id}.png"
        if b.kind == "ocsp":
            return f"{REG}/r/{b.token_id}"
        if b.kind == "license":
            return f"{REG}/v/{b.token_id}"
        return None

    triggered = []
    for b in beacons:
        if b.kind == "dns":
            print(f"  [dns ]    would resolve {b.dns_name} (needs DNS server, skipped)")
            continue
        url = local_url(b)
        r = httpx.get(url, follow_redirects=True,
                      headers={"User-Agent": "Mozilla/5.0 OfficeDocViewer/2024"})
        triggered.append(b.token_id)
        print(f"  [{b.kind:<8}] GET {url} -> {r.status_code}")
    time.sleep(0.3)

    banner("6. Query registry for attribution via beacon token_id")
    tid = triggered[0]
    r = httpx.post(f"{REG}/attribute", json={"token_id": tid})
    data = r.json()
    print(f"  found      = {data['found']}")
    print(f"  file_id    = {data['file_id']}")
    print(f"  recipient  = {data['recipient_id']}")
    print(f"  issuer     = {data['issuer_id']}")
    print(f"  events:")
    for e in data["recent_events"][:5]:
        print(f"    {e['qualified_timestamp']}  {e['kind']:<10}  ip={e['source_ip']}  ua={e['user_agent'][:40]}")

    banner("7. Simulate leak: attacker posts plaintext to breach forum")
    # Decrypt Alice's copy, pretend it ended up on BreachForums, and run attribution.
    decrypted, _ = open_sealed(blob, recipient_x25519_priv=alice.x25519_priv)
    leaked_text = decrypted.decode("utf-8")
    print(f"  leaked plaintext size: {len(leaked_text)} chars")

    recovered = watermark.recover_marks(leaked_text)
    for layer, mlist in recovered.items():
        uniq = sorted({mm.hex() for mm in mlist})
        if uniq:
            print(f"  {layer}: recovered unique IDs = {uniq}")

    banner("8. Attribute leaked copy to recipient")
    for layer, mlist in recovered.items():
        seen = set()
        for mm in mlist:
            h = mm.hex()
            if h in seen:
                continue
            seen.add(h)
            r = httpx.post(f"{REG}/attribute", json={"mark_id": h, "layer": layer})
            d = r.json()
            if d.get("found"):
                print(f"  [!!] LEAK ATTRIBUTED via {layer} mark {h}")
                print(f"       file_id   = {d['file_id']}")
                print(f"       recipient = {d['recipient_id']}  <-- source of leak")
                print(f"       issuer    = {d['issuer_id']}")

    banner("9. Pull full evidence bundle")
    r = httpx.get(f"{REG}/evidence/{m.file_id}")
    bundle = r.json()
    print(f"  file_id         = {bundle['file_id']}")
    print(f"  bundle ts       = {bundle['bundle_generated_at']}")
    print(f"  manifest issuer = {bundle['manifest']['issuer_id']}")
    print(f"  beacons         = {len(bundle['beacons'])}")
    print(f"  watermarks      = {len(bundle['watermarks'])}")
    print(f"  events logged   = {len(bundle['events'])}")
    print(f"  disclaimer      = {bundle['disclaimer'][:80]}...")

    banner("DEMO COMPLETE")


if __name__ == "__main__":
    main()
