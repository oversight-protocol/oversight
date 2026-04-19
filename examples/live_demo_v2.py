#!/usr/bin/env python3
"""OVERSIGHT v0.2 live demo - full registry integration including tlog and signed bundles."""

import sys
import time
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx
from oversight_core import (
    ClassicIdentity, Manifest, Recipient, WatermarkRef,
    content_hash, seal, open_sealed, beacon, watermark,
)
from oversight_core import semantic

REG = "http://127.0.0.1:8765"


def banner(m): print(f"\n{'='*64}\n  {m}\n{'='*64}")


def main():
    banner("1. Check registry is up, show well-known")
    r = httpx.get(f"{REG}/.well-known/oversight-registry")
    wk = r.json()
    print(f"  registry pub = {wk['ed25519_pub'][:32]}...")
    print(f"  version      = {wk['version']}")
    print(f"  tlog_size    = {wk['tlog_size']}")

    banner("2. Seal a multi-layer-watermarked document for Alice")
    issuer = ClassicIdentity.generate()
    alice = ClassicIdentity.generate()

    lines = [f"Acme Q3 forecast line {i}: we begin to show significant results and help our customers find answers." for i in range(60)]
    original = "\n".join(lines)
    mid_zw = watermark.new_mark_id()
    mid_ws = watermark.new_mark_id()
    mid_sem = watermark.new_mark_id()
    t = semantic.apply_semantic(original, mid_sem)
    t = watermark.embed_ws(t, mid_ws)
    t = watermark.embed_zw(t, mid_zw)
    plaintext = t.encode("utf-8")
    print(f"  plaintext {len(plaintext)} bytes, 3-layer watermarked")

    beacons = beacon.gen_beacons("oversight.local", "pending", "alice@acme")
    rec = Recipient(recipient_id="alice@acme", x25519_pub=alice.x25519_pub.hex(), ed25519_pub=alice.ed25519_pub.hex())
    m = Manifest.new("q3_forecast.txt", content_hash(plaintext), len(plaintext),
                     "acme", issuer.ed25519_pub.hex(), rec, REG, "text/plain")
    m.watermarks = [
        WatermarkRef(layer="L1_zero_width", mark_id=mid_zw.hex()),
        WatermarkRef(layer="L2_whitespace", mark_id=mid_ws.hex()),
        WatermarkRef(layer="L3_semantic",   mark_id=mid_sem.hex()),
    ]
    m.beacons = [b.to_dict() for b in beacons]
    seal(plaintext, m, issuer.ed25519_priv, alice.x25519_pub)
    print(f"  file_id = {m.file_id}")

    banner("3. Register with v0.2 registry (tlog-backed)")
    r = httpx.post(f"{REG}/register", json={
        "manifest": m.to_dict(),
        "beacons": [b.to_dict() for b in beacons],
        "watermarks": [{"mark_id": w.mark_id, "layer": w.layer} for w in m.watermarks],
    })
    reg_resp = r.json()
    print(f"  /register -> {r.status_code}")
    print(f"  file_id     = {reg_resp['file_id']}")
    print(f"  tlog_index  = {reg_resp['tlog_index']}")

    banner("4. Trigger beacons (HTTP image + OCSP + license)")
    for b in beacons:
        if b.kind == "dns":
            continue
        url_map = {
            "http_img": f"{REG}/p/{b.token_id}.png",
            "ocsp": f"{REG}/r/{b.token_id}",
            "license": f"{REG}/v/{b.token_id}",
        }
        r = httpx.get(url_map[b.kind], headers={"User-Agent": "OfficeDocViewer/2024"})
        print(f"  [{b.kind:<8}] -> {r.status_code}")

    banner("5. Query tlog head and get signed tree state")
    r = httpx.get(f"{REG}/tlog/head")
    head = r.json()
    print(f"  tlog size      = {head['size']}")
    print(f"  tlog root      = {head['root'][:32]}...")
    print(f"  signature      = {head['signature'][:32]}...")

    banner("6. Get inclusion proof for registration event")
    r = httpx.get(f"{REG}/tlog/proof/{reg_resp['tlog_index']}")
    proof = r.json()
    print(f"  proof for idx={proof['index']}:")
    print(f"    leaf hash  = {proof['leaf_hash'][:32]}...")
    print(f"    root       = {proof['root'][:32]}...")
    print(f"    siblings   = {len(proof['proof'])} hashes")

    banner("7. Simulate airgap-strip attack on a leaked copy")
    decrypted, _ = open_sealed(seal(plaintext, m, issuer.ed25519_priv, alice.x25519_pub), alice.x25519_priv)
    leaked = decrypted.decode()
    # Strip L1 zero-width + normalize whitespace (defeats L1 and L2)
    for zw in ("\u200b", "\u200c", "\u200d"):
        leaked = leaked.replace(zw, "")
    leaked = "\n".join(line.rstrip() for line in leaked.splitlines())
    print(f"  post-strip leaked size: {len(leaked)} chars")

    banner("8. L3 semantic attribution against registry")
    # In a real deployment, the scraper would pull candidate mark_ids from the registry.
    # Here we just test against the mark we know.
    result = semantic.verify_semantic(leaked, mid_sem)
    print(f"  synonyms score = {result['synonyms_score']:.3f} (match={result['synonyms_match']})")
    print(f"  overall match  = {result['overall_match']}")
    if result["overall_match"]:
        r = httpx.post(f"{REG}/attribute", json={"mark_id": mid_sem.hex(), "layer": "L3_semantic"})
        data = r.json()
        if data.get("found"):
            print(f"  [!!] LEAK ATTRIBUTED via L3 semantic watermark")
            print(f"       file_id   = {data['file_id']}")
            print(f"       recipient = {data['recipient_id']}  (leaked by)")
            print(f"       issuer    = {data['issuer_id']}")

    banner("9. Request SIGNED evidence bundle")
    r = httpx.get(f"{REG}/evidence/{m.file_id}")
    bundle = r.json()
    print(f"  file_id         = {bundle['file_id']}")
    print(f"  bundle ts       = {bundle['bundle_generated_at']}")
    print(f"  registry pub    = {bundle['registry_pub'][:32]}...")
    print(f"  signature       = {bundle['bundle_signature_ed25519'][:32]}...")
    print(f"  tlog head size  = {bundle['tlog_head']['size']}")
    print(f"  beacons         = {len(bundle['beacons'])}")
    print(f"  watermarks      = {len(bundle['watermarks'])}")
    print(f"  events logged   = {len(bundle['events'])}")

    banner("10. Verify the bundle signature (as an external auditor would)")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(bundle["registry_pub"]))
    sig = bytes.fromhex(bundle.pop("bundle_signature_ed25519"))
    msg = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        pub.verify(sig, msg)
        print("  [ok] bundle signature VERIFIED — this bundle came from this registry.")
    except Exception as e:
        print(f"  [FAIL] signature verification failed: {e}")

    banner("11. Rate-limit test: hit beacon 50x rapidly")
    ok_count = 0
    throttled_count = 0
    for _ in range(50):
        r = httpx.get(f"{REG}/p/{beacons[1].token_id}.png")
        if r.status_code == 200:
            ok_count += 1
        elif r.status_code == 429:
            throttled_count += 1
    print(f"  allowed  = {ok_count}")
    print(f"  throttled= {throttled_count}")
    if throttled_count > 0:
        print("  [ok] rate limiter is working")

    banner("DEMO COMPLETE — v0.2")


if __name__ == "__main__":
    main()
