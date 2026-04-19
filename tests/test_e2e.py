#!/usr/bin/env python3
"""
End-to-end test of the OVERSIGHT MVP.

Exercises:
  1. Identity generation (issuer + two recipients)
  2. Sealing a text file for recipient Alice with watermarks + beacons
  3. Inspecting the sealed file (manifest visible, ciphertext opaque)
  4. Alice opens it successfully
  5. Bob (wrong key) fails to open it
  6. Tampering with the ciphertext is detected
  7. Tampering with the manifest is detected
  8. Watermark recovery from leaked plaintext identifies Alice
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oversight_core import (
    ClassicIdentity,
    Manifest,
    Recipient,
    WatermarkRef,
    content_hash,
    seal,
    open_sealed,
    beacon,
    watermark,
)
from oversight_core.container import SealedFile


def banner(msg):
    print(f"\n{'=' * 60}\n  {msg}\n{'=' * 60}")


def main():
    banner("1. Generate identities")
    issuer = ClassicIdentity.generate()
    alice = ClassicIdentity.generate()
    bob = ClassicIdentity.generate()
    print(f"  issuer  ed25519_pub = {issuer.ed25519_pub.hex()[:32]}...")
    print(f"  alice   x25519_pub  = {alice.x25519_pub.hex()[:32]}...")
    print(f"  bob     x25519_pub  = {bob.x25519_pub.hex()[:32]}...")

    banner("2. Prepare & watermark plaintext")
    # Multi-line text so the per-line L2 watermark has enough lines to encode 64 bits.
    lines = [
        "CONFIDENTIAL - Q2 Revenue Memo",
        "Revenue for Q2 exceeded projections by 18%.",
        "Do not distribute externally.",
        "",
    ]
    for i in range(80):
        lines.append(f"Supporting detail line {i}: filler content for watermark room.")
    original_text = "\n".join(lines)
    mark_zw = watermark.new_mark_id()
    mark_ws = watermark.new_mark_id()
    wm_text = watermark.embed_zw(original_text, mark_zw)
    wm_text = watermark.embed_ws(wm_text, mark_ws)
    plaintext = wm_text.encode("utf-8")
    print(f"  original bytes  = {len(original_text.encode())}")
    print(f"  watermarked     = {len(plaintext)}")
    print(f"  L1 mark (zw)    = {mark_zw.hex()}")
    print(f"  L2 mark (ws)    = {mark_ws.hex()}")

    banner("3. Build manifest + beacons for Alice")
    beacons = beacon.gen_beacons(
        registry_domain="oversight.test",
        file_id="will-be-assigned",
        recipient_id="alice@example.com",
    )
    recipient = Recipient(
        recipient_id="alice@example.com",
        x25519_pub=alice.x25519_pub.hex(),
        ed25519_pub=alice.ed25519_pub.hex(),
    )
    manifest = Manifest.new(
        original_filename="q2_memo.txt",
        content_hash=content_hash(plaintext),
        size_bytes=len(plaintext),
        issuer_id="acme.corp.legal",
        issuer_ed25519_pub_hex=issuer.ed25519_pub.hex(),
        recipient=recipient,
        registry_url="https://registry.oversight.test",
        content_type="text/plain",
    )
    manifest.watermarks = [
        WatermarkRef(layer="L1_zero_width", mark_id=mark_zw.hex()),
        WatermarkRef(layer="L2_whitespace", mark_id=mark_ws.hex()),
    ]
    manifest.beacons = [b.to_dict() for b in beacons]
    print(f"  file_id = {manifest.file_id}")
    print(f"  beacons = {len(beacons)}")
    print(f"  marks   = {len(manifest.watermarks)}")

    banner("4. Seal")
    blob = seal(
        plaintext=plaintext,
        manifest=manifest,
        issuer_ed25519_priv=issuer.ed25519_priv,
        recipient_x25519_pub=alice.x25519_pub,
    )
    print(f"  sealed blob     = {len(blob)} bytes")
    print(f"  magic OK        = {blob[:6] == bytes([ord('S'),ord('N'),ord('T'),ord('L'),1,0])}")
    print(f"  manifest signed = {manifest.verify()}")

    banner("5. Inspect (no key needed for metadata)")
    sf = SealedFile.from_bytes(blob)
    print(f"  manifest.file_id    = {sf.manifest.file_id}")
    print(f"  manifest.recipient  = {sf.manifest.recipient.recipient_id}")
    print(f"  manifest sig valid  = {sf.manifest.verify()}")

    banner("6. Alice opens (correct key)")
    recovered, m = open_sealed(blob, recipient_x25519_priv=alice.x25519_priv)
    print(f"  decrypted = {len(recovered)} bytes")
    print(f"  exact match to original plaintext = {recovered == plaintext}")

    banner("7. Bob (wrong key) attempts to open")
    try:
        open_sealed(blob, recipient_x25519_priv=bob.x25519_priv)
        print("  FAIL — bob should not have been able to decrypt")
        sys.exit(1)
    except Exception as e:
        print(f"  correctly rejected: {type(e).__name__}: {str(e)[:60]}")

    banner("8. Tamper with ciphertext")
    bad = bytearray(blob)
    # flip the last byte (inside the ciphertext/tag region)
    bad[-1] ^= 0x01
    try:
        open_sealed(bytes(bad), recipient_x25519_priv=alice.x25519_priv)
        print("  FAIL — ciphertext tamper should have been caught")
        sys.exit(1)
    except Exception as e:
        print(f"  correctly rejected: {type(e).__name__}: {str(e)[:60]}")

    banner("9. Tamper with manifest (flip a byte inside the manifest region)")
    bad2 = bytearray(blob)
    # manifest starts at offset 12
    bad2[30] ^= 0x01
    try:
        # this will probably fail at JSON parse or sig-verify
        open_sealed(bytes(bad2), recipient_x25519_priv=alice.x25519_priv)
        print("  FAIL — manifest tamper should have been caught")
        sys.exit(1)
    except Exception as e:
        print(f"  correctly rejected: {type(e).__name__}: {str(e)[:60]}")

    banner("10. Watermark recovery from leaked plaintext")
    leaked = recovered.decode("utf-8")
    marks = watermark.recover_marks(leaked)
    for layer, mlist in marks.items():
        uniq = sorted({m.hex() for m in mlist})
        print(f"  {layer}: {len(mlist)} frame(s), unique IDs: {uniq}")
    # Assert Alice's marks are among them
    found_zw = mark_zw in marks["L1_zero_width"]
    found_ws = any(m == mark_ws for m in marks["L2_whitespace"])
    print(f"  L1 recovered = {found_zw}")
    print(f"  L2 recovered = {found_ws}")
    assert found_zw, "L1 watermark recovery failed"
    assert found_ws, "L2 watermark recovery failed"

    banner("11. Watermark survives format stripping (paste into new doc)")
    # Simulate "attacker pastes plaintext into a new document" — plain string ops
    pasted = "\n".join(line for line in leaked.splitlines())
    # This preserves invisibles but strips our trailing-ws marks
    marks2 = watermark.recover_marks(pasted)
    print(f"  L1 (zw) survived copy-paste: {mark_zw in marks2['L1_zero_width']}")
    print(f"  L2 (ws) survived copy-paste: "
          f"{any(m == mark_ws for m in marks2['L2_whitespace'])}")

    banner("ALL TESTS PASSED")


if __name__ == "__main__":
    main()
