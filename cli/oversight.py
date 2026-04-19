#!/usr/bin/env python3
"""
OVERSIGHT CLI.

Usage:
  oversight keygen --out identity.json
                       Generate a new classic identity (X25519 + Ed25519).

  oversight seal INPUT --recipient-pub PUB.json --issuer-id ID \\
      --issuer-key ISSUER.json --registry-url URL --out OUT.sealed [--watermark]
                       Produce a .sealed file for a recipient.

  oversight open INPUT.sealed --identity IDENT.json --out PLAINTEXT
                       Decrypt a .sealed file.

  oversight inspect INPUT.sealed
                       Dump the (signed) manifest without decrypting.

  oversight attribute --leak LEAK.txt --registry URL
                       Read watermark marks out of leaked text and query registry
                       to identify the source recipient.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

# Make oversight_core importable when running from repo root
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


# ---------------- keygen ----------------

def cmd_keygen(args):
    ident = ClassicIdentity.generate()
    out = {
        "id": args.id or "identity",
        "x25519_priv": ident.x25519_priv.hex(),
        "x25519_pub": ident.x25519_pub.hex(),
        "ed25519_priv": ident.ed25519_priv.hex(),
        "ed25519_pub": ident.ed25519_pub.hex(),
    }
    Path(args.out).write_text(json.dumps(out, indent=2))
    # also write a public-only sibling
    pub_path = Path(args.out).with_suffix(".pub.json")
    pub_path.write_text(json.dumps({
        "id": out["id"],
        "x25519_pub": out["x25519_pub"],
        "ed25519_pub": out["ed25519_pub"],
    }, indent=2))
    print(f"[+] wrote private identity to {args.out}")
    print(f"[+] wrote public  identity to {pub_path}")


# ---------------- seal ----------------

def cmd_seal(args):
    plaintext = Path(args.input).read_bytes()
    issuer = json.loads(Path(args.issuer_key).read_text())
    rec_pub = json.loads(Path(args.recipient_pub).read_text())

    # Optional watermarking (text files only, MVP)
    watermarks_for_manifest: list[WatermarkRef] = []
    if args.watermark:
        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            print("[!] --watermark requires UTF-8 text input; skipping marks")
            text = None

        if text is not None:
            mark_id_zw = watermark.new_mark_id()
            mark_id_ws = watermark.new_mark_id()
            text = watermark.embed_zw(text, mark_id_zw)
            text = watermark.embed_ws(text, mark_id_ws)
            plaintext = text.encode("utf-8")
            watermarks_for_manifest.append(WatermarkRef(
                layer="L1_zero_width", mark_id=mark_id_zw.hex()
            ))
            watermarks_for_manifest.append(WatermarkRef(
                layer="L2_whitespace", mark_id=mark_id_ws.hex()
            ))
            print(f"[+] embedded L1 mark {mark_id_zw.hex()}")
            print(f"[+] embedded L2 mark {mark_id_ws.hex()}")

    # Recipient
    recipient = Recipient(
        recipient_id=rec_pub["id"],
        x25519_pub=rec_pub["x25519_pub"],
        ed25519_pub=rec_pub.get("ed25519_pub"),
    )

    # Beacons
    beacons = beacon.gen_beacons(
        registry_domain=args.registry_domain,
        file_id="pending",  # will be replaced after manifest.new assigns file_id
        recipient_id=rec_pub["id"],
    )

    manifest = Manifest.new(
        original_filename=Path(args.input).name,
        content_hash=content_hash(plaintext),
        size_bytes=len(plaintext),
        issuer_id=args.issuer_id,
        issuer_ed25519_pub_hex=issuer["ed25519_pub"],
        recipient=recipient,
        registry_url=args.registry_url,
        content_type=args.content_type,
    )
    manifest.watermarks = watermarks_for_manifest
    manifest.beacons = [b.to_dict() for b in beacons]

    blob = seal(
        plaintext=plaintext,
        manifest=manifest,
        issuer_ed25519_priv=bytes.fromhex(issuer["ed25519_priv"]),
        recipient_x25519_pub=bytes.fromhex(rec_pub["x25519_pub"]),
    )

    Path(args.out).write_bytes(blob)
    print(f"[+] wrote {args.out} ({len(blob)} bytes)")
    print(f"[+] file_id={manifest.file_id}")
    print(f"[+] recipient={recipient.recipient_id}")
    print(f"[+] beacons={len(beacons)}  watermarks={len(watermarks_for_manifest)}")

    # Register with registry (optional)
    if args.register:
        reg_payload = {
            "manifest": manifest.to_dict(),
            "beacons": [b.to_dict() for b in beacons],
            "watermarks": [w.__dict__ for w in watermarks_for_manifest],
        }
        try:
            resp = httpx.post(
                f"{args.register.rstrip('/')}/register",
                json=reg_payload,
                timeout=10,
            )
            resp.raise_for_status()
            print(f"[+] registered with {args.register}: {resp.json()}")
        except Exception as e:
            print(f"[!] registry registration failed: {e}")


# ---------------- open ----------------

def cmd_open(args):
    blob = Path(args.input).read_bytes()
    ident = json.loads(Path(args.identity).read_text())
    plaintext, manifest = open_sealed(
        blob,
        recipient_x25519_priv=bytes.fromhex(ident["x25519_priv"]),
    )
    Path(args.out).write_bytes(plaintext)
    print(f"[+] decrypted to {args.out}")
    print(f"[+] file_id   = {manifest.file_id}")
    print(f"[+] issuer    = {manifest.issuer_id}")
    print(f"[+] recipient = {manifest.recipient.recipient_id if manifest.recipient else '?'}")
    print(f"[+] marks     = {len(manifest.watermarks)}")
    print(f"[+] beacons   = {len(manifest.beacons)}")


# ---------------- inspect ----------------

def cmd_inspect(args):
    blob = Path(args.input).read_bytes()
    sf = SealedFile.from_bytes(blob)
    print(json.dumps(sf.manifest.to_dict(), indent=2, default=str))
    print()
    print(f"[valid manifest signature] {sf.manifest.verify()}")


# ---------------- attribute ----------------

def cmd_attribute(args):
    text = Path(args.leak).read_text(encoding="utf-8", errors="replace")
    marks = watermark.recover_marks(text)
    print("[*] recovered marks:")
    any_found = False
    for layer, mlist in marks.items():
        for m in mlist:
            print(f"    {layer}: {m.hex()}")
            any_found = True
    if not any_found:
        print("    (none)")
        return

    print(f"[*] querying registry {args.registry} ...")
    for layer, mlist in marks.items():
        for m in mlist:
            try:
                resp = httpx.post(
                    f"{args.registry.rstrip('/')}/attribute",
                    json={"mark_id": m.hex(), "layer": layer},
                    timeout=10,
                )
                data = resp.json()
                if data.get("found"):
                    print(f"\n[!!] ATTRIBUTION: mark {m.hex()} ({layer})")
                    print(f"     file_id      = {data['file_id']}")
                    print(f"     recipient    = {data['recipient_id']}")
                    print(f"     issuer       = {data['issuer_id']}")
            except Exception as e:
                print(f"[!] registry query failed: {e}")


# ---------------- main ----------------

def main():
    p = argparse.ArgumentParser(prog="oversight")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen")
    k.add_argument("--out", required=True)
    k.add_argument("--id", default=None)

    s = sub.add_parser("seal")
    s.add_argument("input")
    s.add_argument("--recipient-pub", required=True)
    s.add_argument("--issuer-id", required=True)
    s.add_argument("--issuer-key", required=True)
    s.add_argument("--registry-url", required=True)
    s.add_argument("--registry-domain", default="oversight.example")
    s.add_argument("--out", required=True)
    s.add_argument("--content-type", default="application/octet-stream")
    s.add_argument("--watermark", action="store_true", help="embed text watermarks")
    s.add_argument("--register", default=None, help="POST manifest to this registry URL")

    o = sub.add_parser("open")
    o.add_argument("input")
    o.add_argument("--identity", required=True)
    o.add_argument("--out", required=True)

    i = sub.add_parser("inspect")
    i.add_argument("input")

    a = sub.add_parser("attribute")
    a.add_argument("--leak", required=True)
    a.add_argument("--registry", required=True)

    args = p.parse_args()

    {
        "keygen": cmd_keygen,
        "seal": cmd_seal,
        "open": cmd_open,
        "inspect": cmd_inspect,
        "attribute": cmd_attribute,
    }[args.cmd](args)


if __name__ == "__main__":
    main()
