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
    l3_policy,
)
from oversight_core.container import SealedFile
from oversight_core import semantic
from oversight_core.fingerprint import ContentFingerprint
from oversight_core.safe_io import (
    atomic_write_bytes,
    atomic_write_private_json,
    atomic_write_text,
    validate_output_path,
)


# ---------------- keygen ----------------

def cmd_keygen(args):
    out_path = Path(args.out)
    pub_path = out_path.with_suffix(".pub.json")
    validate_output_path(out_path)
    validate_output_path(pub_path, input_paths=[out_path])
    ident = ClassicIdentity.generate()
    out = {
        "id": args.id or "identity",
        "x25519_priv": ident.x25519_priv.hex(),
        "x25519_pub": ident.x25519_pub.hex(),
        "ed25519_priv": ident.ed25519_priv.hex(),
        "ed25519_pub": ident.ed25519_pub.hex(),
    }
    atomic_write_private_json(out_path, out)
    # also write a public-only sibling
    atomic_write_text(pub_path, json.dumps({
        "id": out["id"],
        "x25519_pub": out["x25519_pub"],
        "ed25519_pub": out["ed25519_pub"],
    }, indent=2))
    print(f"[+] wrote private identity to {args.out}")
    print(f"[+] wrote public  identity to {pub_path}")


# ---------------- seal ----------------

def cmd_seal(args):
    input_path = Path(args.input)
    issuer_path = Path(args.issuer_key)
    recipient_path = Path(args.recipient_pub)
    out_path = Path(args.out)
    validate_output_path(out_path, input_paths=[input_path, issuer_path, recipient_path])
    plaintext = input_path.read_bytes()
    issuer = json.loads(issuer_path.read_text())
    rec_pub = json.loads(recipient_path.read_text())

    canonical_plaintext = plaintext

    # Optional watermarking (text files only)
    watermarks_for_manifest: list[WatermarkRef] = []
    l3_decision = None
    if args.watermark:
        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            print("[!] --watermark requires UTF-8 text input; skipping marks")
            text = None

        if text is not None:
            # Generate a single mark_id shared across all layers for simpler
            # attribution (one ID per recipient, not one per layer).
            mark_id = watermark.new_mark_id()

            l3_decision = l3_policy.decide_l3(
                filename=args.input,
                content_type=args.content_type,
                text=text,
                declared_class=args.document_class,
                requested_mode=args.l3_mode,
            )

            if l3_decision.enabled:
                if not args.l3_ack and not _confirm_l3(l3_decision):
                    raise SystemExit(
                        "L3 changes visible text. Re-run with --l3-mode off, "
                        "--l3-mode boilerplate, or --l3-ack to acknowledge."
                    )
                text = l3_policy.apply_l3_safe(text, mark_id, mode=l3_decision.mode)
                watermarks_for_manifest.append(WatermarkRef(
                    layer=f"L3_semantic_{l3_decision.mode}", mark_id=mark_id.hex()
                ))

            text = watermark.embed_ws(text, mark_id)
            text = watermark.embed_zw(text, mark_id)
            plaintext = text.encode("utf-8")

            watermarks_for_manifest.append(WatermarkRef(
                layer="L1_zero_width", mark_id=mark_id.hex()
            ))
            watermarks_for_manifest.append(WatermarkRef(
                layer="L2_whitespace", mark_id=mark_id.hex()
            ))
            print(f"[+] embedded L1 mark {mark_id.hex()}")
            print(f"[+] embedded L2 mark {mark_id.hex()}")
            if l3_decision and l3_decision.enabled:
                print(f"[+] embedded L3 mark {mark_id.hex()} ({l3_decision.mode})")
            elif l3_decision:
                print(f"[!] L3 skipped: {l3_decision.reason} ({'; '.join(l3_decision.warnings)})")

    # Recipient
    recipient = Recipient(
        recipient_id=rec_pub["id"],
        x25519_pub=rec_pub["x25519_pub"],
        ed25519_pub=rec_pub.get("ed25519_pub"),
    )

    # Beacons
    manifest = Manifest.new(
        original_filename=input_path.name,
        content_hash=content_hash(plaintext),
        size_bytes=len(plaintext),
        issuer_id=args.issuer_id,
        issuer_ed25519_pub_hex=issuer["ed25519_pub"],
        recipient=recipient,
        registry_url=args.registry_url,
        content_type=args.content_type,
    )
    manifest.canonical_content_hash = content_hash(canonical_plaintext)
    if l3_decision:
        manifest.l3_policy = l3_decision.to_dict()
    beacons = beacon.gen_beacons(
        registry_domain=args.registry_domain,
        file_id=manifest.file_id,
        recipient_id=rec_pub["id"],
    )
    manifest.watermarks = watermarks_for_manifest
    manifest.beacons = [b.to_dict() for b in beacons]

    # Compute content fingerprint for the watermarked plaintext.
    # This is the per-recipient fingerprint stored server-side so we can
    # identify the source copy even if all watermarks are stripped (VM export attack).
    fingerprint = None
    try:
        fingerprint_text = plaintext.decode("utf-8")
        fingerprint = ContentFingerprint.from_text(fingerprint_text)
        print(f"[+] content fingerprint: {len(fingerprint.winnowing_fp)} winnow hashes, "
              f"{len(fingerprint.sentence_fp)} sentence hashes")
    except UnicodeDecodeError:
        pass  # binary file, no fingerprint

    blob = seal(
        plaintext=plaintext,
        manifest=manifest,
        issuer_ed25519_priv=bytes.fromhex(issuer["ed25519_priv"]),
        recipient_x25519_pub=bytes.fromhex(rec_pub["x25519_pub"]),
    )

    atomic_write_bytes(out_path, blob)
    print(f"[+] wrote {args.out} ({len(blob)} bytes)")
    print(f"[+] file_id={manifest.file_id}")
    print(f"[+] recipient={recipient.recipient_id}")
    print(f"[+] beacons={len(beacons)}  watermarks={len(watermarks_for_manifest)}")

    # Store fingerprint alongside the sealed file
    if fingerprint:
        fp_path = out_path.with_suffix(".fingerprint.json")
        atomic_write_text(fp_path, json.dumps({
            "file_id": manifest.file_id,
            "recipient_id": rec_pub["id"],
            "mark_id": watermarks_for_manifest[0].mark_id if watermarks_for_manifest else None,
            "canonical_content_hash": manifest.canonical_content_hash,
            "l3_policy": manifest.l3_policy,
            "fingerprint": fingerprint.to_dict(),
        }, indent=2))
        print(f"[+] wrote fingerprint to {fp_path}")

    # Register with registry (optional)
    if args.register:
        reg_payload = {
            "manifest": manifest.to_dict(),
            "beacons": [b.to_dict() for b in beacons],
            "watermarks": [w.__dict__ for w in watermarks_for_manifest],
        }
        if fingerprint:
            reg_payload["fingerprint"] = fingerprint.to_dict()
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
    input_path = Path(args.input)
    identity_path = Path(args.identity)
    out_path = Path(args.out)
    validate_output_path(out_path, input_paths=[input_path, identity_path])
    blob = input_path.read_bytes()
    ident = json.loads(identity_path.read_text())
    plaintext, manifest = open_sealed(
        blob,
        recipient_x25519_priv=bytes.fromhex(ident["x25519_priv"]),
    )
    atomic_write_bytes(out_path, plaintext)
    print(f"[+] decrypted to {args.out}")
    print(f"[+] file_id   = {manifest.file_id}")
    print(f"[+] issuer    = {manifest.issuer_id}")
    print(f"[+] recipient = {manifest.recipient.recipient_id if manifest.recipient else '?'}")
    print(f"[+] marks     = {len(manifest.watermarks)}")
    print(f"[+] beacons   = {len(manifest.beacons)}")


def _confirm_l3(decision) -> bool:
    print("[!] L3 semantic watermarking changes visible prose.")
    print(f"    document_class={decision.document_class} mode={decision.mode}")
    print(f"    reason={decision.reason}")
    if not sys.stdin.isatty():
        return False
    answer = input("    Type 'I ACKNOWLEDGE' to continue: ").strip()
    return answer == "I ACKNOWLEDGE"


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

    # Phase 1: Extract L1/L2 marks directly from text
    print("[*] Phase 1: Direct extraction (L1 + L2)")
    l1_marks = watermark.extract_zw(text)
    l2_candidate, l2_conf, l2_bits, l2_needed = watermark.extract_ws_partial(text)

    l1_unique = list(set(l1_marks))
    direct_candidates: list[bytes] = list(l1_unique)
    if l2_candidate and l2_conf >= 0.5:
        if l2_candidate not in direct_candidates:
            direct_candidates.append(l2_candidate)

    if l1_unique:
        print(f"    L1: {len(l1_marks)} frames, {len(l1_unique)} unique mark(s)")
        for m in l1_unique:
            print(f"        {m.hex()}")
    else:
        print("    L1: no zero-width frames found (stripped?)")

    if l2_conf >= 1.0:
        print(f"    L2: {l2_bits}/{l2_needed} bits recovered (100%): {l2_candidate.hex()}")
    elif l2_conf > 0:
        print(f"    L2: {l2_bits}/{l2_needed} bits recovered ({l2_conf:.0%}): {l2_candidate.hex()} (partial)")
    else:
        print("    L2: no trailing whitespace marks found (stripped?)")

    # Phase 2: Query registry for candidate mark_ids (for L3 verification)
    registry_candidates: list[bytes] = []
    print(f"\n[*] Phase 2: Registry query ({args.registry})")
    if direct_candidates:
        for m in direct_candidates:
            try:
                resp = httpx.post(
                    f"{args.registry.rstrip('/')}/attribute",
                    json={"mark_id": m.hex(), "layer": "L1_zero_width"},
                    timeout=10,
                )
                data = resp.json()
                if data.get("found"):
                    print(f"    MATCH: {m.hex()} -> recipient={data['recipient_id']}, "
                          f"file={data['file_id']}")
            except Exception as e:
                print(f"    registry query failed: {e}")

    # Also fetch all mark_ids for this file (for L3 verification)
    try:
        resp = httpx.get(
            f"{args.registry.rstrip('/')}/marks",
            timeout=10,
        )
        if resp.status_code == 200:
            registry_data = resp.json()
            for entry in registry_data.get("marks", []):
                mid_bytes = bytes.fromhex(entry["mark_id"])
                if mid_bytes not in registry_candidates:
                    registry_candidates.append(mid_bytes)
            print(f"    fetched {len(registry_candidates)} candidate mark_id(s) from registry")
    except Exception:
        pass  # registry may not support /marks endpoint

    # Phase 3: L3 semantic verification against candidates
    all_candidates = direct_candidates + [
        m for m in registry_candidates if m not in direct_candidates
    ]

    print(f"\n[*] Phase 3: L3 semantic verification ({len(all_candidates)} candidate(s))")
    if all_candidates:
        l3_hits = watermark.verify_l3(text, all_candidates)
        if l3_hits:
            for mid, score, detail in l3_hits:
                print(f"    L3 MATCH: {mid.hex()} score={score:.2f} "
                      f"(synonyms={detail['synonyms_score']:.2f}, "
                      f"punct={detail['punctuation_hits']}, "
                      f"dict={detail['dict_version']})")
        else:
            print("    L3: no candidates matched above threshold")
    else:
        print("    L3: no candidates available (L1/L2 stripped, registry unreachable?)")

    # Phase 4: Multi-layer fusion
    print("\n[*] Phase 4: Multi-layer fusion")
    result = watermark.recover_marks_v2(text, all_candidates if all_candidates else None)
    if result["candidates"]:
        for mark_id, score, layers in result["candidates"]:
            print(f"    {mark_id.hex()}  score={score:.3f}  layers={layers}")
        best = result["candidates"][0]
        print(f"\n[!!] BEST ATTRIBUTION: {best[0].hex()}")
        print(f"     confidence = {best[1]:.1%}")
        print(f"     evidence   = {best[2]}")

        # Final registry lookup for the winning candidate
        try:
            resp = httpx.post(
                f"{args.registry.rstrip('/')}/attribute",
                json={"mark_id": best[0].hex(), "layer": "fused"},
                timeout=10,
            )
            data = resp.json()
            if data.get("found"):
                print(f"     file_id    = {data['file_id']}")
                print(f"     recipient  = {data['recipient_id']}")
                print(f"     issuer     = {data['issuer_id']}")
        except Exception:
            pass
    else:
        print("    No marks recovered from any layer.")
        print("\n[*] Diagnostics:")
        for d in result["diagnostics"]:
            print(f"    {d}")

    # Phase 5: Content fingerprint comparison (VM-strip-export defense)
    if args.fingerprints:
        print(f"\n[*] Phase 5: Content fingerprint comparison")
        leak_fp = ContentFingerprint.from_text(text)
        print(f"    Leak fingerprint: {len(leak_fp.winnowing_fp)} winnow hashes, "
              f"{len(leak_fp.sentence_fp)} sentence hashes")

        best_fp_match = None
        best_fp_score = 0.0

        fp_dir = Path(args.fingerprints)
        if fp_dir.is_dir():
            fp_files = list(fp_dir.glob("*.fingerprint.json"))
        elif fp_dir.is_file():
            fp_files = [fp_dir]
        else:
            fp_files = []
            print(f"    [!] fingerprint path not found: {args.fingerprints}")

        for fp_file in fp_files:
            try:
                fp_data = json.loads(fp_file.read_text())
                stored_fp = ContentFingerprint.from_dict(fp_data["fingerprint"])
                sim = leak_fp.similarity(stored_fp)
                recipient_id = fp_data.get("recipient_id", "unknown")
                mark_id = fp_data.get("mark_id", "unknown")

                if sim["combined"] >= 0.1:
                    print(f"    {fp_file.name}: recipient={recipient_id} "
                          f"winnow={sim['winnowing']:.2f} "
                          f"sentence={sim['sentence']:.2f} "
                          f"combined={sim['combined']:.2f} "
                          f"[{sim['verdict']}]")

                if sim["combined"] > best_fp_score:
                    best_fp_score = sim["combined"]
                    best_fp_match = {
                        "file": fp_file.name,
                        "recipient_id": recipient_id,
                        "mark_id": mark_id,
                        "similarity": sim,
                    }
            except Exception as e:
                print(f"    [!] error reading {fp_file.name}: {e}")

        if best_fp_match and best_fp_score >= 0.3:
            verdict = best_fp_match["similarity"]["verdict"]
            print(f"\n[!!] FINGERPRINT ATTRIBUTION [{verdict}]:")
            print(f"     recipient  = {best_fp_match['recipient_id']}")
            print(f"     mark_id    = {best_fp_match['mark_id']}")
            print(f"     confidence = {best_fp_score:.1%}")
            print(f"     winnowing  = {best_fp_match['similarity']['winnowing']:.1%}")
            print(f"     sentence   = {best_fp_match['similarity']['sentence']:.1%}")
        elif fp_files:
            print("    No fingerprint match above threshold.")
        else:
            print("    No fingerprint files found to compare against.")


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
    s.add_argument("--registry-domain", default="oversightprotocol.dev")
    s.add_argument("--out", required=True)
    s.add_argument("--content-type", default="application/octet-stream")
    s.add_argument("--watermark", action="store_true", help="embed text watermarks")
    s.add_argument("--l3-mode", choices=("auto", "off", "full", "boilerplate"), default="auto",
                   help="semantic L3 mode; auto disables L3 for wording-sensitive document classes")
    s.add_argument("--l3-ack", action="store_true",
                   help="acknowledge that enabled L3 makes recipient text non-identical")
    s.add_argument("--document-class",
                   choices=("auto", "prose", "legal", "regulatory", "technical_spec",
                            "source_code", "sql", "log", "structured_data"),
                   default="auto",
                   help="declare document class for L3 safety decisions")
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
    a.add_argument("--fingerprints", default=None,
                   help="path to fingerprint file or directory for VM-strip detection")

    args = p.parse_args()

    try:
        {
            "keygen": cmd_keygen,
            "seal": cmd_seal,
            "open": cmd_open,
            "inspect": cmd_inspect,
            "attribute": cmd_attribute,
        }[args.cmd](args)
    except (ValueError, FileExistsError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[!] {exc}") from exc


if __name__ == "__main__":
    main()
