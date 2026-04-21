"""
test_gui_hardening_unit
=======================

Focused checks for GUI/CLI filesystem safety and container parser hardening.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cli import gui
from oversight_core import ClassicIdentity, Manifest, Recipient, content_hash, seal
from oversight_core.container import SealedFile
from oversight_core.safe_io import is_private_key_file, validate_output_path


def _identity_dict(identity_id: str = "alice") -> dict:
    ident = ClassicIdentity.generate()
    return {
        "id": identity_id,
        "x25519_priv": ident.x25519_priv.hex(),
        "x25519_pub": ident.x25519_pub.hex(),
        "ed25519_priv": ident.ed25519_priv.hex(),
        "ed25519_pub": ident.ed25519_pub.hex(),
    }


def _sealed_blob() -> bytes:
    issuer = ClassicIdentity.generate()
    recipient = ClassicIdentity.generate()
    plaintext = b"hello oversight"
    manifest = Manifest.new(
        "hello.txt",
        content_hash(plaintext),
        len(plaintext),
        "issuer",
        issuer.ed25519_pub.hex(),
        Recipient("alice", recipient.x25519_pub.hex(), recipient.ed25519_pub.hex()),
        "https://registry.oversightprotocol.dev",
        "text/plain",
    )
    return seal(plaintext, manifest, issuer.ed25519_priv, recipient.x25519_pub)


def t1_private_key_outputs_are_blocked():
    with tempfile.TemporaryDirectory() as td:
        key_path = Path(td) / "alice.priv.json"
        key_path.write_text(json.dumps(_identity_dict()), encoding="utf-8")
        assert is_private_key_file(key_path), "fixture should parse as private key"
        try:
            validate_output_path(key_path)
        except ValueError as exc:
            assert "private key" in str(exc)
        else:
            raise AssertionError("private key overwrite was not blocked")
    print("  [PASS] private key output targets are hard-blocked")


def t2_same_path_outputs_are_blocked():
    with tempfile.TemporaryDirectory() as td:
        input_path = Path(td) / "source.txt"
        input_path.write_text("source", encoding="utf-8")
        try:
            validate_output_path(input_path, input_paths=[input_path])
        except ValueError as exc:
            assert "different" in str(exc)
        else:
            raise AssertionError("same-path output was not blocked")
    print("  [PASS] output paths cannot equal input paths")


def t3_windows_reserved_names_are_rejected():
    try:
        validate_output_path(Path("NUL.priv.json"))
    except ValueError as exc:
        assert "reserved" in str(exc)
    else:
        raise AssertionError("Windows reserved output name was not blocked")
    print("  [PASS] Windows reserved output names are rejected")


def t4_gui_key_shape_errors_are_friendly():
    with tempfile.TemporaryDirectory() as td:
        pub_path = Path(td) / "alice.pub.json"
        pub_path.write_text(json.dumps({"id": "alice", "x25519_pub": "00" * 32}), encoding="utf-8")
        try:
            gui._read_private_identity(pub_path, "Issuer file")
        except ValueError as exc:
            assert "public key" in str(exc) and "x25519_priv" in str(exc)
        else:
            raise AssertionError("public key accepted as private identity")
    print("  [PASS] key-shape mistakes get actionable GUI errors")


def t5_gui_registry_domain_uses_user_url():
    assert gui._registry_domain("https://registry.example.test:8443/api") == "registry.example.test:8443"
    print("  [PASS] GUI beacon domain derives from the configured registry URL")


def t6_container_rejects_suite_id_tamper():
    blob = bytearray(_sealed_blob())
    blob[7] ^= 0x01
    try:
        SealedFile.from_bytes(bytes(blob))
    except ValueError as exc:
        assert "suite" in str(exc).lower()
    else:
        raise AssertionError("suite_id tamper was accepted")
    print("  [PASS] unauthenticated suite_id tamper is rejected")


def t7_container_rejects_trailing_bytes():
    try:
        SealedFile.from_bytes(_sealed_blob() + b"junk")
    except ValueError as exc:
        assert "Trailing bytes" in str(exc)
    else:
        raise AssertionError("trailing bytes were accepted")
    print("  [PASS] trailing bytes after ciphertext are rejected")


def main():
    print("=" * 60)
    print("  GUI/CLI hardening - focused unit tests")
    print("=" * 60)
    t1_private_key_outputs_are_blocked()
    t2_same_path_outputs_are_blocked()
    t3_windows_reserved_names_are_rejected()
    t4_gui_key_shape_errors_are_friendly()
    t5_gui_registry_domain_uses_user_url()
    t6_container_rejects_suite_id_tamper()
    t7_container_rejects_trailing_bytes()
    print()
    print("  ALL TESTS PASSED - 7/7")


if __name__ == "__main__":
    main()
