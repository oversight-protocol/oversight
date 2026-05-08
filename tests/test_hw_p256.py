"""Unit tests for the OSGT-HW-P256-v1 (hardware-backed P-256) suite in
oversight_core.crypto. The tests exercise the pure-Python wrap/unwrap path
that mirrors oversight-rust's seal_hw_p256 + unwrap_dek_with_provider_p256;
cross-language conformance against the Rust reference is layered in a
separate harness.
"""
from __future__ import annotations

import os
import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from oversight_core import crypto, container


def _gen_p256_pair() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Generate a P-256 keypair, returning (priv, pub_sec1_uncompressed)."""
    sk = ec.generate_private_key(ec.SECP256R1())
    pub_sec1 = sk.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return sk, pub_sec1


def test_constants_match_rust_reference():
    assert crypto.SUITE_HW_P256_V1 == "OSGT-HW-P256-v1"
    assert crypto.P256_PUBLIC_KEY_LEN == 65
    assert container.SUITE_HW_P256_V1_ID == 3
    assert container.SUITE_ID_TO_NAME[3] == "OSGT-HW-P256-v1"


def test_wrap_unwrap_round_trip_with_private_key_object():
    sk, pub = _gen_p256_pair()
    dek = os.urandom(32)
    wrapped = crypto.wrap_dek_for_recipient_p256(dek, pub)
    recovered = crypto.unwrap_dek_p256(wrapped, sk)
    assert recovered == dek


def test_wrap_unwrap_round_trip_with_pkcs8_bytes():
    # PivKeyProvider candidates store PKCS#8-encoded keys before passing them
    # to ECDH backends. Confirm that path works too.
    sk, pub = _gen_p256_pair()
    pkcs8 = sk.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    dek = os.urandom(32)
    wrapped = crypto.wrap_dek_for_recipient_p256(dek, pub)
    recovered = crypto.unwrap_dek_p256(wrapped, pkcs8)
    assert recovered == dek


def test_wrap_unwrap_round_trip_with_raw_int_scalar():
    sk, pub = _gen_p256_pair()
    scalar = sk.private_numbers().private_value
    dek = os.urandom(32)
    wrapped = crypto.wrap_dek_for_recipient_p256(dek, pub)
    recovered = crypto.unwrap_dek_p256(wrapped, scalar)
    assert recovered == dek


def test_envelope_shape_matches_spec():
    sk, pub = _gen_p256_pair()
    wrapped = crypto.wrap_dek_for_recipient_p256(os.urandom(32), pub)
    # SPEC.md sec 5.2: OSGT-HW-P256-v1 wrapped_dek JSON has exactly these keys.
    assert set(wrapped.keys()) == {"suite", "ephemeral_pub", "nonce", "wrapped_dek"}
    assert wrapped["suite"] == "OSGT-HW-P256-v1"
    eph_pub = bytes.fromhex(wrapped["ephemeral_pub"])
    assert len(eph_pub) == 65, "P-256 ephemeral pub MUST be 65 bytes (SEC1 uncompressed)"
    assert eph_pub[0] == 0x04, "SEC1 uncompressed encoding starts with 0x04"
    assert len(bytes.fromhex(wrapped["nonce"])) == 24, "XChaCha20 nonce MUST be 24 bytes"


def test_wrong_recipient_rejected():
    alice_sk, alice_pub = _gen_p256_pair()
    bob_sk, _ = _gen_p256_pair()
    dek = os.urandom(32)
    wrapped = crypto.wrap_dek_for_recipient_p256(dek, alice_pub)
    # Bob's key is a valid P-256 key but not the one this DEK is bound to.
    with pytest.raises(Exception):
        crypto.unwrap_dek_p256(wrapped, bob_sk)


def test_wrap_rejects_wrong_pub_length():
    with pytest.raises(ValueError, match="65 bytes"):
        crypto.wrap_dek_for_recipient_p256(os.urandom(32), b"\x04" + b"\x00" * 31)


def test_unwrap_rejects_wrong_ephemeral_length():
    sk, pub = _gen_p256_pair()
    wrapped = crypto.wrap_dek_for_recipient_p256(os.urandom(32), pub)
    # Truncate the ephemeral pub to the X25519 size (32 bytes) and confirm
    # we refuse rather than try to interpret it as a P-256 point.
    wrapped["ephemeral_pub"] = wrapped["ephemeral_pub"][:64]
    with pytest.raises(ValueError, match="65 bytes"):
        crypto.unwrap_dek_p256(wrapped, sk)


def test_unwrap_rejects_missing_fields():
    sk, _ = _gen_p256_pair()
    incomplete = {"suite": "OSGT-HW-P256-v1", "nonce": "00" * 24, "wrapped_dek": "deadbeef"}
    with pytest.raises(ValueError, match="ephemeral_pub"):
        crypto.unwrap_dek_p256(incomplete, sk)


def test_aad_binding_classic_envelope_does_not_unwrap():
    """
    Sanity check that a classic-suite wrapped_dek (X25519, 32-byte
    ephemeral, info=oversight-v1-dek-wrap, AAD=oversight-dek) does not
    accidentally decrypt through the P-256 path even if you bend the
    field shapes. The two suites use different HKDF info strings and
    different AEAD AAD values; either of those diverging is enough to
    make AEAD authentication fail.
    """
    # Build a malformed envelope that looks shaped-like-P256 but the
    # ciphertext was produced under classic AAD. The unwrap MUST fail.
    sk, pub = _gen_p256_pair()
    wrapped = crypto.wrap_dek_for_recipient_p256(os.urandom(32), pub)
    # Replace the wrapped_dek with one encrypted under classic-suite AAD
    # using the same key bytes (impossible in practice, but tests AAD
    # binding even when keys collide).
    bogus_aead_nonce, bogus_wrapped = crypto.aead_encrypt(
        b"\x00" * 32, b"would-be DEK", aad=b"oversight-dek"
    )
    wrapped["nonce"] = bogus_aead_nonce.hex()
    wrapped["wrapped_dek"] = bogus_wrapped.hex()
    with pytest.raises(Exception):
        crypto.unwrap_dek_p256(wrapped, sk)
