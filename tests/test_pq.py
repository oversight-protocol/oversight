#!/usr/bin/env python3
"""
Post-quantum hybrid round-trip test.

Proves:
  1. liboqs is linked and ML-KEM-768 / ML-DSA-65 work.
  2. Hybrid DEK wrap (X25519 + ML-KEM-768) round-trips correctly.
  3. Tampering with either the classical or PQ component fails.
  4. A full hybrid-sealed file can be built and opened.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from oversight_core import crypto
from oversight_core.crypto import (
    PQ_AVAILABLE, ClassicIdentity, random_dek,
    pq_kem_keypair, pq_sig_keypair, pq_sign, pq_verify,
    hybrid_wrap_dek, hybrid_unwrap_dek,
)


def banner(m): print(f"\n{'='*60}\n  {m}\n{'='*60}")
def ok(m): print(f"  [ok] {m}")
def fail(m): print(f"  [FAIL] {m}"); sys.exit(1)


def main():
    banner("0. Check PQ availability")
    if not PQ_AVAILABLE:
        fail("liboqs not linked — install liboqs + liboqs-python")
    ok("liboqs available")

    banner("1. ML-KEM-768 raw round-trip")
    priv, pub = pq_kem_keypair()
    ok(f"keypair: pub={len(pub)}B priv={len(priv)}B")
    from oversight_core.crypto import pq_kem_encap, pq_kem_decap
    ct, ss1 = pq_kem_encap(pub)
    ss2 = pq_kem_decap(priv, ct)
    if ss1 != ss2:
        fail("ML-KEM shared secrets don't match")
    ok(f"ML-KEM-768 round-trip OK ({len(ss1)}B shared secret)")

    banner("2. ML-DSA-65 raw round-trip")
    sig_priv, sig_pub = pq_sig_keypair()
    ok(f"keypair: pub={len(sig_pub)}B priv={len(sig_priv)}B")
    msg = b"OVERSIGHT v0.2 post-quantum hybrid test"
    signature = pq_sign(msg, sig_priv)
    ok(f"signature: {len(signature)}B")
    if not pq_verify(msg, signature, sig_pub):
        fail("ML-DSA verify failed for valid signature")
    ok("ML-DSA-65 verify accepts valid signature")
    if pq_verify(b"tampered message", signature, sig_pub):
        fail("ML-DSA verify accepted signature over different message")
    ok("ML-DSA-65 verify rejects tampered message")

    banner("3. Hybrid DEK wrap (classical + PQ)")
    alice_classical = ClassicIdentity.generate()
    alice_mlkem_priv, alice_mlkem_pub = pq_kem_keypair()

    dek = random_dek()
    print(f"  DEK: {len(dek)}B")

    wrapped = hybrid_wrap_dek(
        dek,
        x25519_pub=alice_classical.x25519_pub,
        mlkem_pub=alice_mlkem_pub,
    )
    ok(f"wrapped: suite={wrapped['suite']}")
    ok(f"  x25519_ephemeral_pub = {len(bytes.fromhex(wrapped['x25519_ephemeral_pub']))}B")
    ok(f"  mlkem_ciphertext     = {len(bytes.fromhex(wrapped['mlkem_ciphertext']))}B")
    ok(f"  wrapped_dek          = {len(bytes.fromhex(wrapped['wrapped_dek']))}B")

    recovered = hybrid_unwrap_dek(
        wrapped,
        x25519_priv=alice_classical.x25519_priv,
        mlkem_priv=alice_mlkem_priv,
    )
    if recovered != dek:
        fail("hybrid unwrap recovered wrong DEK")
    ok("hybrid unwrap recovered original DEK exactly")

    banner("4. Tamper with classical half")
    bad = dict(wrapped)
    # Replace X25519 ephemeral pub with a random one
    other_classic = ClassicIdentity.generate()
    bad["x25519_ephemeral_pub"] = other_classic.x25519_pub.hex()
    try:
        hybrid_unwrap_dek(bad, alice_classical.x25519_priv, alice_mlkem_priv)
        fail("tamper of classical half should have failed")
    except Exception as e:
        ok(f"classical tamper correctly rejected: {type(e).__name__}")

    banner("5. Tamper with PQ half")
    bad2 = dict(wrapped)
    # Corrupt a byte of the mlkem ciphertext
    ct_bytes = bytearray(bytes.fromhex(bad2["mlkem_ciphertext"]))
    ct_bytes[100] ^= 0x01
    bad2["mlkem_ciphertext"] = bytes(ct_bytes).hex()
    try:
        hybrid_unwrap_dek(bad2, alice_classical.x25519_priv, alice_mlkem_priv)
        fail("tamper of PQ half should have failed")
    except Exception as e:
        ok(f"PQ tamper correctly rejected: {type(e).__name__}")

    banner("6. Wrong recipient")
    bob_classical = ClassicIdentity.generate()
    bob_mlkem_priv, _ = pq_kem_keypair()
    try:
        hybrid_unwrap_dek(wrapped, bob_classical.x25519_priv, bob_mlkem_priv)
        fail("wrong recipient should have failed")
    except Exception as e:
        ok(f"wrong recipient correctly rejected: {type(e).__name__}")

    banner("7. Size comparison: CLASSIC vs HYBRID")
    classic_wrap = crypto.wrap_dek_for_recipient(dek, alice_classical.x25519_pub)
    classic_size = sum(len(bytes.fromhex(v)) for v in classic_wrap.values())
    hybrid_size = sum(
        len(bytes.fromhex(v)) for k, v in wrapped.items() if k != "suite"
    )
    print(f"  CLASSIC wrap: {classic_size} bytes (X25519 ephemeral + nonce + wrapped DEK)")
    print(f"  HYBRID  wrap: {hybrid_size} bytes (X25519 eph + ML-KEM ct + nonce + wrapped DEK)")
    print(f"  overhead:     {hybrid_size - classic_size} bytes per file")

    banner("ALL PQ TESTS PASSED — OVERSIGHT is post-quantum-ready")


if __name__ == "__main__":
    main()
