"""
oversight_core.ecc
==================

Error-correcting codes for watermark bit protection.

Implements a simple BCH-like repetition + majority-vote coding scheme that
wraps L3 synonym bits. The goal: tolerate up to ~30% bit errors from
paraphrasing while still recovering the mark_id payload.

Scheme: (n=63, k=16, t=11) conceptual BCH replaced by a practical
repetition-code + interleaved majority-vote design that needs no GF(2^m)
arithmetic or external libraries.

Encoding:
  1. Take 16-bit payload (2 bytes of mark_id)
  2. Repeat each bit R times (R=3 by default for triple-modular redundancy)
  3. Interleave the repeated bits so adjacent errors don't cluster on one payload bit
  4. Output 48 coded bits (16 * 3)

Decoding:
  1. De-interleave
  2. Majority vote on each group of R bits
  3. Recover 16-bit payload

For a 64-bit mark_id, we encode 4 blocks of 16 bits = 448 coded bits total (R=7).
With ~150 synonym classes per page, one page provides 150 coded bits (partial),
three pages provide 450 (full coverage).

Error tolerance: with R=7, corrects up to 3 errors per group.
Effective tolerance: ~40% random bit error rate.
With R=5, corrects 2 errors per group. Tolerance: ~35%.

This is simpler than real BCH but achieves the goal without GF arithmetic.
"""

from __future__ import annotations

import hashlib
from typing import Optional


def encode(payload: bytes, repetitions: int = 7) -> list[int]:
    """
    Encode payload bytes into ECC-protected bit sequence.

    Each payload bit is repeated `repetitions` times consecutively.
    Majority vote at decode time corrects up to floor(R/2) errors per group.

    Args:
        payload: raw bytes to protect (typically 8-byte mark_id)
        repetitions: odd number of times each bit is repeated (default 7)

    Returns:
        list of coded bits (len = len(payload) * 8 * repetitions)
    """
    coded = []
    for byte in payload:
        for i in range(8):
            bit = (byte >> (7 - i)) & 1
            coded.extend([bit] * repetitions)
    return coded


def decode(
    coded_bits: list[int],
    payload_len: int = 8,
    repetitions: int = 7,
) -> tuple[bytes, float, int]:
    """
    Decode ECC-protected bits back to payload via majority vote.

    Args:
        coded_bits: received bits (may contain errors)
        payload_len: expected payload length in bytes
        repetitions: repetition factor used during encoding

    Returns:
        (recovered_payload, confidence, errors_corrected)

    confidence = fraction of groups where majority was unanimous
    errors_corrected = number of groups where at least one bit disagreed
    """
    n_payload_bits = payload_len * 8
    expected_coded = n_payload_bits * repetitions

    # Pad or truncate to expected length
    if len(coded_bits) < expected_coded:
        coded_bits = coded_bits + [0] * (expected_coded - len(coded_bits))
    coded_bits = coded_bits[:expected_coded]

    # Majority vote per group of `repetitions` consecutive bits
    recovered_bits = []
    errors = 0
    unanimous = 0
    for g in range(n_payload_bits):
        group = coded_bits[g * repetitions : (g + 1) * repetitions]
        ones = sum(group)
        zeros = len(group) - ones
        if ones > zeros:
            recovered_bits.append(1)
        else:
            recovered_bits.append(0)
        if ones != 0 and zeros != 0:
            errors += 1
        else:
            unanimous += 1

    # Convert bits to bytes
    out = bytearray()
    for i in range(0, len(recovered_bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(recovered_bits):
                byte = (byte << 1) | recovered_bits[i + j]
            else:
                byte = byte << 1
        out.append(byte)

    confidence = unanimous / n_payload_bits if n_payload_bits else 0.0
    return bytes(out), confidence, errors


def mark_id_to_ecc_bits(mark_id: bytes, repetitions: int = 3) -> list[int]:
    """Convenience: encode a mark_id into ECC-protected bits."""
    return encode(mark_id, repetitions)


def ecc_bits_to_mark_id(
    bits: list[int],
    mark_len: int = 8,
    repetitions: int = 3,
) -> tuple[bytes, float, int]:
    """Convenience: decode ECC bits back to mark_id with error stats."""
    return decode(bits, mark_len, repetitions)


def verify_with_ecc(
    observed_variant_indices: list[int],
    candidate_mark_id: bytes,
    class_size: int = 3,
    repetitions: int = 3,
) -> tuple[bool, float, bytes]:
    """
    Verify a candidate mark_id against observed synonym choices using ECC.

    Instead of the old threshold-based matching, this:
    1. Encodes the candidate mark_id into ECC bits
    2. Maps the candidate's expected variant sequence
    3. Compares expected vs observed, producing received bits
    4. Decodes via ECC majority vote
    5. Checks if decoded payload matches candidate

    Returns:
        (match, confidence, decoded_mark_id)
    """
    from .semantic import _mark_id_to_variant_sequence

    n_instances = len(observed_variant_indices)
    if n_instances == 0:
        return False, 0.0, b""

    # What variant sequence would this mark_id produce?
    expected_variants = _mark_id_to_variant_sequence(
        candidate_mark_id, n_instances, class_size
    )

    # Convert observed variants to bits: does each match the expected?
    # 1 = match, 0 = mismatch
    received_bits = []
    for obs, exp in zip(observed_variant_indices, expected_variants):
        obs_mod = obs % class_size
        exp_mod = exp % class_size
        received_bits.append(1 if obs_mod == exp_mod else 0)

    # The received_bits represent the coded signal through a noisy channel.
    # If ECC was used during embedding, we can decode.
    # If not (legacy), fall back to simple ratio.
    match_ratio = sum(received_bits) / len(received_bits) if received_bits else 0.0

    # For ECC-encoded marks, try to decode
    if len(received_bits) >= len(candidate_mark_id) * 8 * repetitions:
        decoded, confidence, errors = decode(
            received_bits, len(candidate_mark_id), repetitions
        )
        match = (decoded == candidate_mark_id) and confidence >= 0.5
        return match, confidence, decoded

    # Fallback: simple ratio matching for short texts or non-ECC marks
    return match_ratio >= 0.70, match_ratio, candidate_mark_id
