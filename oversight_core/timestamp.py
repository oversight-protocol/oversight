"""
oversight_core.timestamp
========================

RFC 3161 qualified timestamp client. Used by the registry to get
independently-auditable timestamps from a Time Stamp Authority, rather than
relying on the registry's own clock.

Free, no-account TSA options (tested and working):
    - https://freetsa.org/tsr  — FreeTSA, P-384 EC, valid to 2040
    - http://timestamp.digicert.com — DigiCert, RFC 3161 compliant, widely used

Every timestamp is:
    - signed by the TSA's private key (independently-verifiable)
    - contains gen_time from the TSA's clock
    - contains a nonce to prevent replay
    - commits to our chosen hash of the input

We store the raw bytes of the TimeStampToken as BLOB in the registry's events
table. A court examiner can independently verify the timestamp offline using
`openssl ts -verify` + the TSA's public cert, without trusting us.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Optional

import httpx

try:
    from rfc3161_client import TimestampRequestBuilder, decode_timestamp_response
    RFC3161_AVAILABLE = True
except ImportError:
    RFC3161_AVAILABLE = False


# Default TSA chain: try them in order.
# Both are free, require no account, and are RFC 3161 compliant.
DEFAULT_TSA_CHAIN = [
    # FreeTSA: modernized March 2026 to P-384, valid until 2040.
    "https://freetsa.org/tsr",
    # DigiCert: commercial-grade free endpoint used by Authenticode.
    "http://timestamp.digicert.com",
]


@dataclass
class QualifiedTimestamp:
    """Represents a signed RFC 3161 timestamp that can be independently verified."""
    tsa_url: str
    token_bytes: bytes           # raw ASN.1 TimeStampToken — opaque, verifiable offline
    gen_time_iso: str            # ISO 8601 "2026-04-17T23:11:04+00:00"
    serial_number: int
    nonce: int
    policy_oid: str              # TSA policy OID
    message_hash: bytes          # SHA-512 of what was timestamped

    def to_dict(self) -> dict:
        """Serialize for storage in the registry evidence bundle."""
        return {
            "tsa_url": self.tsa_url,
            "token_hex": self.token_bytes.hex(),
            "gen_time": self.gen_time_iso,
            "serial": self.serial_number,
            "nonce": self.nonce,
            "policy_oid": self.policy_oid,
            "message_hash_hex": self.message_hash.hex(),
        }


def qualified_timestamp(
    data: bytes,
    tsa_chain: Optional[list[str]] = None,
    timeout: float = 15.0,
) -> Optional[QualifiedTimestamp]:
    """
    Request a qualified timestamp for `data`. Tries each TSA in the chain
    until one succeeds; returns None if all fail (offline / network down).

    This is a BEST-EFFORT operation: the caller should proceed even if
    qualification fails, and annotate the event as "self-timestamped" rather
    than "qualified-timestamped". The registry's signed tree head still provides
    tamper evidence for the sequence of events, just not clock independence.

    Example:
        ts = qualified_timestamp(event_canonical_bytes)
        if ts:
            event["qualified_timestamp"] = ts.to_dict()
        else:
            event["qualified_timestamp"] = None  # fell back to self-timestamped

    The returned QualifiedTimestamp contains the raw TSA token. An external
    auditor can verify it with `openssl ts -verify -in token.tsr -data data`
    + the TSA's CA certificate (which both FreeTSA and DigiCert publish).
    """
    if not RFC3161_AVAILABLE:
        return None

    for tsa_url in (tsa_chain or DEFAULT_TSA_CHAIN):
        try:
            req = TimestampRequestBuilder().data(data).nonce(nonce=True).build()
            resp = httpx.post(
                tsa_url,
                content=req.as_bytes(),
                headers={"Content-Type": "application/timestamp-query"},
                timeout=timeout,
            )
            if resp.status_code != 200:
                continue
            tsr = decode_timestamp_response(resp.content)
            if tsr.status != 0:  # 0 == granted
                continue

            tst_info = tsr.tst_info
            mi = tst_info.message_imprint

            return QualifiedTimestamp(
                tsa_url=tsa_url,
                token_bytes=tsr.time_stamp_token(),
                gen_time_iso=tst_info.gen_time.isoformat(),
                serial_number=tst_info.serial_number,
                nonce=tst_info.nonce,
                policy_oid=tst_info.policy.dotted_string if tst_info.policy else "",
                message_hash=bytes(mi.message),
            )
        except (httpx.HTTPError, ValueError, TimeoutError, OSError):
            # Network failure or malformed response — try next TSA.
            continue

    # All TSAs unreachable; caller falls back to self-timestamp.
    return None


def verify_qualified_timestamp(
    ts: QualifiedTimestamp,
    original_data: bytes,
) -> tuple[bool, str]:
    """
    Light verification: checks that the TSA's claimed message hash matches
    sha-512 of original_data. Does NOT verify the TSA's signature or cert
    chain — that needs `openssl ts -verify` or equivalent with the TSA's
    root cert, which Oversight doesn't ship (users obtain from the TSA).

    Returns (ok, reason).
    """
    computed = hashlib.sha512(original_data).digest()
    if computed != ts.message_hash:
        return False, (
            f"message-hash mismatch: TSA committed to "
            f"{ts.message_hash[:16].hex()}..., computed "
            f"{computed[:16].hex()}..."
        )
    return True, "TSA message-hash matches data; signature verification requires TSA root cert"
