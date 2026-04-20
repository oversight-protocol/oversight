# Oversight Registry v1 Interop Draft

Status: draft; wire format is not stable until v1.0.

This document defines the minimum interoperable registry surface for an
independent Oversight registry operator. It follows OpenAPI 3.1 conventions for
schema shape and keeps Oversight-specific policy out of the transport where
possible.

## Goals

- Let more than one operator run a compatible attribution registry.
- Preserve issuer-signed manifest authority: request sidecars MUST match the
  manifest's signed `beacons` and `watermarks` arrays.
- Keep beacon callbacks passive and authenticated between DNS/web beacon
  collectors and the registry.
- Preserve local or public transparency-log evidence for every registration
  and event.

## Common Requirements

- All JSON request bodies SHOULD be UTF-8 encoded.
- Registries MUST reject unknown oversized identifiers. The reference limit is
  256 bytes for `file_id`, `mark_id`, `token_id`, `recipient_id`, and
  `issuer_id`.
- Registries MUST verify the Ed25519 signature on the manifest before writing
  beacons, watermarks, corpus hashes, Rekor entries, or tlog events.
- Registries MUST NOT accept beacon or watermark sidecars that differ from the
  issuer-signed manifest copies.
- DNS event callbacks from non-loopback clients MUST authenticate with
  `X-Oversight-DNS-Secret` or an equivalent deployment-specific channel.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Service health and tlog size |
| `POST` | `/register` | Register signed manifest, beacons, watermarks, optional corpus hashes |
| `POST` | `/attribute` | Look up attribution by `token_id`, `mark_id`, or perceptual/content hash |
| `GET` | `/query/{file_id}` | Return manifest ownership plus registered beacons/watermarks |
| `POST` | `/dns_event` | Authenticated DNS beacon callback |
| `GET` | `/evidence/{file_id}` | Evidence bundle with manifest, events, tlog proofs, and signed tree head |

## `/register`

Request:

```json
{
  "manifest": {},
  "beacons": [],
  "watermarks": [],
  "corpus": {
    "winnowing": "optional-hash",
    "sentence": "optional-hash"
  }
}
```

Validation:

1. Canonicalize and verify `manifest.signature_ed25519`.
2. Compare `beacons` and `watermarks` against signed manifest arrays.
3. Reject malformed signed artifacts rather than silently dropping rows.
4. Append a registry transparency-log event.
5. If Rekor is enabled and a watermark mark ID exists, attest using
   `subject.name = "mark:<mark_id>"` and
   `subject.digest.sha256 = manifest.content_hash`.

Response:

```json
{
  "ok": true,
  "file_id": "uuid",
  "registered_beacons": 1,
  "tlog_index": 42,
  "rekor": {}
}
```

## `/dns_event`

Request:

```json
{
  "token_id": "hex-or-url-safe-token",
  "client_ip": "collector-observed-ip",
  "qtype": "A",
  "qname": "token.beacon.example"
}
```

Security:

- Public/non-loopback callbacks MUST include `X-Oversight-DNS-Secret`.
- Registries SHOULD prefer collector-observed source metadata over
  user-controlled body fields when available.
- Events SHOULD be appended to the local transparency log and included in
  evidence bundles.

## Evidence Bundle

Evidence bundles SHOULD contain:

- manifest JSON and signature
- registry event rows
- local tlog signed tree head
- inclusion proof for every bundled tlog event
- Rekor DSSE bundle, if public transparency was requested

## Federation Notes

The wire format MUST NOT require the official `oversightprotocol.dev` domain.
Operators may run their own registry and beacon domains as long as manifests
declare the registry URL and beacon descriptors unambiguously.
