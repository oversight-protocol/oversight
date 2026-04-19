# Oversight Registration Predicate v1

**Predicate Type URI:**
`https://github.com/oversight-protocol/oversight/blob/v0.5.0/docs/predicates/registration-v1.md`

**Statement type:** `https://in-toto.io/Statement/v1`
**Envelope:** DSSE (`application/vnd.in-toto+json`)
**Signature algorithm:** Ed25519 (issuer key from the Oversight manifest)

## Purpose

This predicate describes the act of an Oversight issuer registering a sealed
file's mark with a public transparency log (Sigstore Rekor v2). The DSSE
envelope is uploaded to Rekor; the returned `TransparencyLogEntry` is then
embedded in the local evidence bundle.

The predicate is intentionally minimal on the public log — recipient
identifiers and pubkeys are hashed before publication so the log cannot be
mined for "who got what."

## Subject

A statement carries exactly one subject:

```json
{
  "name": "mark:<mark_id_hex>",
  "digest": {"sha256": "<plaintext sha256 hex>"}
}
```

`mark_id_hex` is the 128-bit watermark identifier in lowercase hex. It is an
opaque random value; it is NOT a human-meaningful label and contains no PII.

`digest.sha256` is the SHA-256 of the plaintext that was sealed. This is the
hook auditors use to find matching registrations when investigating a leak:
hash the leaked text, query Rekor by digest.

## Predicate body fields

| field                       | type        | required | notes                                                      |
|-----------------------------|-------------|----------|------------------------------------------------------------|
| `predicate_version`         | int         | yes      | Always `1` for this URI.                                   |
| `file_id`                   | string UUID | yes      | The Oversight manifest's `file_id`.                        |
| `issuer_pubkey_ed25519`     | hex string  | yes      | Verifying key for the DSSE envelope and the manifest.      |
| `recipient_id`              | string      | yes      | SHOULD be a hash or UUID. Issuers MUST NOT publish raw PII.|
| `recipient_pubkey_sha256`   | hex string  | yes      | `sha256(recipient_x25519_pub_raw_bytes)`. NEVER the raw key.|
| `suite`                     | string      | yes      | `OSGT-CLASSIC-v1` / `OSGT-PQ-HYBRID-v1` / `OSGT-HW-P256-v1`.|
| `registered_at`             | string      | yes      | ISO 8601 UTC timestamp.                                    |
| `policy`                    | object      | yes      | Subset of the manifest policy that bears on attribution.   |
| `watermarks`                | object      | yes      | `{L1:bool, L2:bool, L3:bool}` — which layers were embedded.|
| `rfc3161_tsa`               | string URL  | optional | TSA endpoint used.                                         |
| `rfc3161_token_b64`         | base64      | optional | Raw RFC 3161 TimeStampToken.                               |
| `rfc3161_chain_b64`         | base64      | optional | Concatenated PEM cert chain for TSA validation post-expiry.|

## Privacy contract

The on-log payload MUST NOT contain:
- Raw recipient public keys.
- Email addresses, phone numbers, or other directly identifying recipient PII.
- File content, even ciphertext.
- Watermark mark_ids belonging to other recipients of the same source file
  (one statement, one recipient).

Issuers who need to retain the raw recipient pubkey MUST keep it in the local
`.sealed` bundle, not in the DSSE envelope.

## Versioning

Backward-incompatible changes to this predicate body produce a new file at a
new git tag, e.g. `…/blob/v0.6.0/docs/predicates/registration-v2.md`. The URI
itself is the version anchor; never re-edit a published predicate URI's
contents.
