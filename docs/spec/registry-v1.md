# Oversight Registry v1 Interop Draft

Status: draft; the wire format is not stable until Oversight v1.0. This
document tracks the surface a second operator needs to implement to run
a registry that the Python and Rust reference clients can treat as
interchangeable with the origin deployment.

## Goals

- Let more than one operator run a compatible attribution registry so
  "open protocol" is a property of the code and not of a hostname.
- Preserve issuer-signed manifest authority: every registration sidecar
  MUST match the manifest's signed `beacons` and `watermarks` arrays
  byte for byte.
- Keep beacon callbacks authenticated between DNS or web beacon
  collectors and the registry so spoofed events cannot pollute the
  attribution record.
- Preserve local or public transparency-log evidence for every
  registration and every event, and expose proofs that a federated
  verifier can fetch without trusting the operator.

## Common Requirements

### Transport

- All request and response bodies are JSON unless a specific endpoint
  says otherwise. Content-Type MUST be `application/json; charset=utf-8`
  for request bodies that carry one.
- Registries MUST reject identifiers larger than 256 bytes for each of
  `file_id`, `mark_id`, `token_id`, `recipient_id`, and `issuer_id`.
- Registries SHOULD apply a per-client rate limit and return HTTP 429
  with the standard error envelope when exceeded.

### Canonicalization

The manifest signature is computed over a canonical JSON serialization
with the following exact rules. Implementations that deviate cannot
verify manifests produced by the reference client.

1. Serialize the manifest dictionary with recursively sorted keys.
2. Use the separators `","` and `":"` with no whitespace.
3. Encode the resulting string as UTF-8 before feeding it to the
   Ed25519 verifier.
4. The `signature_ed25519` field is stripped before canonicalization
   and re-attached to the signed object before it is wire-transmitted.

In Python the canonical form matches
`json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")`.
In Rust the reference implementation uses the `canonical_json` crate
with identical output. The cross-language conformance suite pins this.

### Signature verification

- Registries MUST verify `manifest.signature_ed25519` before writing
  any beacon, watermark, corpus hash, Rekor entry, or transparency-log
  event.
- Registries MUST NOT accept beacon or watermark sidecars that differ
  from the manifest's signed arrays. Comparison uses the canonicalized
  per-item JSON after sorting by canonical bytes.
- Re-registration under the same `file_id` MUST require the same
  `issuer_ed25519_pub` as the original record. A mismatch returns
  HTTP 409.

### Error envelope

Non-2xx responses MUST carry a JSON envelope:

```json
{"error": {"code": "signature_invalid", "message": "manifest signature invalid"}}
```

Implementations MAY include additional fields under `error` (for
example, `retry_after` on 429), but consumers rely only on `code`
and `message`.

The defined `code` values in v1:

| Code | HTTP | When |
|------|------|------|
| `missing_field` | 400 | A required field is absent |
| `signature_invalid` | 400 | Manifest Ed25519 verification failed |
| `sidecar_mismatch` | 400 | Request beacons or watermarks differ from the signed manifest |
| `issuer_mismatch` | 409 | `file_id` already registered under a different issuer pubkey |
| `auth_required` | 401 | DNS event callback missing required secret |
| `rate_limited` | 429 | Client exceeded per-key token bucket |
| `not_found` | 404 | Queried record does not exist |
| `server_error` | 500 | Registry internal failure |

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/health` | Liveness and local tlog size |
| `GET`  | `/.well-known/oversight-registry` | Registry identity advertisement |
| `POST` | `/register` | Register signed manifest, beacons, watermarks, optional corpus hashes |
| `POST` | `/attribute` | Look up attribution by `token_id`, `mark_id`, or perceptual hash |
| `POST` | `/dns_event` | Authenticated DNS beacon callback |
| `GET`  | `/evidence/{file_id}` | Evidence bundle with manifest, events, tlog proofs, and signed tree head |
| `GET`  | `/tlog/head` | Current signed tree head for the local transparency log |
| `GET`  | `/tlog/proof/{index}` | Inclusion proof for a local tlog entry |
| `GET`  | `/tlog/range` | Entry range, used by federated verifiers or monitors |
| `GET`  | `/p/{token_id}.png` | HTTP pixel beacon, records an event |
| `GET`  | `/r/{token_id}`, `/ocsp/r/{token_id}` | OCSP-shaped beacon, records an event |
| `GET`  | `/v/{token_id}`, `/lic/v/{token_id}` | License-check beacon, records an event |
| `GET`  | `/candidates/semantic` | Recent L3 mark IDs for scraper-style verification |

## `/health`

```json
{"status": "ok", "service": "oversight-registry", "version": "0.2.1", "tlog_size": 42}
```

`status` is `"ok"` or `"degraded"`. `service` MUST begin with
`oversight-registry` so identity cannot be counterfeited without an
intentional lie. `tlog_size` is the current local transparency-log
leaf count.

## `/.well-known/oversight-registry`

```json
{
  "ed25519_pub": "<hex>",
  "version": "0.2.1",
  "jurisdiction": "GLOBAL",
  "tlog_size": 42,
  "federation": {
    "spec_version": "v1",
    "canonicalization": "json-sort-keys-compact-utf8",
    "rekor_enabled": true
  }
}
```

`ed25519_pub` is the registry's own signing key hex and is the stable
identifier a federated verifier uses to tell operators apart.
`federation.spec_version` MUST be `"v1"` for registries that implement
this document. Unknown `federation.*` fields MUST be ignored by
consumers so the shape can extend without breaking older clients.

## `/register`

Request:

```json
{
  "manifest": { "...": "see docs/SPEC.md" },
  "beacons":  [ { "token_id": "...", "kind": "dns|http|ocsp|license" } ],
  "watermarks": [ { "mark_id": "...", "layer": "L1|L2|L3_semantic" } ],
  "corpus": { "winnowing": "optional-hash", "sentence": "optional-hash" }
}
```

Validation order:

1. `manifest.file_id` MUST be present and fit the 256-byte bound.
2. `manifest.signature_ed25519` MUST verify over the canonical bytes
   (see Canonicalization).
3. `manifest.issuer_ed25519_pub` MUST be present.
4. `beacons` and `watermarks` sidecars MUST equal the signed arrays
   under canonical comparison.
5. Prior registration of the same `file_id` MUST have come from the
   same `issuer_ed25519_pub`.
6. A transparency-log event is appended before the response is sent.
7. If Rekor attestation is enabled, the registry uses
   `subject.name = "mark:<mark_id>"` and
   `subject.digest.sha256 = manifest.content_hash`.

Success response:

```json
{
  "ok": true,
  "file_id": "uuid",
  "registered_beacons": 1,
  "tlog_index": 42,
  "rekor": {"log_url": "...", "log_index": 12345, "log_id": "...", "integrated_time": 1730000000}
}
```

`rekor` is present when public attestation is enabled. Absent or empty
`rekor` is not an error.

## `/attribute`

Request accepts exactly one of `token_id`, `mark_id` (with optional
`layer`), or `perceptual_hash`. Missing or multiple-populated bodies
return `missing_field`.

Success response on a hit:

```json
{
  "found": true,
  "file_id": "uuid",
  "recipient_id": "...",
  "issuer_id": "...",
  "manifest": { "..." : "..." },
  "events": [ { "kind": "dns", "timestamp": 0, "source_ip": "..." } ]
}
```

A miss returns `{"found": false}` with HTTP 200. Bare 404s are reserved
for unknown endpoints, not for search misses.

## `/dns_event`

Request:

```json
{
  "token_id": "hex-or-url-safe",
  "client_ip": "collector-observed-ip",
  "qtype": "A",
  "qname": "token.beacon.example"
}
```

Authentication:

- Loopback clients are trusted without a secret so a DNS server on
  the same host can call without extra configuration.
- Non-loopback callers MUST send `X-Oversight-DNS-Secret: <secret>`
  that matches the registry's configured secret. The comparison MUST
  be constant-time (`hmac.compare_digest` or equivalent).
- A registry that has no secret configured MUST refuse non-loopback
  callers. Silent acceptance of unauthenticated non-loopback events
  is a conformance failure.

Success response:

```json
{"ok": true, "tlog_index": 42}
```

## `/evidence/{file_id}`

Evidence bundles carry everything a recipient or auditor needs to
verify attribution without trusting the registry operator. The reference
shape is flat so a verifier can pull each artifact with a single JSON
dereference.

Required top-level fields:

- `file_id`: echoes the path parameter
- `bundle_generated_at`: registry clock timestamp, for context
- `registry_pub`: the registry's Ed25519 public key hex, matching
  `/.well-known/oversight-registry`
- `manifest`: the signed manifest object (signature still attached)
- `beacons`: registered beacon rows for this file
- `watermarks`: registered watermark rows for this file
- `events`: registry event rows for this file, ordered by timestamp
- `tlog_head`: the current signed tree head; when the registry has no
  transparency log configured, this field is `null`
- `tlog_proofs`: array of inclusion proofs for the rows in `events`
  that have a `tlog_index`; each proof carries `event_row`,
  `tlog_index`, and `inclusion`

Optional fields:

- `rekor`: the sigstore-compatible DSSE bundle when public attestation
  is enabled; `bundle_schema` MUST be `2`
- `disclaimer`: a human-readable note about the bundle's legal posture
- `bundle_signature_ed25519`: registry signature over the canonical
  bundle bytes, present on all conforming responses

Unknown `file_id` returns HTTP 404 with the standard error envelope.

## `/tlog/head`, `/tlog/proof/{index}`, `/tlog/range`

These expose the local transparency log so a federated verifier can
monitor it without relying on the registry's own query responses.
The signed tree head MUST be Ed25519-signed by the registry identity
key advertised at `/.well-known/oversight-registry`.

## Beacon endpoints

Beacon paths are normative because manifests embed URLs that follow
these shapes and the Python and Rust clients assemble them the same
way.

| Path | Kind stored in `events` |
|------|------------------------|
| `GET /p/{token_id}.png` | `http_img` |
| `GET /r/{token_id}`, `GET /ocsp/r/{token_id}` | `ocsp` |
| `GET /v/{token_id}`, `GET /lic/v/{token_id}` | `license` |

Responses MUST return 200 for well-formed token IDs so resolvers and
document viewers do not retry. The pixel endpoint returns a 1x1 PNG;
the OCSP endpoint returns an empty 200; the license endpoint returns
`{"valid": true}`.

## Federation notes

The wire format MUST NOT require the official `oversightprotocol.dev`
domain. Operators run their own registry and beacon domains; manifests
declare the registry URL and beacon descriptors unambiguously.

Operators SHOULD:

- Publish `/.well-known/oversight-registry` on HTTPS.
- Serve a stable `ed25519_pub`. Rotating this key breaks the chain
  of evidence for already-registered files.
- Run Rekor attestation enabled so the public log is the root of
  trust for federated verifiers.

## Conformance

The repository ships a conformance harness at
`tests/test_registry_conformance.py` that exercises every endpoint in
this document against a registry URL. The harness is the canonical
test of whether an independent implementation is compatible. Operators
run it with:

```
OVERSIGHT_REGISTRY_URL=https://registry.example.org \
  python3 tests/test_registry_conformance.py
```

The harness uses a throwaway issuer identity, posts a minimal valid
manifest, and then validates the responses. Runs against the local
reference registry are included in CI; operator-hosted runs are the
interop acceptance gate for federation.
