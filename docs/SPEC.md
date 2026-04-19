# OVERSIGHT Protocol Specification

**Sealed Entity, Notarized Trust, Integrity & Evidence Layer**

Version 0.1 — Draft — April 2026

---

## 1. Status

This document is a draft specification for an open protocol for data provenance, attribution, and leak detection. It is intended for eventual submission as a standards-track RFC following independent cryptographic review.

## 2. Goals and non-goals

### 2.1 Goals

The protocol MUST:

- Produce a file container format (`.sealed`) that wraps arbitrary payloads in an authenticated, recipient-bound cryptographic envelope.
- Allow post-quantum cryptographic agility without breaking existing sealed files.
- Bind every sealed file to a specific recipient identity via a signed manifest.
- Carry per-recipient watermarking identifiers that survive plaintext escape.
- Carry per-recipient passive beacon tokens that fire on open via standard rendering behaviors (DNS resolution, image fetch, certificate check) without executing code on the reader.
- Support distributed, jurisdiction-aware attribution registries.
- Produce evidence artifacts suitable as the foundation of a court-admissible chain-of-custody report.
- Be format-agnostic: the payload is opaque bytes; the protocol does not care whether it wraps DOCX, PDF, MP4, JSON, or raw bytes.
- Be open, reviewable, and free of proprietary dependencies.

### 2.2 Non-goals

The protocol does NOT:

- Execute code of any kind on the reader's machine. No active payloads. No RATs.
- Prevent all leaks. Plaintext, once decrypted, can be retyped, photographed, or OCR'd. The protocol's defense is attribution, not prevention.
- Provide DRM in the film-industry sense (playback restrictions, output protection). It provides attribution and revocation.
- Authenticate the truth of content. Like C2PA, OVERSIGHT proves who signed what for whom; it does not verify the claims in the content itself.

## 3. Threat model

### 3.1 Assumptions

- The issuer controls its signing keys and operates a registry (or delegates to a federated operator).
- The intended recipient controls its decryption keys.
- The network between recipient and registry is untrusted but standard TLS is available.

### 3.2 Adversaries

The protocol defends against:

| Adversary | Capability | Defense |
|-----------|------------|---------|
| Passive interceptor | Captures sealed file in transit | AEAD, recipient-bound DEK |
| Curious insider | Receives file, shares with third party | Per-recipient watermarking → attribution |
| Thief with wrong key | Steals sealed file, has no decryption key | ECDH/KEM unwrap fails |
| Tamperer | Modifies ciphertext or manifest | AEAD tag + manifest signature + content-hash verify |
| Format-conversion attacker | Decrypts, converts to PDF/screenshot, posts plaintext | Multi-layer watermarking; attribution via registry match |
| Metadata-stripping attacker | Re-serializes file to remove marks | Defeats L2+; L1 zero-width and L3 semantic marks survive |
| Nation-state with quantum computer (future) | Decrypts classical ciphertexts | Hybrid mode: ML-KEM + X25519 |

The protocol does NOT defend against:

- The fully-airgapped attacker who also OCR/retypes the document and distributes only the retyped copy. (Semantic/synonym watermarks are the only defense; they are probabilistic.)
- An attacker who compromises the issuer's signing key. (Key rotation and revocation logs are the mitigation.)
- An attacker who owns the registry infrastructure. (Use a federated/transparency-log registry; mitigate with jurisdictional profiles.)

## 4. Cryptographic primitives

### 4.1 Algorithm suites

Every sealed file declares an `suite` in its manifest. Implementations MUST reject unknown suites.

#### 4.1.1 `OSGT-CLASSIC-v1` (suite_id = 1)

- Key agreement: X25519 (RFC 7748)
- KDF: HKDF-SHA256 (RFC 5869), info = `"oversight-v1-dek-wrap"`
- AEAD: XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha)
- Signature: Ed25519 (RFC 8032)
- Hash: SHA-256

#### 4.1.2 `OSGT-HYBRID-v1` (suite_id = 2)

All primitives of CLASSIC-v1, plus:

- KEM: ML-KEM-768 (FIPS 203), combined with X25519 using hybrid KDF
- Signature: ML-DSA-65 (FIPS 204), combined with Ed25519 (dual signatures)

Hybrid key establishment combines the two shared secrets:

```
hybrid_ss = HKDF-SHA256(
    salt = "oversight-hybrid-v1",
    ikm  = x25519_ss || mlkem_ss,
    info = "oversight-hybrid-dek-wrap",
    len  = 32
)
```

Hybrid signatures attach both signatures to the manifest. Verification requires BOTH to validate.

### 4.2 Custom cryptography is PROHIBITED

Implementations MUST NOT introduce new cryptographic primitives. The suite identifiers are reserved; new suites may only be added via specification update after independent review.

## 5. Container format

### 5.1 Wire layout

All integers are unsigned big-endian.

```
offset  length    field              notes
------  --------  -----------------  ---------------------------------
0       6         magic              0x53 0x4E 0x54 0x4C 0x01 0x00  ("OSGT\x01\x00")
6       1         format_version     MUST be 0x01
7       1         suite_id           1 = CLASSIC_v1, 2 = HYBRID_v1
8       4         manifest_len       length of manifest JSON in bytes
12      M         manifest           canonical JSON (signed)
12+M    4         wrapped_dek_len
...     W         wrapped_dek        JSON: {ephemeral_pub, nonce, wrapped_dek}
...     24        aead_nonce         XChaCha20-Poly1305 nonce
...     4         ciphertext_len
...     C         ciphertext         AEAD output, includes 16-byte tag
```

### 5.2 Manifest

The manifest is canonical JSON (sorted keys, no whitespace, UTF-8). Required fields:

- `file_id` (UUID v4)
- `issued_at` (unix seconds, UTC)
- `version` (`"OVERSIGHT-v1"`)
- `suite` (suite identifier string)
- `content_hash` (hex SHA-256 of plaintext)
- `size_bytes` (plaintext length)
- `issuer_id` (string)
- `issuer_ed25519_pub` (hex)
- `recipient` (object: `recipient_id`, `x25519_pub`, optional `ed25519_pub`)
- `signature_ed25519` (hex, Ed25519 over canonical bytes without signature fields)

Optional fields:

- `original_filename`, `content_type`
- `watermarks` (array of `{layer, mark_id}`)
- `beacons` (array of beacon descriptors)
- `policy` (`not_after`, `max_opens`, `jurisdiction`, `registry_url`, `require_attestation`)
- `signature_ml_dsa` (hex, for HYBRID suites)

### 5.3 DEK wrapping

A fresh 32-byte DEK is generated per file. The wrapping procedure for CLASSIC-v1:

1. Generate ephemeral X25519 keypair `(eph_sk, eph_pk)`.
2. Compute `ss = X25519(eph_sk, recipient_x25519_pub)`.
3. Derive `kek = HKDF-SHA256(ss, salt=nil, info="oversight-v1-dek-wrap", len=32)`.
4. Encrypt DEK: `(nonce, ct) = XChaCha20-Poly1305(kek, DEK, aad="oversight-dek")`.
5. Store `{eph_pk, nonce, ct}` as `wrapped_dek`.

### 5.4 AEAD binding

The ciphertext AEAD takes `AAD = content_hash` (the hex string from the manifest). This binds the ciphertext to the signed manifest; an attacker cannot swap ciphertexts between manifests without breaking the AEAD tag.

### 5.5 Post-decrypt verification

After decryption, the implementation MUST verify that `SHA-256(plaintext) == manifest.content_hash`. If not, discard the plaintext.

## 6. Watermarking

Watermarking is optional but RECOMMENDED. Each applied layer registers a `mark_id` in the manifest.

### 6.1 Layer identifiers

- `L1_zero_width` — zero-width unicode characters scattered through text payloads
- `L2_whitespace` — trailing space vs tab at line endings
- `L3_synonyms` — synonym-class rotation (reserved; MVP stub)
- `L4_dct_visual` — reserved; for image payloads
- `L5_layout` — reserved; for PDF/document layout perturbation

### 6.2 Mark IDs

Mark IDs are 64-bit random values. Collision probability at 2^32 issued marks is ~2^-32.

### 6.3 Recovery

A leaked plaintext is scanned by all supported layer extractors. Each recovered `mark_id` is queried against the registry. A match returns `(file_id, recipient_id, issuer_id)`.

Implementations SHOULD use multiple layers so that defeating one does not defeat attribution.

## 7. Beacons

### 7.1 Types

| Kind       | Channel | Triggered by                                          |
|------------|---------|-------------------------------------------------------|
| `dns`      | DNS     | Document rendering, network-aware readers, preview pipelines |
| `http_img` | HTTPS   | `<img>` tags in HTML/Office/PDF/SVG                    |
| `ocsp`     | HTTPS   | Certificate revocation checks                          |
| `license`  | HTTPS   | Explicit license-server check (policy-enforced)       |

### 7.2 Token format

Each beacon carries a 128-bit unguessable `token_id`. The registry maps `token_id → (file_id, recipient_id, issuer_id)`.

### 7.3 Passive-only requirement

Beacons MUST NOT cause code execution on the reader. A beacon is a network callback that a standard renderer makes naturally; it does not require a plugin, macro, or active payload.

## 8. Registry

### 8.1 Endpoints

A compliant registry exposes:

| Method | Path                       | Purpose                                 |
|--------|----------------------------|-----------------------------------------|
| POST   | `/register`                | Issuer registers a file's beacons+marks |
| GET    | `/p/{token_id}.png`        | HTTP image beacon receiver              |
| GET    | `/r/{token_id}`            | OCSP-style beacon receiver              |
| GET    | `/v/{token_id}`            | License-check beacon receiver           |
| POST   | `/attribute`               | Query by token_id or mark_id            |
| GET    | `/evidence/{file_id}`      | Assemble evidence bundle                |

### 8.2 Qualified timestamps

Production registries MUST timestamp events via RFC 3161 against at least one qualified Time Stamping Authority (TSA). Evidence bundles MUST include the TimeStampToken(s).

### 8.3 Transparency log

Production registries SHOULD chain events into an append-only transparency log (Sigstore-style Merkle log) so that registry operators cannot fabricate or suppress events undetected.

### 8.4 Jurisdictional profiles

Registries MUST publish a jurisdictional profile declaring:

- Data residency (where event logs are stored)
- Permitted field collection per event (IP, UA, geolocation, etc.)
- Retention period
- Cross-border data-sharing policy

The manifest `policy.jurisdiction` MUST match the registry's profile or the seal MUST be rejected.

## 9. Evidence bundles

An evidence bundle is a JSON artifact containing:

1. The original signed manifest
2. All registered beacons and watermarks
3. Chronologically ordered event log
4. Qualified timestamps for each event
5. Registry's own signature over the bundle
6. Transparency-log inclusion proofs

The bundle is the foundation for a forensic report per ISO/IEC 27037. A court-admissible final report requires additional human-in-the-loop procedures: examiner qualifications, methodology documentation, and proper preservation of the original blob.

## 10. Security considerations

### 10.1 Key compromise

- Issuer key compromise allows forged manifests for the compromise window. Mitigation: short-lived issuer keys, certificate transparency, a revocation list.
- Recipient key compromise allows decryption of all files ever sealed for that recipient. Mitigation: per-purpose recipient keys, forward-secret variants (future work).

### 10.2 Replay

Ciphertext is bound to manifest via AEAD AAD. Manifest is signed and uniquely identified by `file_id`. Replay of a full sealed blob is equivalent to possession of the blob.

### 10.3 Side channels

Implementations MUST use constant-time implementations for all cryptographic primitives. Watermark-embedding timing may leak whether a recipient is being marked; embed times SHOULD be bounded.

### 10.4 Metadata exposure

The manifest is not encrypted. An attacker who captures a sealed blob learns the recipient, issuer, beacons, and watermark IDs. This is intentional: third parties (legal discovery, compliance auditors) must be able to inspect the metadata without holding the decryption key. Sensitive fields SHOULD be hashed or omitted from the manifest if their disclosure is unacceptable.

### 10.5 Traffic analysis of beacons

Beacon callbacks reveal that a sealed file was opened. In hostile environments an attacker who blocks outbound traffic will suppress beacon callbacks. The protocol does not claim to defeat such an attacker; watermarking provides the post-escape attribution path.

## 11. IANA considerations

Reserved media type: `application/vnd.oversight.sealed`
Reserved file extension: `.sealed`
Reserved URN namespace: `urn:oversight:file:<file_id>`

## 12. References

- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism
- FIPS 204: Module-Lattice-Based Digital Signature Standard
- RFC 7748: Elliptic Curves for Security (X25519)
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 5869: HKDF
- RFC 3161: Time-Stamp Protocol (TSP)
- ISO/IEC 27037: Guidelines for identification, collection, acquisition and preservation of digital evidence
- C2PA 2.3: Content Credentials specification
- draft-irtf-cfrg-xchacha: XChaCha20-Poly1305

## 13. Appendix A — Test vectors (normative)

To follow in v0.2. Implementations SHOULD include a conformance test suite producing and verifying known sealed blobs.
