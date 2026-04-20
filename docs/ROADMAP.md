# Oversight Roadmap

## April 20, 2026 correction

The launch plan is now gated on product usability and threat-model honesty:

1. **L3 safety fixes and collusion docs** - shipped in v0.4.5: L3 defaults off for wording-sensitive document classes, requires explicit disclosure when enabled, records `canonical_content_hash`, and supports a boilerplate-only mode.
2. **Web viewer / drag-drop share UI** - next website/product milestone. Do not launch broadly on HN/Reddit until non-technical recipients can open and inspect Oversight files without the CLI.
3. **Outlook add-in only** for the first ecosystem integration. Defer Drive, Box, SharePoint, and Teams plugins until there is a maintainer or design partner paying for them.
4. **SIEM integration before SOC 2**: prioritize Splunk HEC, Microsoft Sentinel, and Elastic Common Schema exports because they are fast and high enterprise ROI.
5. **SOC 2 Type 1 scoping** is realistic after a design partner. ISO 27001 comes after SOC 2. **FedRAMP is dropped from near-term planning**; it is a multi-year commercial program requiring sponsor-agency backing.
6. **Registry federation**: publish and harden `docs/spec/registry-v1.md` during the Rust Axum/SQLx registry work so a second operator can run a compatible registry.

Correct public-launch sequence:

1. L3 safety + collusion documentation.
2. GUI / web viewer / drag-drop share workflow.
3. Outlook add-in.
4. One regulated-industry design partner deployment.
5. SOC 2 Type 1 scoping in parallel.
6. Public launch after the above, not while CLI-only.

This roadmap tracks work that lives outside a single release cut: external
integrations, spec publication, third-party review, and community milestones.
Every item references real upstream projects with current links so the plan
can be audited, not assumed.

Dates and prices reviewed against upstream sources on April 20, 2026.
Re-verify before committing to procurement or travel.

---

## Shipped

### RFC 3161 qualified timestamps — shipped in v0.3

`oversight_core/timestamp.py` and `registry/server.py` perform real RFC 3161
requests. The default TSA chain tries FreeTSA first, falls back to DigiCert,
and falls back to the registry's own clock if both are unreachable. Verified
live: 4667-byte signed TimeStampToken, valid P-384 signature, correct
gen_time, correct nonce.

For an evidence bundle to be admissible under EU eIDAS (qualified) or US FRE
901 (authenticated), the timestamp must come from a Time Stamp Authority
whose clock and signing key are independently auditable. RFC 3161 defines the
request/response format; ETSI EN 319 421 defines the operational
requirements for qualified status.

**Configured vendors (free, no account, no vendor lock-in):**

| Vendor | URL | Status | eIDAS-qualified? |
|---|---|---|---|
| FreeTSA | https://freetsa.org/tsr | Primary, live-tested | No (research-grade) |
| DigiCert | http://timestamp.digicert.com | Fallback, live-tested | No (RFC 3161) |
| sigstore/timestamp-authority (self-hosted) | github.com/sigstore/timestamp-authority | Optional | No (operator CA) |

**Optional paid integrations for deployments with eIDAS requirements:**

| Vendor | Pricing | eIDAS-qualified? |
|---|---|---|
| GlobalSign Timestamping SaaS | ~$1K–5K/yr | Yes (AATL + eIDAS) |
| GLOBALTRUST | Contact sales | Yes (eIDAS) |

To add a paid qualified TSA, edit `DEFAULT_TSA_CHAIN` in
`oversight_core/timestamp.py` and put the paid endpoint first. The RFC 3161
client code is URL-identical across providers.

FreeTSA modernized to the P-384 curve in March 2026, valid until 2040.
Timestamps are self-consistent and court-useful as long as the examiner
trusts FreeTSA's published root cert. Not eIDAS-qualified, so EU litigation
may reject it. Under US FRE 901, FreeTSA's timestamps satisfy "evidence that
the item is what the proponent claims it is" as long as chain of custody is
documented — sufficient for most legal purposes short of financial-regulatory
disputes.

### Sigstore Rekor v2 transparency log — shipped in v0.5

Oversight now attests registrations into a public Sigstore Rekor v2 log.
Implementation lives in `oversight_core/rekor.py` (Python) and
`oversight-rust/oversight-rekor/` (Rust), with a conformance suite proving
byte-identical behavior across the two implementations.

- Wire format: DSSE statements appended via `/api/v2/log/entries` on
  `log2025-1.rekor.sigstore.dev`, returning real `log_index` values.
- Predicate type resolves to a git-tagged GitHub path
  (`docs/predicates/registration-v1.md`) so third-party verifiers can
  resolve the schema without a live oversight.dev endpoint.
- Privacy contract: recipient X25519 public keys are SHA-256 hashed before
  going on-log.
- Opt-in by default (`OVERSIGHT_REKOR_ENABLED=1`). Failures are non-fatal;
  the local SQLite tlog stays authoritative for issuer-scoped queries.
- Offline verification: `build_bundle()` produces a sigstore-compatible
  bundle (`bundle_schema: 2`) carrying the log public key, checkpoint,
  entry schema, and optional RFC 3161 chain.
- Test coverage: 10 Python unit tests + 9 Rust unit tests + 2 live end-to-end
  tests + 5 backcompat tests + 4 cross-language conformance checks.

Self-hosted Rekor v2 is supported: point `OVERSIGHT_REKOR_URL` at a private
instance. Trillian or tile-backed deployments both work since the protocol
surface is the upstream Rekor v2 API.

### Rust canonical port of the hot path — shipped in v0.4

The seal / open / manifest / policy / semantic / tlog / rekor path is
implemented as a Rust workspace under `oversight-rust/`, with `cargo build
--workspace --release` passing with zero warnings. Python remains the
reference implementation; Rust is the canonical implementation for
production deployments. A conformance suite proves bit-identical output for
every manifest and envelope.

**Current crate selection:**

| Function | Python reference | Rust canonical | Notes |
|---|---|---|---|
| X25519 + Ed25519 + AEAD | `cryptography` + `pynacl` | `aws-lc-rs` | Audited |
| ML-KEM-768 | `liboqs-python` | `ml-kem` (RustCrypto, pure Rust) | FIPS 203; pending independent audit |
| ML-DSA-65 | `liboqs-python` | `ml-dsa` (RustCrypto) | FIPS 204; pending independent audit |
| HKDF / SHA-2 | `cryptography` | `hkdf` + `sha2` (RustCrypto) | Audited |
| JSON canonicalization | `json` | `serde_json` + `canonical_json` | — |
| Transparency log | `oversight_core/tlog.py` | `oversight-tlog` + `oversight-rekor` | Local + Rekor v2 |

A dual-stack build option lets operators diff outputs between AWS-LC and
liboqs to catch divergence in PQ implementations.

The registry server remains Python + FastAPI; the performance-critical path
is client-side.

---

## In progress

### Open-source strong-key protection (hardware security keys)

Earlier drafts proposed a cloud-TEE design to hold recipient private keys
with attestation-gated release. That approach tied Oversight to a single
cloud vendor, which contradicts the "truly open source" goal, and has been
dropped.

The remaining threat: an adversary who steals both a ciphertext and a
recipient's private key. With plain X25519, they win. The defense is a
hardware security key — YubiKey 5, OnlyKey, Nitrokey, or any FIDO2/PIV
device. All are vendor-independent, ~$50–$80 one-time, no cloud account.

The recipient's X25519 private key is generated on the device and never
leaves it. All ECDH operations happen inside the device's secure element.
The host OS sees only ECDH outputs. Even with root on the recipient's
machine, an adversary can only perform ECDH while the device is plugged in
(and typically touch-to-confirm or PIN-gated).

**Tradeoffs vs. a TEE design:**

- Weaker: does not prove "a specific signed binary is the decryptor."
  An attacker with the plugged-in device can still open files via a
  compromised client.
- Equal: an attacker who only stole a key file off a dead drive gets
  nothing.
- Better for open source: no cloud vendor, no recurring cost, no
  attestation-based revocation choreography — deauthorization is a
  single row change in the registry.

**Integration plan:**

1. Define a `KeyProvider` trait in `oversight-crypto`:
   ```rust
   pub trait KeyProvider {
       fn x25519_public(&self) -> [u8; 32];
       fn ecdh(&self, peer_pub: &[u8; 32]) -> Result<[u8; 32], KeyError>;
       fn ed25519_sign(&self, msg: &[u8]) -> Result<[u8; 64], KeyError>;
   }
   ```
2. Ship two providers:
   - `FileKeyProvider` — current behavior, 0600-mode JSON key file.
   - `PivKeyProvider` — PKCS#11 to a YubiKey or Nitrokey slot, via the
     `yubikey` or `pcsc` crate.
3. The registry records whether each recipient pubkey is `file_backed` or
   `hardware_backed`, so issuers can require hardware backing for sensitive
   material.
4. `docs/HARDWARE_KEYS.md` documents a vendor-neutral setup covering
   YubiKey 5C, OnlyKey, and Nitrokey 3.

Operators who need the stronger TEE guarantee can layer AWS Nitro, Azure
Confidential VMs, or Google Confidential Computing on top of Oversight
themselves. The core will not bake any specific cloud vendor in.

### Spec publication

**GitHub (complete).** Canonical repo:
[github.com/oversight-protocol/oversight](https://github.com/oversight-protocol/oversight).
Licensed Apache 2.0. Test vectors published. Discussions open for
community questions.

**arXiv preprint (in progress).** ~15-page paper targeting `cs.CR`.
Structure: motivation, threat model, protocol, cryptographic construction,
security arguments, implementation, evaluation, limitations, related work.
arXiv publishes within 1–2 days of endorsement; this establishes
date-of-invention and a citable artifact.

**IETF Internet-Draft (next).** Format as `draft-oversight-00` using
xml2rfc or mmark; submit to datatracker.ietf.org; present at an informal
BoF of a security working group (SUIT, OHAI, LAKE, or CFRG depending on the
framing chosen). Iterate 6–12 months before pushing for RFC publication.
Multiple independent implementations are required before the RFC stage.

---

## Planned

### Independent security review

Trail of Bits, NCC Group, and Cure53 are the primary candidates. Trail of
Bits has the strongest Sigstore-ecosystem track record (rekor-monitor, OpenSSF
funding) and has publicly funded post-quantum tooling. Zellic is an
additional candidate for cryptography-heavy scope.

**Typical engagement shape:**

- Scope: `oversight_core/crypto.py`, `oversight_core/container.py`,
  `oversight_core/manifest.py`, `oversight_core/policy.py`, the Rust
  counterparts, and the SPEC.md document.
- Duration: 4–8 engineer-weeks.
- Cost: $75K–$200K depending on firm and depth.
- Deliverable: private report, 60-day disclosure window, then public
  blog-post version with findings and fixes.

**Prerequisites before soliciting quotes:**

1. Freeze the spec (no changes during review).
2. Publish test vectors.
3. Publish a threat model document (STRIDE or similar), 5–10 pages.
4. Fuzz the container parser for 24+ hours and fix anything that trips.
5. Complete an internal review pass first — catching bugs in-house makes
   paid review far more valuable.

Target window: 2027, after v1.0 spec freeze.

### Conference presentations

**Closed for 2026:**

- Black Hat USA 2026 Briefings (closed March 20, 2026)
- WOOT '26 (closed March 3, 2026)
- USENIX Security '26 Cycle 1 (closed February 5, 2026)

**Open or upcoming:**

- **USENIX Security '26 Cycle 2** — full papers due early June 2026
  (re-verify at usenix.org/sec26/cfp). Primary academic target for the
  Oversight v0.5 cycle.
- **Black Hat Europe 2026** (December 2026, London) — CFP typically opens
  July, closes August. Industry-track audience; strong fit for the
  "defensive watermarking and attribution" framing.
- **Black Hat USA 2027 Briefings** — CFP opens ~January 2027, closes ~March.
- **WOOT '27** — academic track closes ~December 2026.
- **ACSAC 2026** — submissions typically open May–June.

**Framing:** open protocol for data provenance, attribution, and leak
detection for the post-quantum era. Vendor-neutral alternative to
proprietary DRM. Rust implementation, peer-reviewed crypto, no cloud
lock-in, no custom cryptography.

**Demonstration material:**

- Live seal and open with DEK wrapping, shown in both Python and Rust for
  cross-language compatibility.
- Live leak simulation: paste watermarked text into a webform, scraper
  picks it up, attribution fires in real time.
- Hybrid PQ demonstration showing size overhead and future-proofing.
- Air-gap strip demonstration: open in a VM, retype, paste to a pastebin,
  attribution still fires via L3 semantic marks.
- Hardware-key demonstration: pull the device mid-open; open fails cleanly.

---

## Phased plan

| Phase | Horizon | Items | Status |
|---|---|---|---|
| 0 | Complete | GitHub org, Apache 2.0 license, v0.5 release, SECURITY.md | Shipped |
| 1 | Complete | FreeTSA + DigiCert RFC 3161 chain, live verified | Shipped (v0.3) |
| 2 | Complete | Rust canonical port of hot path, conformance suite | Shipped (v0.4) |
| 3 | Complete | Rekor v2 integration, public log attestations, cross-language parity | Shipped (v0.5) |
| 4 | Near-term | arXiv preprint, threat model document, conformance vectors | In progress |
| 5 | Near-term | Hardware `KeyProvider` in Rust, `docs/HARDWARE_KEYS.md` | In progress |
| 6 | Mid-term | Internet-Draft submission, working-group BoF presentation | Planned |
| 7 | Mid-term | USENIX Security Cycle 2 paper submission | Planned |
| 8 | Mid-term | Black Hat Europe 2026 CFP submission | Planned |
| 9 | 2027 | Independent security audit (Trail of Bits / NCC / Cure53 / Zellic) | Planned |
| 10 | 2027 | v1.0 release, RFC shepherding, Black Hat USA 2027 | Planned |

## Cost outlook

| Item | Cost |
|---|---|
| FreeTSA (primary TSA) | $0 |
| DigiCert (fallback TSA) | $0 |
| Public Sigstore Rekor v2 | $0 |
| GitHub Actions CI (open-source tier) | $0 |
| Hardware keys for development and testing (2 units) | ~$100 |
| Domain, DNS, public beacon hosting (annual) | ~$60 |
| Conference registration and travel (USENIX + Black Hat EU) | ~$6K |
| Independent security audit (2027) | $75K–$200K |

All year-one work runs on free and open infrastructure. Paid dependencies
are optional, not required.
