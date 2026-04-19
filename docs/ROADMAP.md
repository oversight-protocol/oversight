# Oversight — External Roadmap (research-backed, v0.3)

This was the plan for the external items that couldn't be built inside a
single code session. Revised in v0.3 to reflect: (a) Nitro Enclaves dropped
in favor of open-source hardware keys, (b) audit budget deferred to 2027,
(c) FreeTSA integration shipped, (d) Rust port core shipped.

Every item has real vendor links, current pricing, and timelines so you can
decide, not guess.

Dates and prices as of April 17, 2026. Re-verify before committing money.

---

## 1. RFC 3161 qualified timestamps ✅ SHIPPED in v0.3

**Status:** `oversight_core/timestamp.py` + `registry/server.py`
`qualified_timestamp_or_stub()` now perform real RFC 3161 requests.
Default TSA chain tries FreeTSA first, falls back to DigiCert, falls back
to the registry's own clock if both are unreachable. Verified working with
a real FreeTSA round-trip: 4667-byte signed TimeStampToken, valid P-384
signature, correct gen_time, correct nonce.

**Why this mattered:** for an evidence bundle to be admissible in court
under EU eIDAS (qualified) or US Federal Rules of Evidence 901
(authenticated), the timestamp must come from a Time Stamp Authority whose
clock and signing key are independently auditable. RFC 3161 defines the
request/response format; ETSI EN 319 421 defines the operational
requirements for qualified status.

### What's wired (all free, no account, no vendor lock-in)

| Vendor | URL | Status | eIDAS-qualified? |
|---|---|---|---|
| **FreeTSA** | https://freetsa.org/tsr | Primary, tested working | No (research-grade) |
| **DigiCert** | http://timestamp.digicert.com | Fallback, tested working | No (RFC 3161) |
| Self-host sigstore/timestamp-authority | github.com/sigstore/timestamp-authority | Optional | No (your own CA) |

### What's NOT wired (left as optional for users with eIDAS needs)

| Vendor | Pricing | eIDAS-qualified? |
|---|---|---|
| GlobalSign Timestamping SaaS | ~$1K–5K/yr | Yes (AATL + eIDAS) |
| GLOBALTRUST | Contact sales | Yes (eIDAS) |

To add a paid qualified TSA, edit `DEFAULT_TSA_CHAIN` in
`oversight_core/timestamp.py` and put the paid endpoint first. The
integration is URL-identical — same RFC 3161 client code works.

### Notes on what FreeTSA gives you

- FreeTSA modernized to P-384 curve in March 2026, valid until 2040.
- Timestamps are self-consistent and court-useful as long as the
  examiner trusts FreeTSA's published root cert. Not eIDAS-qualified,
  so EU litigation may reject it.
- For US litigation under FRE 901, FreeTSA's timestamps satisfy
  "evidence that the item is what the proponent claims it is" as long as
  the chain of custody is documented. Sufficient for most legal purposes
  short of financial-regulatory disputes.

---

## 2. Sigstore Rekor v2 transparency log

**Status in the code:** `oversight_core/tlog.py` is a custom Merkle tree that's
self-consistent but NOT RFC 6962 compliant (it uses "promote odd trailing"
instead of left-heavy split). Inclusion proofs won't verify against a
standard RFC 6962 verifier like Sigstore's.

**Why migrate:** Rekor v2 went GA October 2025. It's a tile-backed transparency
log, cheaper to run, simpler to maintain, and its inclusion proofs are RFC 6962
compliant so any Sigstore-ecosystem tool (rekor-cli, rekor-monitor,
sigstore-python/go/java) can verify OVERSIGHT entries without custom code.

### Two deployment options

**Option A — Use the public Sigstore Rekor instance.**
  - URL: `https://rekor.sigstore.dev` — 99.5% SLO, monitored oncall
  - Free for open source / reasonable use
  - Entry size limit: 100 KB (our manifests fit easily)
  - Pros: zero ops burden, ecosystem tooling works out of the box
  - Cons: public log — registry events are visible to anyone watching

**Option B — Run our own Rekor v2 instance on CT 222.**
  - Self-hosted, private to CumpsterMedia, full control over retention
  - Uses Google Trillian as backend (or the newer tile-backed mode)
  - Pros: private events, can enforce jurisdictional retention rules
  - Cons: you operate the signing key, downtime = blind spot, SLO is yours

**Recommendation:** start with our own `oversight_core/tlog.py` for dev/test,
migrate to **Option B (self-hosted Rekor v2)** for production. Rekor v2 is
now simple enough to self-host that the operational cost is modest — small
Postgres DB + the Rekor server binary.

### Integration plan

Replace `oversight_core/tlog.py` with a thin client wrapper:

```python
import httpx
class RekorClient:
    def __init__(self, rekor_url: str, signer_key):
        self.url = rekor_url
        self.signer = signer_key  # Ed25519 signing key for OVERSIGHT events
    def append(self, event: dict) -> dict:
        # Build a sigstore-bundle-formatted entry with the event as payload
        # POST /api/v2/log/entries
        ...
    def get_inclusion_proof(self, uuid: str) -> dict: ...
    def get_signed_tree_head(self) -> dict: ...
```

Keep the signed tree head verification in `integrations/perseus_canarykeeper.py`
— the Rekor public key is distributed via TUF.

**Effort:** ~1 week to swap in a full Rekor client + self-host Rekor v2 +
wire rekor-monitor for alerting.

---

## 3. Rust port of the hot path

**Status in the code:** all Python. Fine for a reference implementation;
not what I'd run on 10K seal operations/second or put in a kernel-adjacent
security product.

**Why Rust:** 37% of cryptographic library vulnerabilities are memory safety
issues per the Blessing et al. study on crypto library CVEs. Rust eliminates
that class. For OVERSIGHT specifically, the seal/open hot path is small
enough (~1K LOC) to port quickly.

### Crate selection (verified current as of April 2026)

| Function | Python (today) | Rust (port) | Status |
|---|---|---|---|
| X25519 + Ed25519 + AEAD | `cryptography` + `pynacl` | `aws-lc-rs` | Production, audited |
| ML-KEM-768 | `liboqs-python` | `ml-kem` (RustCrypto, pure Rust) | FIPS 203, NIST vectors, **not independently audited** |
| ML-DSA-65 | `liboqs-python` | `aws-lc-rs` (unstable flag) or `ml-dsa` (RustCrypto) | FIPS 204, gated behind flag |
| HKDF / SHA-2 | `cryptography` | `hkdf` + `sha2` (RustCrypto) | Audited |
| JSON canonicalization | `json` | `serde_json` + `canonical_json` | Fine |
| Merkle log | custom | `rs-merkle` or defer to Rekor | Fine |

**Recommendation:** `aws-lc-rs` for classical + `liboqs` bindings
(`oqs-sys` crate) for PQ in v0.3. Switch PQ to pure-Rust `ml-kem`/`ml-dsa`
in v0.4 once those crates receive independent audits. Dual-stack build option
lets us diff outputs between AWS-LC and liboqs and catch bugs.

### Port plan

Scope: `oversight_core/crypto.py` + `oversight_core/container.py` +
`oversight_core/manifest.py` + `oversight_core/policy.py`. About 1K LOC total,
so a realistic timeline is:

- Week 1: `oversight-crypto` crate — X25519/Ed25519/AEAD/HKDF + unit tests against
  Python-generated vectors
- Week 2: `oversight-container` crate — binary format parser + seal/open +
  fuzz with `cargo-fuzz`
- Week 3: PQ crypto + hybrid wrap
- Week 4: Cross-language test: seal in Python, open in Rust, and vice versa
  (conformance test vectors).

Don't port the registry server — Python + FastAPI is fine there, and the
perf-critical path is client-side anyway.

**Decision needed from you:** now, or after v0.2 is spec-frozen?

**My recommendation:** freeze v0.2 spec first. Don't have two moving targets.
Rust port targets v0.3 or v1.0.

---

## 4. Open-source strong-key protection (YubiKey / hardware security keys)

**Why this replaces the original AWS Nitro Enclaves plan:**

An earlier draft proposed AWS Nitro Enclaves for confidentiality — a TEE
would hold recipient private keys, release them only when a KMS policy matched
the enclave's measured boot hash. That design works, but it tied Oversight to
a single cloud vendor. Antithetical to "truly open source." Dropped.

The threat we're still defending against: adversary steals BOTH a ciphertext
AND a recipient's private key. With plain X25519, they win — the key
decrypts. We need a story where key theft alone isn't enough.

The open-source answer is a **hardware security key** — YubiKey 5 series,
OnlyKey, Nitrokey, or any FIDO2/PIV device. All are vendor-independent,
all are ~$50–$80 one-time, no cloud account needed.

The recipient's X25519 private key is generated on the device and never
leaves it. All ECDH operations happen inside the device's secure element.
The host OS has access only to ECDH outputs, never the raw private key. Even
with root on the recipient's laptop, the adversary can only do ECDH while the
device is physically plugged in (often plus a touch-to-confirm or PIN).

### What this does and doesn't buy us

Compared to the Nitro plan:
- **Weaker:** we don't get "specific code running is proven, plaintext never
  touches the host." An attacker with the plugged-in device can still open
  Oversight files via a compromised client.
- **Equal:** an attacker who only stole a `~/.oversight/alice.key` file
  off a dead hard drive gets nothing.
- **Better for open source:** no cloud vendor, no recurring bill, no
  attestation-based key revocation puzzle (just deauthorize the device pub
  key in the registry).

### Integration plan

1. Define a `KeyProvider` trait in the Rust `oversight-crypto` crate:
   ```rust
   pub trait KeyProvider {
       fn x25519_public(&self) -> [u8; 32];
       fn ecdh(&self, peer_pub: &[u8; 32]) -> Result<[u8; 32], KeyError>;
       fn ed25519_sign(&self, msg: &[u8]) -> Result<[u8; 64], KeyError>;
   }
   ```
2. Ship two providers out of the box:
   - `FileKeyProvider` — current behavior, keys in a 0600 JSON file.
   - `PivKeyProvider` — PKCS#11 to a YubiKey / Nitrokey slot. Uses
     `yubikey` crate or `pcsc` crate in Rust.
3. The registry records whether a recipient pubkey is `file_backed` or
   `hardware_backed` in the `recipients` table, so issuers can require
   hardware-backed recipients for sensitive material.
4. Document a vendor-neutral setup guide in `docs/HARDWARE_KEYS.md`:
   same instructions work for YubiKey 5C, OnlyKey, Nitrokey 3.

### Costs
- $50–$80 per recipient, one-time.
- Zero recurring, zero vendor account.

### When the Nitro path still makes sense
Only when you need the "a specific signed binary is what decrypts, not a
specific person who has the key" guarantee — e.g., a confidential-computing
service offered to third parties where YOU operate the open client and want
to prove it to auditors. That's out of scope for an open protocol. Users who
want that can layer Nitro, Azure Confidential VMs, or Google Confidential
Computing on top of Oversight themselves. We won't bake AWS in.

---

## 5. Spec publication (GitHub + arXiv + IETF)

### Timeline

**Month 0 (now): GitHub.**
- Public repo: `github.com/<you>/oversight` OR new org `oversight-protocol`.
- Apache 2.0 license (already in the code).
- Tag `v0.2.1`, write a first release with test vectors.
- Create a GitHub Discussions or Matrix channel for questions.

**Month 1: arXiv.**
- Write a ~15-page paper. Target: `cs.CR` category.
- Structure: motivation → threat model → protocol → cryptographic
  construction → security arguments → implementation → evaluation →
  limitations → related work.
- arXiv will publish within 1–2 days after endorsement. No peer review.
  This establishes date-of-invention and gives something to cite.

**Month 2–4: Internet-Draft.**
- Format spec as an IETF I-D (`draft-<lastname>-oversight-00`) using
  xml2rfc or mmark.
- Submit to datatracker.ietf.org. Present at an informal BoF of a
  security working group (SUIT? OHAI? LAKE? CFRG? — pick based on the
  angle you lead with).
- Iterate for 6–12 months before pushing for RFC publication. Multiple
  independent implementations required before RFC.

**Month 6+: conference paper** (see section 7).

### Decision needed from you

- Personal GitHub or new `oversight-protocol` org?
- Any conflict between publishing as "OVERSIGHT" and your existing
  HackerOne handle `artemispwns1`? (Answer probably no, but worth stating.)
- Do you want your real name or a pseudonym on the arXiv submission?

---

## 6. Independent security review

**Research:** I looked at who would be the right fit. Trail of Bits has the
best track record on Sigstore ecosystem work — they built rekor-monitor and
have publicly funded Sigstore tooling via OpenSSF. They also have dedicated
cryptography engineers with post-quantum experience. NCC Group and Cure53 are
comparable tier.

### Typical engagement shape

- Scope: full code + spec review of `oversight_core/crypto.py`,
  `oversight_core/container.py`, `oversight_core/manifest.py`,
  `oversight_core/policy.py`, plus the SPEC.md document.
- Duration: 4–8 engineer-weeks of review.
- Cost: **$75K–$200K** depending on firm and depth. Trail of Bits' publicly
  documented engagements have run in that band.
- Deliverable: private report, then a 60-day-disclosure window, then a public
  blog-post version with findings + fixes.

### Prerequisites (do these BEFORE asking for a quote)

1. Freeze the spec at v0.2.1 (no changes during review).
2. Publish test vectors.
3. Write a threat model document (STRIDE or similar). 5–10 pages.
4. Fuzz the container parser for 24+ hours and fix anything that trips.
5. Run your own internal review pass — catching your own bugs first makes
   the paid review far more valuable.

### Decision needed from you

- **Deferred to 2027+** (per budget constraint — not this year).
- When you're ready: Zellic, NCC Group, Cure53 also do comparable work;
  do 2–3 quote calls before picking.

---

## 7. Conference talks (Black Hat, USENIX, WOOT)

### What's already closed (re-verified April 2026)

- **Black Hat USA 2026 Briefings**: CFP closed March 20, 2026. Miss it.
- **WOOT '26 academic track**: March 3 closed. Up-and-coming track: March 3
  closed too.
- **USENIX Security '26 Cycle 1**: February 5 closed.

### What's open or upcoming

- **USENIX Security '26 Cycle 2**: full papers due ~early June 2026
  (timeline: re-verify at usenix.org/sec26/cfp, but the cycle-2 window is
  typically 3–4 months after cycle-1). **This is the realistic academic
  target for Oversight v0.3.**
- **Black Hat Europe 2026** (Dec 2026, London): CFP typically opens July
  and closes August. Industry-track audience — perfect for a
  "defensive watermarking + attribution" talk.
- **Black Hat USA 2027 Briefings**: CFP opens ~January 2027, closes ~March.
- **WOOT '27**: academic track closes ~December 2026.
- **ACSAC 2026**: submissions typically open May–June.

### Talk framing (so the CFP reviewer says yes)

Frame as: "Open protocol for data provenance, attribution, and leak
detection for the post-quantum era. Vendor-neutral alternative to
proprietary DRM. Rust implementation, peer-reviewed crypto, no cloud
lock-in, no custom cryptography."

Concrete demo for the talk:
- Live seal + open with DEK wrapping — shown in both Python and Rust
  for cross-language compatibility.
- Live leak simulation: paste watermarked text into a webform, scraper
  picks it up, attribution fires in real time.
- Hybrid PQ → show size overhead + future-proofing.
- Airgap-strip demo: open in a VM, retype, paste to pastebin, attribution
  still fires via L3 semantic.
- YubiKey demo: pull the YubiKey out mid-open → open fails cleanly.

### Decision needed from you

- Which venue first? My recommendation:
  1. arXiv preprint now (month 1).
  2. USENIX Security '26 Cycle 2 submission (June 2026) — academic cred.
  3. Black Hat Europe 2026 (Dec 2026) — industry reach.
  4. Black Hat USA 2027 Briefings (Aug 2027) — flagship.

---

## Phased action plan (tldr)

| Phase | Timeline | Items | Decision gates |
|---|---|---|---|
| 0 — now | week 1 | Freeze v0.3 spec; GitHub repo public; write SECURITY.md | GitHub org name |
| 1 — soon | month 1 | arXiv preprint; conformance vectors; threat model | Real name or pseudonym |
| 2 — near | month 2 | Wire FreeTSA (done) + DigiCert fallback (done); swap tlog → Rekor v2 self-hosted | — |
| 3 — near | month 3 | Internet-Draft submission to datatracker | Which WG to target |
| 4 — mid | month 4–6 | USENIX Security Cycle 2 paper submission | — |
| 5 — mid | month 4–9 | Complete Rust port (watermark L3 + registry + formats) | — |
| 6 — mid | month 6–9 | YubiKey / hardware KeyProvider in Rust crate | — |
| 7 — late | month 9–12 | Black Hat Europe 2026 CFP | — |
| 8 — 2027 | year 2 | Paid security audit (Trail of Bits tier) | Budget available |
| 9 — 2027 | year 2 | v1.0 release; RFC shepherding; Black Hat USA 2027 | — |

## Budget estimate (12-month horizon, year 1 only)

| Item | Cost |
|---|---|
| FreeTSA (free, tested, working) | $0 |
| DigiCert fallback TSA (free) | $0 |
| Rekor v2 self-hosting (CT 222 on existing Proxmox) | $0 |
| Rust toolchain + CI (GitHub Actions free tier) | $0 |
| YubiKey 5C for development/testing (2 units) | $100 |
| Domain + DNS + public beacon hosting (1 yr) | $60 |
| Conference registration + travel (USENIX Sec + Black Hat EU) | $6K |
| **Year-1 total** | **~$6K** |

Year 2 (2027) adds:
| Trail of Bits / NCC / Cure53 audit | $75K–$200K |
| Extended conference / travel | $5K–10K |

**The audit is deferred to 2027 per your constraint.** Year 1 ships for
under $6,200, all-in, with no cloud-vendor dependencies and no custom
cryptography.
