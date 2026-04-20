# Oversight Protocol

**Open protocol for cryptographic data provenance, recipient attribution, and leak detection.**

Co-authored by Zion Boggan and Claude Opus 4.6/4.7 (Anthropic).

Format-agnostic. Post-quantum ready (ML-KEM-768 + ML-DSA-65). Three-layer watermarking that survives format conversion, invisible-char stripping, and screenshot/OCR. Content fingerprinting that identifies leaked copies even when all watermarks are destroyed.

No cloud vendor lock-in. No paid service required. No custom cryptography. Apache 2.0.

**Website:** https://oversight-protocol.github.io/oversight/

---

## Install

Requires Python 3.10+.

```bash
# Clone the repo
git clone https://github.com/oversight-protocol/oversight.git
cd oversight

# Install (adds the `oversight` command to your PATH)
pip install .

# Verify
oversight status
```

That's it. The `oversight` command is now available globally.

### Optional extras

```bash
# Include registry server (FastAPI)
pip install ".[registry]"

# Include format adapters (PDF, DOCX, image watermarking)
pip install ".[formats]"

# Everything
pip install ".[all]"
```

## Quick start

```bash
# 1. Initialize a project directory
mkdir my-project && cd my-project
oversight init

# 2. Generate your issuer identity
oversight keys generate --name zion

# 3. Generate a recipient identity (they would do this on their machine)
oversight keys generate --name alice --out alice.json

# 4. Import the recipient's public key
oversight keys import alice.pub.json

# 5. Seal a document to the recipient (watermarks embedded by default)
oversight seal report.txt --to alice

# 6. The recipient opens the sealed file
oversight open report.txt.sealed --out report-decrypted.txt

# 7. If the document leaks, attribute it
oversight attribute --leak leaked.txt --fingerprints .oversight/fingerprints
```

### What happens when you seal

The seal command applies three watermark layers to the document, each targeting a different attack surface:

- **L1** inserts zero-width Unicode characters (survives copy-paste)
- **L2** encodes bits in trailing whitespace patterns (survives most editors)
- **L3** rotates synonyms from a 151-class dictionary, adjusts punctuation style, spelling variants, and contractions (survives format conversion, invisible-char stripping, and screenshot/OCR)

Then it encrypts to the recipient's X25519 public key, timestamps via RFC 3161, logs to the Merkle tree, and writes the `.sealed` file plus a `.fingerprint.json` sidecar for the content fingerprint database.

Oversight currently emits one sealed file per recipient. Multi-recipient
sealing is intentionally disabled until the manifest format can bind
multiple recipients without weakening attribution evidence.

### What happens when you attribute

The attribute command runs a 5-phase pipeline:

1. **Direct extraction** of L1/L2 marks from the leaked text
2. **Registry query** for candidate mark IDs
3. **L3 semantic verification** against candidates (synonym score + punctuation + spelling + contractions)
4. **Multi-layer Bayesian fusion** combining all evidence into ranked candidates
5. **Content fingerprint comparison** (winnowing + sentence hashing) as a last resort when all watermarks are stripped

## What's new in v0.4.3

**Anti-stripping defenses.** ECC-protected synonym bits (R=7 repetition codes), winnowing content fingerprints, sentence-level content hashing, 25 spelling variant pairs, 30 contraction choices, number formatting marks. The VM-strip-export attack (open in airgapped VM, strip invisible chars, export clean file) is now defended by content fingerprinting.

**Rich interactive CLI.** Colorful terminal interface with progress bars, panels, config management, and streamlined commands. Run `oversight init` to get started.

**L3 integration.** The 151-class synonym rotation system and punctuation fingerprinting, previously implemented but not wired into the pipeline, are now fully integrated. Multi-layer Bayesian fusion combines L1, L2, and L3 evidence.

See `CHANGELOG.md` for full version history.

## Security hardening

- `max_opens` now counts only successful recipient decryptions, not failed key guesses.
- `LOCAL_ONLY` open counters now work on Windows as well as POSIX hosts.
- `REGISTRY` and `HYBRID` policy modes fail closed instead of silently falling back to local counters.
- Rekor offline verification now checks the attested digest against the expected content hash.
- Registry Rekor attestations now index by real watermark mark IDs and the manifest's actual `content_hash`.
- Multi-recipient sealing is disabled until a recipient-honest manifest format lands.

## Repository layout

```
oversight/                              Python reference (6,800 LOC)
├── oversight_core/
│   ├── crypto.py                      X25519 + Ed25519 + XChaCha20 + HKDF + PQ hybrid
│   ├── container.py                   .sealed binary format
│   ├── manifest.py                    signed canonical-JSON manifest
│   ├── watermark.py                   L1 zero-width, L2 whitespace
│   ├── semantic.py                    L3 synonyms + punctuation
│   ├── synonyms_v2.py                 150-class expanded dictionary
│   ├── policy.py                      not_after / max_opens / jurisdiction
│   ├── beacon.py                      DNS / HTTP / OCSP / license beacons
│   ├── tlog.py                        Merkle transparency log
│   ├── timestamp.py                   RFC 3161 (FreeTSA + DigiCert)
│   ├── decoy.py                       Ollama-powered decoy files
│   └── formats/{text,image,pdf,docx}.py
├── oversight_dns/server.py            authoritative NS for beacon domain
├── registry/server.py                 FastAPI — tlog, signed bundles, rate limit
├── integrations/
│   ├── flywheel_oversight_match.py    Flywheel scraper hook
│   └── perseus_canarykeeper.py        Perseus Discord alert agent
├── cli/oversight.py
├── tests/{test_e2e.py,test_e2e_v2.py,test_pq.py}
└── docs/{SPEC.md,ROADMAP.md,RUNBOOK.md}

oversight-rust/                         Rust port (~1,500 LOC, core complete)
├── Cargo.toml                          workspace
├── oversight-crypto/                   X25519, Ed25519, XChaCha20, HKDF, zeroize
├── oversight-manifest/                 JCS canonical JSON, Ed25519 sign/verify
├── oversight-container/                .sealed format parser, hard caps
├── oversight-watermark/                L1 + L2
├── oversight-cli/                      keygen / seal / open / inspect
└── tests/conformance_cross_lang.sh     bit-for-bit Python<->Rust conformance
```

## Quickstart

### Python reference (all features)

```bash
pip install -r requirements.txt
python tests/test_e2e.py         # 11 checks
python tests/test_e2e_v2.py      # 13 checks
python tests/test_pq.py          # 7 checks (needs liboqs)
```

### Rust core (crypto, container, manifest, watermark, CLI)

```bash
cd oversight-rust
cargo test --workspace           # 21 checks
cargo run -- keygen --out alice.json
cargo run -- seal --input doc.txt --output doc.sealed \
    --issuer issuer.json --recipient-pub <hex> --recipient-id alice@test
cargo run -- open --input doc.sealed --output - --recipient alice.json
```

### Cross-language conformance

```bash
bash oversight-rust/tests/conformance_cross_lang.sh
```

## Test coverage

| Layer | Checks | Status |
|---|---|---|
| Python test_e2e | 11 | green |
| Python test_e2e_v2 | 13 | green |
| Python test_pq | 7 | green |
| Rust oversight-crypto | 7 | green |
| Rust oversight-manifest | 2 | green |
| Rust oversight-container | 8 | green |
| Rust oversight-watermark | 4 | green |
| Rust oversight-tlog | 7 | green |
| Rust oversight-policy | 6 | green |
| Rust oversight-semantic | 8 | green |
| Cross-language conformance | 3 | green |
| Total | 76 | all green |

## Design principles (what Oversight never does)

- **No custom cryptography.** Every primitive is NIST-standardized or equivalent. `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`, ML-KEM-768, ML-DSA-65 via liboqs. That's the whole list.
- **No cloud vendor lock-in.** Dropped the original AWS Nitro Enclaves plan. Hardware-key protection uses any FIDO2 device (YubiKey, OnlyKey, Nitrokey). Transparency log can run on public Sigstore Rekor or self-hosted; your choice.
- **No RATs, no defensive malware.** Every "phone home" mechanism is a passive beacon — the kind of network call a normal document reader makes during rendering (image fetch, OCSP lookup, DNS resolution). We never execute code on a reader's machine.
- **No tracking of personal identifiers.** Mark IDs are random 128-bit tokens. The registry maps them to recipient IDs that the issuer chose — the issuer decides how much identity binding to apply.
- **No paid service required.** Year-1 all-in cost estimate: ~$6,200 (YubiKeys + domain + one conference). See `docs/ROADMAP.md`.

## Honest limitations

- **Human paraphrasing defeats watermarks.** Someone who reads the document and rewrites it in their own words leaves no trace. Fundamental, not an engineering gap.
- **Beacons fire only when the reader has network access.** Airgapped readers leave no callback. L3 semantic watermarking is the attribution path for that case.
- **The local Python Merkle transparency log is still not a full Sigstore-compatible substitute.**
  Public-log interoperability is now via Rekor DSSE attestations; the local log remains
  a lightweight registry integrity mechanism, not a drop-in replacement for Rekor.
- **No independent security audit yet.** Planned for 2027. Until then: user-beware, cryptographer-review welcome. Open an issue.
- **Rust port is core-only.** ~1,500 LOC ported. The remaining ~5,500 LOC (semantic dictionary, format adapters, registry server, integrations) is multi-release scope. Python is still the canonical reference.

## License

Apache 2.0. See `LICENSE`.
