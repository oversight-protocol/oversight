# Oversight v0.5

**Open protocol + reference implementation for data provenance, attribution, and leak detection.**

Format-agnostic. Post-quantum-verified (ML-KEM-768 + ML-DSA-65 via liboqs). Jurisdiction-aware. Fully passive — no code execution on readers, no RATs, no defensive malware.

**Truly open source.** No cloud vendor lock-in. No paid service required. No custom cryptography. Every primitive is NIST-standardized and publicly auditable.

---

## What's new in v0.4

**Rust port expanded from core to core+enforcement+semantics.** Three new Rust crates on top of the v0.3 core:

- `oversight-tlog` — RFC 6962-compliant Merkle transparency log with signed tree heads, inclusion proofs, durable append.
- `oversight-policy` — TOCTOU-safe max_opens enforcement, jurisdiction / not_after / not_before checks, file-id sanitization.
- `oversight-semantic` — L3 airgap-strip-survivor watermarking with the full 151-class synonym dictionary and URL/code/path/hex/base64 skip regions.

**RFC 6962 fix in Python.** The v0.2 tlog used a promote-odd-trailing shortcut that was self-consistent but not RFC 6962 compliant — inclusion proofs wouldn't verify against Sigstore tooling. Now ported to the canonical largest-power-of-2 left-heavy split. Added `verify_inclusion_proof` helper. Tested across asymmetric tree sizes.

**Fuzz harness.** `cargo-fuzz` targets for container_parser and manifest_parser. Ready to run 24+ hours before a paid audit engagement.

**Hardware key setup guide.** `docs/HARDWARE_KEYS.md` covers YubiKey / Nitrokey / OnlyKey end-to-end — PIN/PUK setup, PIV slot provisioning, curve choice rationale, revocation, threat model, deployment checklist.

**Everything from v0.3 is still here.** FreeTSA RFC 3161 timestamps, cross-language conformance, Python↔Rust bit-for-bit compatibility, PQ hybrid, multi-recipient sealing, registry with signed bundles.

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
- **Our Merkle transparency log isn't RFC 6962 compliant** (uses promote-odd-trailing, not left-heavy split). Self-consistent but won't verify against Sigstore tooling. Planned migration to Rekor v2 in v0.4.
- **No independent security audit yet.** Planned for 2027. Until then: user-beware, cryptographer-review welcome. Open an issue.
- **Rust port is core-only.** ~1,500 LOC ported. The remaining ~5,500 LOC (semantic dictionary, format adapters, registry server, integrations) is multi-release scope. Python is still the canonical reference.

## License

Apache 2.0. See `LICENSE`.
