# Oversight Protocol

**Open protocol for cryptographic data provenance, recipient attribution, and leak detection.**

Co-authored by Zion Boggan and Claude Opus 4.6/4.7 (Anthropic) and Codex ChatGPT-5-4 (OpenAI).

Format-agnostic. Post-quantum ready (ML-KEM-768 + ML-DSA-65). Layered watermarking with honest limits: L1/L2 are lightweight steganographic signals, L3 is opt-in semantic marking for prose, and content fingerprinting helps identify leaked copies even when fragile marks are destroyed.

No cloud vendor lock-in. No paid service required. No custom cryptography. Apache 2.0.

**Website:** [https://oversight-protocol.github.io/oversight/](https://oversightprotocol.dev/)
**Mobile companion (verifier):** [oversight-protocol/oversight-mobile](https://github.com/oversight-protocol/oversight-mobile) — Flutter UI on top of the same Rust crates that power this CLI, currently in internal TestFlight beta.

---

## Install

Requires Python 3.10+.

> **Not comfortable at the command line?** Oversight ships a small desktop app. After the `pip install` step below, run `oversight gui` (or `oversight-gui`) and follow the [GUI quick start](#gui-quick-start). All seal, open, and key-generation workflows are available through the GUI without ever opening a terminal again.

```bash
# Clone the repo
git clone https://github.com/oversight-protocol/oversight.git
cd oversight

# Install (adds the `oversight` command to your PATH)
pip install .

# Verify
oversight status
```

That's it. The `oversight` command is now available globally. The `oversight-gui` desktop app entry point is installed at the same time.

On Debian, Ubuntu, and derivatives, Tkinter is packaged separately. Install it once so the GUI can launch: `sudo apt install python3-tk`. On Windows and macOS, Tkinter ships with the standard CPython installer.

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

### GUI quick start

If you would rather click than type, run `oversight gui` (or the equivalent `oversight-gui` entry point). A single desktop window opens with three tabs that cover the same workflows as the CLI steps above.

1. **Generate Keys.** Pick an identity name and an output path, then press **Generate Keypair**. The GUI writes your private identity JSON (with `0600` permissions on POSIX or a best-effort Windows ACL narrowing) and a sibling `.pub.json` that you hand to any issuer who needs to seal something to you.
2. **Seal File.** Choose the input plaintext, the issuer's private key, and the recipient's `.pub.json`. Pick an L3 mode (`auto` is safest), leave the L1 and L2 watermark checkbox on, and press **Seal**. The GUI writes a `.sealed` container and a `.fingerprint.json` sidecar next to it. If L3 is about to rewrite body text, the GUI asks for explicit acknowledgement first, matching the CLI's `--l3-ack` gate.
3. **Open File.** Choose a `.sealed` file, your private identity, and an output path. The GUI verifies the manifest signature, enforces policy, decrypts the content, and writes the plaintext to the chosen location.

The full walk-through, including every field, the L3 disclosure flow, and troubleshooting for common issues, is at [oversightprotocol.dev/docs/gui.html](https://oversightprotocol.dev/docs/gui.html).

### What happens when you seal

The seal command applies watermark layers to the document, each targeting a different attack surface:

- **L1** inserts zero-width Unicode characters (survives copy-paste)
- **L2** encodes bits in trailing whitespace patterns (survives most editors)
- **L3** optionally rotates prose choices from a 151-class dictionary (survives format conversion and screenshot/OCR, but changes visible text and can be defeated by motivated collusion/canonicalization)

L3 defaults off for legal documents, regulatory filings, technical specifications, source code, SQL, logs, and structured data. When L3 is enabled, Oversight asks for explicit acknowledgement and records `canonical_content_hash` in the signed manifest so disputes can compare the recipient copy against the canonical source.

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

## What's new in v0.4.11

**Hardware-keys completion across every reference implementation.** v0.4.11
finishes what v0.4.10 started. The `OSGT-HW-P256-v1` suite now ships
end-to-end in `oversight_core.crypto` (Python: `wrap_dek_for_recipient_p256`,
`unwrap_dek_p256` accepting `EllipticCurvePrivateKey`, PKCS#8 bytes, or raw
integer scalars), in `oversight-container` (`seal_hw_p256` +
`open_sealed_with_provider` polymorphic dispatch on `suite_id`), in the
manifest schema (`Recipient.p256_pub` optional field, deserialization
back-compatible), and in the public browser inspector at
<https://oversightprotocol.dev/viewer/> via vendored `@noble/curves` P-256
ECDH. Every existing classic and hybrid call site is unchanged. The
container's existing rule that the unsigned `suite_id` header must match
the signed `manifest.suite` covers cross-suite-mixing attacks for free.
A new `tools/gen_hw_p256_sample.py` produces the public viewer's
`tutorial-hw-p256.sealed` fixture without needing `oqs` or hardware. The
last piece of the hardware story, `PivKeyProvider` against PKCS#11, is
the next bounded follow-up.

## What's new in v0.4.10

**Hardware-keys foundation.** `oversight-crypto` now exposes a
`KeyProvider` trait that abstracts the recipient-side ECDH so a
hardware-backed token (YubiKey / Nitrokey / OnlyKey via PIV) can plug
into the open path without changing call sites. `FileKeyProvider`
ships as the X25519 default. The hardware-track suite
`OSGT-HW-P256-v1` is fully implemented in software:
`wrap_dek_for_recipient_p256` + `WrappedDekP256` +
`SoftwareP256KeyProvider` (NIST P-256 ECDH, RustCrypto's `p256`
crate). `oversight-container` recognizes the new suite id (`3`) so
sealed files for hardware recipients ride the existing 1-byte header
dispatch without a layout change. The `PivKeyProvider` (PKCS#11)
implementation is the next bounded follow-up; the trait and software
reference let it ship without touching seal-side or container code.
Full crate test count is 21/21 in `oversight-crypto` and 12/12 in
`oversight-container`. Public API additive; v0.4.9 callers unchanged.

## What's new in v0.4.9

**Browser inspector decrypts hybrid (post-quantum) sealed files.**
The viewer at <https://oversightprotocol.dev/viewer/> now decrypts
both `OSGT-CLASSIC-v1` and `OSGT-HYBRID-v1` files end-to-end. The
hybrid path uses WebCrypto for X25519 + HKDF-SHA256, a vendored
`@noble/ciphers` for XChaCha20-Poly1305, and a vendored
`@noble/post-quantum` ML-KEM-768 for the post-quantum half of the
KEM. The KEK is bound X-wing-style over both shared secrets and
both ephemeral inputs (`ss_x || ss_pq || eph_pub || mlkem_ct`),
matching `oversight_core.crypto.hybrid_wrap_dek` byte for byte.
All vendored libraries ship with rewritten relative imports so the
inspector remains fully offline-capable. Try it with the new
"Load hybrid tutorial identity" button against `tutorial-hybrid.sealed`.

**Rust registry v1 conformance.** `oversight-rust/oversight-registry`
now exposes the full read-only and beacon surface
(`/.well-known/oversight-registry`, `/evidence/{file_id}`,
`/tlog/head|proof|range`, `/p/{token_id}.png`, `/r/{token_id}`,
`/v/{token_id}`, `/candidates/semantic`) and ships strict CORS
restricted to the public browser-inspector origins with GET and
OPTIONS only. The Axum server now passes `tests/test_registry_conformance.py`
(33/33) in live-URL mode. `oversight-rust/oversight-manifest` learned
to verify Python-signed v0.4.5+ manifests by carrying
`canonical_content_hash` and `l3_policy` in the signed model, with
a fallback path for older manifests that lack those fields.

**Format watermark round-trip fixes.** `oversight-rust/oversight-formats`
text embedding now keeps L2 trailing-whitespace marks at physical
line endings after L1 zero-width insertion, and image LSB embedding
no longer overwrites earlier payload bits via duplicate pixel
slots. Workspace test suite is green again.

## What's new in v0.4.8

**Mobile-build portability and security bump.** Patch release. The
Rust core's 4 GiB ciphertext-size cap is now gated to 64-bit targets
and falls back to `usize::MAX` on 32-bit, which is what unblocks the
mobile companion's `armv7` and `i686` Android builds (the desktop CLI
and registry are unchanged). `rustls-webpki` lifted to 0.103.13 to
pick up the GHSA-82j2-j2ch-gfr8 CRL parse fix and a corrected URI
name-constraint check; both apply to our Rekor TLS path.

## What's new in v0.4.7

**Registry federation hardening.** `docs/spec/registry-v1.md` now
specifies the canonicalization algorithm, the uniform error envelope
and code vocabulary, the full endpoint list including the normative
beacon paths, the `/.well-known/oversight-registry` shape, and the
`/evidence` bundle fields. The spec matches what the reference
registry actually serves, so an independent implementation can target
something real instead of something aspirational.

**Conformance harness.** `tests/test_registry_conformance.py` is a
32-check test that runs either against the reference registry
in-process (CI) or against any live URL
(`OVERSIGHT_REGISTRY_URL=https://registry.example.org python3
tests/test_registry_conformance.py`). An independent operator who
passes the harness can claim v1 compatibility.

## What's new in v0.4.6

**SIEM export.** Registry beacon events can now be emitted in three
SIEM-native formats: Splunk HEC envelopes, Elastic Common Schema 8.x
documents, and Microsoft Sentinel Log Analytics custom-log rows. The new
`oversight_core.siem` module ships pure formatters, a normalized
`OversightEvent` model built from the registry `events` table, file and
stdout and HTTP sinks, and a Sentinel HMAC signing helper.

**`oversight siem export` CLI.** Streams events as JSON lines to stdout,
a file, or a generic HTTPS collector. Supports `--since`, `--limit`,
repeatable `--header`, and Splunk source/sourcetype/index overrides.
Opens the registry database in read-only mode so it is safe to run
against a live service. Full operator guide at `docs/SIEM.md`.

## What's new in v0.4.5

**L3 safety and usability.** Semantic watermarking is now format-aware and
opt-in for sensitive classes, with full/boilerplate/off modes, disclosure
acknowledgement, canonical source hashing, protected-region skips, and explicit
collusion/threat-model documentation in `docs/security.md`.

**GUI starter.** `oversight gui` launches a small desktop app for key
generation, sealing, and opening files so non-technical recipients are not
forced through the CLI. The GUI and CLI now guard local writes so seal/open
outputs cannot overwrite selected input files or Oversight private-key JSON;
private-key generation uses atomic replacement and restrictive permissions or
best-effort Windows ACL hardening.

**Registry federation draft.** `docs/spec/registry-v1.md` documents the
interoperability contract for compatible registry operators.

## What's new in v0.4.4

**Security hardening over v0.4.3.** This line starts from the v0.4.3 Python
package baseline and adds the 2026-04-20 review fixes from Codex (GPT-5.4).
Use v0.4.4 or current `main` for the hardened behavior described below.

**Signed evidence continuity.** Registry registration now stores only the
beacons and watermarks that match the issuer-signed manifest, Rekor
attestations index by real watermark IDs and actual content hashes, and the
local transparency-log empty root matches RFC 6962.

**Recipient-honest policy enforcement.** `max_opens` counts only successful
recipient decryptions, Windows local counters work, registry-backed counter
modes fail closed until implemented, and unsafe multi-recipient sealing is
disabled until the manifest format can represent multiple recipients honestly.

## What's new in v0.4.3

**Anti-stripping defenses.** ECC-protected synonym bits (R=7 repetition codes), winnowing content fingerprints, sentence-level content hashing, 25 spelling variant pairs, 30 contraction choices, number formatting marks. The VM-strip-export attack (open in airgapped VM, strip invisible chars, export clean file) is now defended by content fingerprinting.

**Rich interactive CLI.** Colorful terminal interface with progress bars, panels, config management, and streamlined commands. Run `oversight init` to get started.

**L3 integration.** The 151-class synonym rotation system and punctuation fingerprinting, previously implemented but not wired into the pipeline, are now fully integrated. Multi-layer Bayesian fusion combines L1, L2, and L3 evidence.

See `CHANGELOG.md` for full version history.

## Security hardening

These items are included in v0.4.4/v0.4.5 and current `main`:

- `max_opens` now counts only successful recipient decryptions, not failed key guesses.
- `LOCAL_ONLY` open counters now work on Windows as well as POSIX hosts.
- `REGISTRY` and `HYBRID` policy modes fail closed instead of silently falling back to local counters.
- Rekor offline verification now checks the attested digest against the expected content hash.
- Registry Rekor attestations now index by real watermark mark IDs and the manifest's actual `content_hash`.
- Registry registration now refuses unsigned beacon/watermark sidecars that do not match the issuer-signed manifest.
- Multi-recipient sealing is disabled until a recipient-honest manifest format lands.
- Local transparency-log empty-tree roots now match RFC 6962 exactly.
- Rust registry and format-adapter paths now mirror the Python hardening:
  authenticated DNS beacon callbacks, no silent signed-artifact drops,
  digest-checked Rekor offline verification, fail-closed Rust `max_opens`,
  DOCX keyword insertion, and PDF action screening.
- L3 semantic watermarking is opt-in for sensitive classes, requires
  disclosure acknowledgement when enabled, and records `canonical_content_hash`.
- `.sealed` parsing rejects suite-byte tamper, malformed manifest or wrapped-DEK
  JSON, unknown manifest fields, and trailing bytes after ciphertext.
- Dependency floors now exclude known vulnerable PyPI and Rust manifest ranges
  flagged by Dependabot/advisory checks.

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

## Embedding the verification core

Downstream projects can embed the Oversight Rust verification core without
reimplementing it. The companion mobile verifier
([`oversight-protocol/oversight-mobile`](https://github.com/oversight-protocol/oversight-mobile))
does exactly this through `flutter_rust_bridge`, so a manifest that opens on
a desktop opens the same way on a phone with the same answer.

The full integration contract, including the seven verifier-safe crates,
the crates that are explicitly out of scope for downstream embedding, the
git-plus-tag pin pattern, and the minimum versions for 32-bit mobile
support, is documented at [`docs/EMBEDDING.md`](docs/EMBEDDING.md). v0.4.8
is the recommended pin for any new embedder; older tags work but the
project does not backport fixes below the current stable line.

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
