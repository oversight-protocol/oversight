# Oversight CHANGELOG

## Unreleased - 2026-04-20 security hardening

- `oversight_core/container.py`: `max_opens` now increments only after a
  successful decrypt, and unsafe `seal_multi()` is disabled until the
  manifest format can honestly represent multiple recipients.
- `oversight_core/policy.py`: `LOCAL_ONLY` counter locking now works on
  Windows, and `REGISTRY` / `HYBRID` fail closed instead of silently using
  local state.
- `oversight_core/rekor.py`: offline verification now rejects DSSE envelopes
  whose subject digest does not match the expected content hash.
- `registry/server.py`: Rekor attestations now use real watermark mark IDs
  and the manifest's actual `content_hash`, and `/register` now rejects
  unsigned beacon / watermark sidecars that do not match the signed manifest.
- `oversight_core/formats/text.py`: text adapter now applies L3 before L2/L1,
  matching the core watermark pipeline.
 - `oversight_core/tlog.py`: empty-tree roots now use the RFC 6962 Merkle
  hash (`SHA-256("")`) instead of an all-zero placeholder.
 - `oversight_core/__init__.py`: package `__version__` is back in sync with
  `pyproject.toml`.
- Added focused regression coverage in `tests/test_policy_unit.py`,
  `tests/test_registry_unit.py`, `tests/test_rekor_unit.py`,
  `tests/test_text_format_unit.py`, and `tests/test_tlog_unit.py`.

## v0.5.0 — 2026-04-19

First release with public-Rekor attestations. Now hosted at
https://github.com/oversight-protocol/oversight (so the v0.5 predicate URI
resolves for any third-party verifier).

### Session B (registry wiring + e2e + backcompat)
- `registry/server.py`: `/register` now opt-in attests each registration into
  a public Rekor v2 log. Off by default; opt in with
  `OVERSIGHT_REKOR_ENABLED=1`. Failures non-fatal — local SQLite tlog stays
  authoritative for "list marks for issuer X" queries.
- `oversight_core/rekor.py upload_dsse`: fixed three wire-shape bugs against
  current rekor-tiles proto (`verifier`→`verifiers` array, `keyDetails` as
  sibling of `publicKey`, `raw_bytes` carries DER not PEM). Verified live
  against `log2025-1.rekor.sigstore.dev` — got real `log_index` returned.
- `tests/test_rekor_e2e.py`: 2 live tests, gated behind
  `OVERSIGHT_REKOR_E2E=1` so default runs do not append entries to the
  public log.
- `tests/test_rekor_backcompat.py`: 5 offline checks of v0.4 contract
  preservation.

### Session C (Rust crate + cross-language conformance + version bump)
- New crate `oversight-rust/oversight-rekor`: bit-identical port of
  `oversight_core.rekor`. 9 inline tests cover PAE byte-exactness,
  sign/verify round trip, tamper + wrong-key rejection, statement shape,
  canonical envelope JSON, and offline TLE inclusion check.
- New conformance suite `oversight-rust/tests/conformance_rekor.sh`: proves
  Python ↔ Rust bit-identity in 4 ways — PAE bytes, Python-signs/Rust-verifies,
  Rust-signs/Python-verifies, canonical payload bytes for the same statement.
- Version bumped to 0.5.0 across `oversight-rust/Cargo.toml`, `README.md`,
  `docs/SPEC.md`.

Hard constraints respected: no new crypto primitives (RustCrypto +
`cryptography`'s Ed25519 only), test count additions-only, Python ↔ Rust
bit-identity proven by conformance script.

## Unreleased — v0.5 Session A (2026-04-19)
- Added `docs/V05_REKOR_PLAN.md`: full Rekor v2 migration plan, verified
  against current upstream API (Rekor v2 GA 2025-10-10, DSSE + hashedrekord
  only, tile-backed reads, no online proof API, public log shard rotates
  ~6 months).
- Added `oversight_core/rekor.py` (~280 LOC): DSSE statement construction,
  PAE-exact signing/verification against the spec, Rekor v2 `/api/v2/log/entries`
  upload helper, offline inclusion-check helper, and `build_bundle()` shaper.
- Added `docs/predicates/registration-v1.md`: the URI the predicate type
  resolves to, with privacy contract and field schema.
- Added `tests/test_rekor_unit.py` with 10 offline unit tests covering DSSE
  PAE, sign/verify, tamper rejection, wrong-key rejection, statement shape,
  canonical envelope JSON, offline bundle verification, the recipient-pubkey
  privacy guarantee, predicate-version int, and 5-year-replay bundle fields.
- Six desktop-review fixes baked into Session A before commit:
  - Recipient X25519 pubkey now SHA-256 hashed before going on-log
    (deanonymization fix).
  - Predicate URI pinned to git-tagged GitHub path, not `oversight.dev`.
  - Bundle gained `bundle_schema: 2` integer + `log_pubkey_pem` +
    `checkpoint` + `log_entry_schema` + optional `rfc3161_chain`.
- Conformance script `oversight-rust/tests/conformance_cross_lang.sh` now
  derives REPO_ROOT from its own location instead of `/home/claude` hardcode.
- `HANDOFF.md` gained explicit "what NOT to accept from a future Claude
  session" section per the v0.4.1 retro.

Test count: 76 → 86 (additions only, baseline conformance still green).

## v0.4.1 — 2026-04-18

Cosmetic polish only, no functionality changes.

### Fixed
- Removed unused `std::path::Path` import from `oversight-policy` — clean
  `cargo build --workspace --release` with zero warnings.
- Rust workspace version bumped to 0.4.1 across all crates via
  `version.workspace = true`.

### No behavioral changes
All 76 tests (31 Python + 42 Rust + 3 conformance) still green.

---

## v0.4.0 — 2026-04-17

**Rust port expands from core to core+enforcement+semantics.** Three new Rust
crates; Python reference unchanged in functionality but with RFC 6962 fix.

### Added

- **`oversight-tlog`** Rust crate (367 LOC). RFC 6962-compliant Merkle tree
  from day one — left-heavy largest-power-of-2 split, not the promote-odd
  shortcut from the Python v0.2 tlog. Signed tree heads, inclusion proofs,
  durable append (fsync), automatic recovery on reopen. 7 tests.
- **`oversight-policy`** Rust crate (284 LOC). TOCTOU-safe `max_opens`
  enforcement via `fs2::FileExt::lock_exclusive` + atomic temp-file rename.
  File-ID sanitization against path traversal. Jurisdiction / not_after /
  not_before checks. 6 tests.
- **`oversight-semantic`** Rust crate (345 LOC + 156-line dictionary file).
  Full port of the 151-class synonym dictionary and L3 watermarking.
  Airgap-strip-survivor verified (tests embed, then strip zero-width and
  trailing whitespace, then verify — still attributes). URL / email / code
  / path / hex / base64 skip regions. 8 tests.
- **Fuzz harness** (`oversight-rust/fuzz/`) — two `cargo-fuzz` targets
  hammering the container parser and manifest parser. Excluded from main
  workspace so normal builds don't need nightly. README with 24-hour
  pre-audit run recommendation.
- **`docs/HARDWARE_KEYS.md`** — vendor-neutral setup guide for YubiKey /
  Nitrokey / OnlyKey. Covers PIN/PUK setup, PIV slot 9d provisioning,
  Oversight identity-file format for hardware-backed recipients, curve
  choice rationale (P-256 for PIV compat vs X25519 file-backed), revocation
  procedure, threat model, deployment checklist.

### Fixed

- **`oversight_core/tlog.py`** now RFC 6962 compliant. Replaced the
  promote-odd-trailing shortcut with the canonical largest-power-of-2
  left-heavy split. Added `_rfc6962_mth`, `_rfc6962_path`,
  `verify_inclusion_proof` helpers. Tested with asymmetric sizes
  (n ∈ {1,2,3,4,5,7,8,16,17,100}) — every leaf's proof verifies;
  tampered proofs rejected. Old custom Merkle logic removed.
- **Mutex self-deadlock** in `oversight-tlog::inclusion_proof` — was
  holding the leaves lock while calling `root()` which also locks.
  Fixed by dropping the lock before invoking `root()`.
- **`oversight-semantic` round-trip bug** — `embed_synonyms` could pick
  hyphenated variants like `"write-up"` that `WORD_RE` tokenizes as two
  separate words, desyncing the verify sequence. Both embed and verify
  now explicitly skip non-round-trippable variants (whitespace or hyphen).

### Changed

- **Workspace version** bumped to `0.4.0`. Python reference remains `v0.3`
  (unchanged feature set, one correctness fix).
- **SealedFile** gained `#[derive(Debug)]` to support test assertions with
  `{:?}` formatting.

### Known limitations (unchanged from v0.3)

- Paraphrasing attack defeats all three watermark levels.
- Airgapped readers leave no network beacon.
- Hardware-backed recipients require v0.5+ `KeyProvider` abstraction (not
  yet implemented — currently file-backed only).
- Format adapters (image DCT, PDF, DOCX) remain Python-only until v0.6.
- Registry server (FastAPI) remains Python-only until v1.0.

## v0.3.0 — 2026-04-17

See earlier commits. Initial Rust core + FreeTSA RFC 3161 + cross-language
conformance + SENTINEL→Oversight rename + Nitro→YubiKey pivot.

## v0.2.1 and earlier

Python-only; see git history.
