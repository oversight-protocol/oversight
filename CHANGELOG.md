# Oversight CHANGELOG

## Unreleased

- `oversight-rust/oversight-registry`: added the missing registry v1
  read-only and beacon surface (`/.well-known/oversight-registry`,
  `/evidence/{file_id}`, `/tlog/head|proof|range`, `/p/{token_id}.png`,
  `/r/{token_id}`, `/v/{token_id}`, `/candidates/semantic`) and tightened
  CORS to the public browser-inspector origins with GET/OPTIONS only. The
  Axum server now passes the existing 33-check
  `tests/test_registry_conformance.py` harness in live-URL mode.
- `oversight-rust/oversight-manifest`: added `canonical_content_hash` and
  `l3_policy` to the signed manifest model so Rust verifies Python-signed
  v0.4.5+ manifests without dropping signed fields before canonicalization,
  while retaining a fallback verification path for older manifests that lack
  those default fields.

## v0.4.8 - 2026-04-29 Mobile-build portability and rustls-webpki security bump

Patch release covering two upstream-driven fixes that landed on `main`
since v0.4.7. No new features and no breaking changes.

- `oversight-rust/oversight-container`: gate the 4 GiB
  `MAX_CIPHERTEXT_BYTES` literal to 64-bit targets and fall back to
  `usize::MAX` on 32-bit. Required to cross-compile the Rust core for
  Android `armv7-linux-androideabi` and `i686-linux-android`, which the
  mobile companion (`oversight-protocol/oversight-mobile`, Flutter +
  Rust via `flutter_rust_bridge`) embeds unchanged. Behavior is preserved
  for any realistic bundle on 32-bit; `usize::MAX` is just under 4 GiB
  on those targets. (PR #4, merged 2026-04-26.)
- `oversight-rust` Cargo.lock: bumped `rustls-webpki` from 0.103.12 to
  0.103.13. Patches a reachable panic in CRL parsing
  (GHSA-82j2-j2ch-gfr8) and an inverted-meaning URI excluded-subtree
  check (rustls/webpki#471). In scope because the Rust registry and
  Rekor clients use rustls for TLS. (Dependabot PR #3, merged 2026-04-29.)

## v0.4.7 - 2026-04-22 Registry federation hardening and conformance harness

Federation stops being aspirational when a second operator can prove
compatibility. v0.4.7 hardens the registry v1 interop spec against the
reference implementation and ships a conformance harness that any
operator can point at their deployment.

- `docs/spec/registry-v1.md`: expanded with the canonicalization algorithm
  (`json.dumps(sort_keys=True, separators=(",", ":"))` over UTF-8), the
  uniform error envelope and `code` vocabulary, a full endpoint table
  including the normative beacon paths (`/p/{token_id}.png`, `/r/{token_id}`,
  `/v/{token_id}`), the `/.well-known/oversight-registry` shape, the
  `/evidence/{file_id}` bundle fields, and the `/tlog/head|proof|range`
  endpoints federated verifiers rely on. Removed a phantom
  `/query/{file_id}` endpoint that was in the draft but never shipped.
- `tests/test_registry_conformance.py`: 32-check harness with two modes.
  In-process against a FastAPI `TestClient` for CI, or against a live URL
  when `OVERSIGHT_REGISTRY_URL` is set. Covers identity, liveness, a full
  signed-manifest registration round trip, attribution by token id,
  evidence bundle shape, transparency-log head, every beacon endpoint,
  and DNS event authentication.
- `docs/ROADMAP.md`: the registry federation item references the harness
  as the acceptance gate for federation.
- Version bumped to `0.4.7`. No breaking changes.

## v0.4.6 - 2026-04-22 SIEM export: Splunk, Sentinel, and Elastic

Registry beacon events can now be emitted in three SIEM-native formats so
security teams get Oversight data into the incident pipeline they already
run. Formatters are pure; transport is a thin sink layer.

- `oversight_core/siem.py`: new module. Normalized `OversightEvent` model
  built from the registry `events` table, pure formatters for Splunk HEC,
  Elastic Common Schema 8.x, and Microsoft Sentinel (Log Analytics custom
  logs), plus `sentinel_authorization()` helper that signs the Data
  Collector API `Authorization` header per Microsoft's recipe.
- `cli/oversight.py`: new `oversight siem export` subcommand. Streams
  events as JSON lines to stdout, a file, or an HTTPS collector. Supports
  `--since`, `--limit`, repeatable `--header`, and Splunk source/sourcetype/
  index overrides. Opens the registry database read-only so it is safe
  to run against a live service.
- `docs/SIEM.md`: operator integration guide covering each of the three
  SIEMs, the event field dictionary, the Sentinel HMAC signing window,
  and the honest beacon-absence caveat. Also surfaced from the website
  docs index.
- `tests/test_siem_unit.py`: 11 focused unit tests covering envelope
  shape per format, empty-field suppression, SQLite row mapping,
  read-only iteration, Sentinel HMAC stability, and action-name
  coverage for every beacon kind.
- `oversight_core/__init__.py` and `pyproject.toml`: version bumped to
  `0.4.6`. No breaking changes; SIEM is additive.

## v0.4.5 - 2026-04-20 L3 safety, GUI, and registry federation docs

Review-driven hardening from `P:/Oversight/oversight-protocol-review.md`.

- `oversight_core/l3_policy.py`: new L3 safety policy engine. L3 defaults off
  for legal, regulatory, technical/spec, source-code, SQL, log, and structured
  data classes; explicit `full`, `boilerplate`, and `off` modes are supported.
- `cli/oversight.py` and `cli/oversight_rich.py`: seal-time L3 disclosure now
  requires acknowledgement when L3 is enabled, and seal manifests record the
  applied L3 policy.
- `oversight_core/manifest.py`: manifests now carry `canonical_content_hash`
  so auditors can diff recipient copies against the original source bytes.
- `oversight_core/watermark.py` and `oversight_core/formats/text.py`: high-level
  L3 application is opt-in; L1/L2 remain available by default.
- `cli/gui.py`: added a Tkinter desktop GUI for key generation, sealing, and
  opening files (`oversight gui`) so non-technical users have a starter path.
- GUI and CLI output writes now fail closed against private-key overwrites,
  same-path writes, reserved Windows device names, malformed key files, and
  non-UTF-8 watermark attempts. Private-key writes use atomic replacement and
  restrictive permissions/ACL hardening where supported.
- `.sealed` parsing now rejects tampered suite IDs, malformed manifest/wrapped-DEK
  JSON, unknown manifest fields, and trailing bytes after ciphertext.
- `oversight-rust/oversight-container`: Rust now mirrors the Python parser's
  strictness by rejecting suite-byte tamper and trailing bytes after the
  authenticated ciphertext region.
- `docs/security.md`: documented L3 collusion/canonicalization limits, layer
  survival properties, passive beacon limits, jurisdiction-by-IP limits, and
  RFC 3161 timestamp semantics.
- `docs/spec/registry-v1.md`: added a registry federation/interoperability
  draft for independent compatible registry operators.
- `docs/ROADMAP.md`: corrected launch sequencing, dropped near-term FedRAMP,
  scoped ecosystem plugins to Outlook-first, and prioritized SIEM integration
  before SOC 2 / ISO 27001 work.
- Raised vulnerable dependency floors flagged by Dependabot/PyPI advisory
  checks: setuptools, cryptography, PyNaCl, pydantic, python-multipart,
  Pillow, and pypdf now require patched minimums; Rust manifest floors
  now pin patched minima for sqlx, tokio, rand_core, zip, chrono, regex,
  once_cell, and tracing-subscriber.
- Added focused regression coverage in `tests/test_l3_policy_unit.py`.

## v0.4.4 - 2026-04-20 security hardening

Security patch line started from the `v0.4.3` Python package baseline
(`0b1a4ab`) and incorporates the Codex review fixes made on 2026-04-20.
This is the current `main` download line. Historical `v0.5.0` Rekor/Rust
work remains in git history and the Rust workspace, but the Python package
metadata now intentionally advances from `0.4.3` to `0.4.4` so users do not
confuse the hardened tree with the vulnerable `v0.4.3` baseline.

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
- `oversight_core/__init__.py`, `pyproject.toml`, and the Rich CLI banner:
  version metadata is now `0.4.4`, marking this post-`0.4.3` hardening train.
- `oversight_dns/server.py` and `registry/server.py`: DNS beacon callbacks now
  support a shared `OVERSIGHT_DNS_EVENT_SECRET`, and non-loopback callbacks
  fail closed when no secret is configured.
- `registry/server.py`: evidence bundles now include local transparency-log
  inclusion proofs for recorded events, not just the signed tree head.
- `oversight-rust`: removed the direct `rand` dependency in favor of
  `rand_core::OsRng`, clearing the low-severity `rand` advisory path.
- `oversight-rust/oversight-registry`: `/dns_event` now requires
  `OVERSIGHT_DNS_EVENT_SECRET` for non-loopback callbacks, signed
  beacon/watermark artifacts fail registration when malformed instead of being
  silently dropped, and Rekor attestation skips watermarkless registrations
  rather than logging `mark:<file_id>`.
- `oversight-rust/oversight-container` and `oversight-rust/oversight-policy`:
  Rust opens can now enforce `max_opens` after successful recipient decrypt,
  `REGISTRY` / `HYBRID` modes fail closed instead of falling back to local
  counters, and Rust `seal_multi()` fails closed until recipient-honest
  manifests exist.
- `oversight-rust/oversight-rekor`: offline verification now mirrors Python by
  rejecting DSSE envelopes whose subject digest does not match the expected
  content hash.
- `oversight-rust/oversight-formats`: DOCX metadata insertion no longer reports
  success when `<cp:keywords>` is missing, and PDF processing rejects indirect
  Launch / JavaScript / unsafe URI actions before rewriting files.
- Added focused regression coverage in `tests/test_policy_unit.py`,
  `tests/test_registry_unit.py`, `tests/test_rekor_unit.py`,
  `tests/test_text_format_unit.py`, and `tests/test_tlog_unit.py`.

Patch sequence on top of `v0.4.3`:

1. `0.4.3` / `0b1a4ab`: Rich CLI, anti-stripping defenses, and L3
   integration baseline.
2. `0.4.4` / `dab6157`: policy and Rekor verification hardening.
3. `0.4.4` / `4d60e3b`: registry Rekor mark indexing fix.
4. `0.4.4` / `20a566b`: multi-recipient sealing fails closed until the
   manifest can represent multiple recipients honestly.
5. `0.4.4` / `482f294`: default beacon/registry domain updated from
   `oversight.example` to `oversightprotocol.dev`.
6. `0.4.4` / `7712f98`: signed registry sidecars enforced and RFC 6962
   empty tlog roots fixed.
7. `0.4.4` / `0a7a2da`: package, core, and CLI version metadata
   aligned to the hardened `0.4.4` line.
8. `0.4.4` / `69e50aa`: public changelog patch chronology documented.
9. `0.4.4` / `26db8d3`: DNS evidence hardening, Rust RNG dependency
   cleanup, and evidence-bundle inclusion proofs.
10. `0.5.0+` / `b9bee41`: Claude-added Rust format adapters, Axum registry,
    and USENIX benchmark scaffolding.
11. `0.5.0+` / current hardening commit: Codex audit fixes for the new Rust
    registry/container/policy/Rekor/format-adapter security regressions.

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
