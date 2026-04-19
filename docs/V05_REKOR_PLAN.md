# v0.5 — Sigstore Rekor v2 Migration Plan

Drafted 2026-04-19. Approved scope: public Rekor v2 only (no self-host).
USENIX Cycle 2 strategy: v0.4.1 frozen as paper artifact safety net;
v0.5 lands as a stretch goal if evaluation work comes together first.

---

## 0. Source-of-truth facts (verified 2026-04-19 via web)

- **Rekor v2 GA: 2025-10-10.** Tile-backed log following C2SP `tlog-tiles`.
- **Entry types:** ONLY `hashedrekord` (artifact) and `dsse` (attestation).
  intoto, rekord, helm, tuf, rfc3161, jar, rpm, cose, alpine are removed.
  Custom types are **not** accepted — "additional types may be added if there is
  demand, but this requires updating the client specification."
- **Write API:** single endpoint `POST /api/v2/log/entries` (HTTP + gRPC).
  Returns `TransparencyLogEntry` (protobuf) which clients persist in bundles.
  Minimum client write timeout: 20s.
- **Reads:** no online proof API. Clients fetch tiles per the tlog-tiles spec
  and compute inclusion proofs locally. Inclusion proofs are bundled into the
  `TransparencyLogEntry` returned at write time.
- **Signed timestamps removed from Rekor** — clients fetch from a separate TSA.
  (Oversight already uses FreeTSA RFC 3161; no change needed.)
- **Search indexing removed** — Rekor will not answer "what entries did issuer X
  register?". A separate verifiable-index service is planned. Oversight registry
  must keep its own local index (it does: `registry/server.py` SQLite).
- **Public log URL pattern:** `https://logYEAR-N.rekor.sigstore.dev/api/v2/`,
  rotated about every 6 months. Current: `log2025-1`. **Do NOT hardcode.**
  Discover via Sigstore TUF trusted root.
- **Client coverage:** Python, Go, Java GA. JS + Ruby pending.

## 1. Goals (in order)

1. Replace `oversight_core/tlog.py` calls in the issuer's registration path with
   a Rekor v2 DSSE upload, while keeping the local tlog as a verifier fallback
   for v0.4-era `.sealed` files.
2. Embed the returned `TransparencyLogEntry` in the Oversight evidence bundle.
3. Add a `verify_rekor_inclusion()` helper auditors can run with no Oversight
   code at all — only the standard `sigstore-python` library.
4. Maintain bit-identical Python ↔ Rust output. New conformance test:
   `seal-then-register` round trip across both languages must produce the same
   DSSE envelope bytes (signatures aside, since they're nondeterministic).

## 2. Non-goals for v0.5

- No self-hosted Rekor on CT 222. Recorded as out-of-scope (revisit point 3).
- No removal of legacy `oversight_core/tlog.py`. It stays as fallback verifier.
- No Hardware KeyProvider work — that's v0.6 alongside format adapters.
- No new entry-type negotiation with Sigstore. We use vanilla DSSE.

## 3. Entry-type design: DSSE, not hashedrekord

`hashedrekord` proves "key K signed digest D." We need more: "issuer K asserts
that mark_id M maps to file_id F with content_hash H, recipient R, suite S,
registered at time T, with optional policy bounds." That's an attestation, not
a signature primitive. Use **DSSE** with a custom predicate type.

**Predicate type:** `https://oversight.dev/registration/v1`

**Statement payload (canonical JSON, JCS):**

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{
    "name": "mark:<mark_id>",
    "digest": {"sha256": "<content_hash_hex>"}
  }],
  "predicateType": "https://oversight.dev/registration/v1",
  "predicate": {
    "file_id": "<uuid>",
    "issuer_pubkey_ed25519": "<base64>",
    "recipient_id": "<string>",
    "recipient_pubkey_x25519": "<base64>",
    "suite": "OSGT-CLASSIC-v1 | OSGT-PQ-HYBRID-v1 | OSGT-HW-P256-v1",
    "policy": { "not_after": "<iso>?", "max_opens": <int>?, "jurisdiction": [...]? },
    "watermarks": { "L1": true, "L2": true, "L3": true },
    "registered_at": "<iso>",
    "rfc3161_tsa": "<TSA URL used>",
    "rfc3161_token_b64": "<base64 of TimeStampToken>"
  }
}
```

DSSE envelope: signed by the issuer's Ed25519 key (the same key already in the
manifest). Sigstore Fulcio/OIDC is **not** required for v0.5; we use
"self-managed key" mode of the Rekor v2 write API.

## 4. Bundle format change

Today (`v0.4`):
```json
{ "manifest": {...}, "manifest_sig": "...", "tlog_proof": {...}, "rfc3161_token": "..." }
```

After v0.5:
```json
{
  "manifest": {...},
  "manifest_sig": "...",
  "tlog_kind": "rekor-v2-dsse",
  "rekor": {
    "log_url": "https://log2025-1.rekor.sigstore.dev/api/v2/",
    "log_entry_b64": "<protobuf TransparencyLogEntry>",
    "dsse_envelope_b64": "<DSSE we uploaded>"
  },
  "rfc3161_token": "..."
}
```

For v0.4 backward compat, the verifier reads `tlog_kind`. Default
(omitted/`oversight-self-merkle-v1`) → use `oversight_core/tlog.py`.
`rekor-v2-dsse` → use Rekor verifier.

## 5. Code surface

### New files
- `oversight_core/rekor.py` (~250 LOC)
  - `build_oversight_dsse(manifest, ed25519_priv) -> dsse_envelope_bytes`
  - `upload_to_rekor(envelope, log_url) -> TransparencyLogEntry`
  - `verify_rekor_inclusion(entry, dsse_envelope, issuer_pubkey) -> bool`
  - Pure-stdlib HTTP client; no `sigstore-python` runtime dep (we use it only in
    the auditor helper, which lives in a separate file).
- `oversight_core/auditor_helper.py` (~80 LOC)
  - Thin wrapper over `sigstore-python` so an external auditor can verify a
    bundle with one import.
- `oversight-rust/oversight-rekor/` (new crate, ~400 LOC)
  - Mirrors Python rekor.py exactly; uses `sigstore` crate for verify only.
  - Async (tokio) for upload; sync verify path for use from CLI.

### Modified files
- `oversight_core/manifest.py`: add optional `tlog_kind` field (default-omit
  for back-compat).
- `registry/server.py`: replace inline tlog append with `rekor.upload_to_rekor`.
  Keep the SQLite event index — that is now the only way to answer "list marks
  for issuer X" queries.
- `oversight_core/tlog.py`: mark module-docstring as "fallback verifier for
  pre-v0.5 bundles only." No new writes against it.
- `oversight-rust/oversight-cli/`: `inspect` learns to print Rekor entry info.

### New tests (must add at least 3 to keep "additions only" promise)
- `tests/test_rekor_e2e.py` — register a mark, upload to Rekor, fetch back,
  verify locally without Oversight code (uses `sigstore-python` only).
- `tests/test_rekor_backcompat.py` — open a v0.4-era `.sealed` file and
  confirm verifier falls back to local tlog.
- `oversight-rust/tests/conformance_rekor.sh` — Python uploads, Rust
  downloads-and-verifies. Skip when offline; mark as "online conformance."

Target test count after v0.5: **79+** (76 existing + 3 new minimum).

## 6. Backward compatibility rules (do not break)

1. Every existing v0.4.1 `.sealed` file must still parse, open, and verify
   exactly as it does today. The cross-language conformance script must keep
   passing without modification on those files.
2. Bundle format must accept missing `tlog_kind` and behave as
   `oversight-self-merkle-v1` (the v0.4 path).
3. Python and Rust must agree on every new field's canonical JSON ordering
   (JCS already enforces this; just make sure the new fields are added to both
   sides in the same commit).

## 7. Risks / gotchas

- **Log shard rotation.** `log2025-1` will freeze and `log2026-1` (or similar)
  will replace it. Bundles registered against a frozen shard are still
  verifiable — the shard URL stays read-only. We must record the URL we used
  in the bundle and never assume "current" log.
- **No online inclusion proof API.** Old habit dies hard: there is no
  `GET /api/v2/log/entries/{uuid}/proof`. The proof is bundled at write time.
  If a verifier is missing one, they have to compute from tiles.
- **20s write timeout minimum.** Set urllib3/reqwest accordingly. Don't fail
  fast on registration.
- **Rekor v2 won't accept custom predicate types via metadata** — the predicate
  type lives inside the DSSE statement payload, which Rekor doesn't inspect.
  This is fine; we just need to be unambiguous in our own predicate URI so
  third parties don't collide.
- **No Oversight code on the auditor's side.** This is a feature, not a risk.
  The whole point of migrating is that any Sigstore-compatible client can
  audit Oversight bundles. Don't compromise this by leaking proprietary
  helpers into the verify path.

## 8. Sequencing (3 sessions)

**Session A (this one or next):**
- Approve plan with Zion (this document).
- Add `tlog_kind` field, keep default behavior unchanged. Land + tests.
- Build `oversight_core/rekor.py` skeleton with the DSSE construction,
  unit-tested against a fixture envelope (no network).

**Session B:**
- Wire `registry/server.py` to call Rekor for new registrations.
- `tests/test_rekor_e2e.py` against `log2025-1.rekor.sigstore.dev`.
- Backward compat test against v0.4-era fixtures.

**Session C:**
- Rust `oversight-rekor` crate.
- Cross-language Rekor conformance.
- Update `docs/SPEC.md`, bump version to 0.5.0, ship.

## 8b. Desktop review fixes applied 2026-04-19

Independent review by desktop session caught six issues; all addressed before
Session A landed:

1. **DSSE choice confirmed** — hashedrekord cannot carry structured
   attestations; Rekor v2 forces this choice.
2. **Predicate URI pinned** to git-tagged GitHub path
   `https://github.com/oversight-protocol/oversight/blob/v0.5.0/docs/predicates/registration-v1.md`
   instead of `oversight.dev` (which Zion may not own / could be squatted).
   Predicate body now also carries `predicate_version: 1` for cheap
   version gating without URI parsing.
3. **Bundle gained four 5-year-replay fields:**
   `rekor.log_pubkey_pem` (raw key at write time, lets verifiers skip TUF),
   `rekor.checkpoint` (signed tree-head promoted out of the protobuf so a
   strip-happy serializer can't drop it),
   `rekor.log_entry_schema = "rekor/v1.TransparencyLogEntry"` (schema URI for
   the opaque base64 blob), and the optional
   `rfc3161_chain` (full TSA cert chain so 2031 verifiers can validate the
   token after the TSA cert has expired).
4. **`bundle_schema: 2` integer** added so pre-v0.5 verifiers fail fast with
   "unknown schema, upgrade" instead of mis-routing on `tlog_kind`.
5. **`sigstore-python>=4.1,<5` pin** for the auditor helper. Rekor v2 support
   is stable since v4.0.0 (2025-09-19). No beta risk.
6. **Privacy fix (critical):** the on-log predicate now carries
   `recipient_pubkey_sha256` instead of the raw X25519 public key. Otherwise
   anyone could enumerate recipients by pubkey or correlate marks across
   issuers. The raw key stays in the local `.sealed` bundle. New unit test
   `t8_recipient_pubkey_never_appears_raw` enforces this.

## 9. Open questions to surface to Zion before Session B

1. Predicate URI: `https://oversight.dev/registration/v1` — does he own
   oversight.dev? If not, use `https://github.com/oversight-protocol/spec/registration/v1`
   so the URI resolves to public spec docs.
2. Auditor helper: ship inside `oversight_core/` or as a separate
   `oversight-auditor` PyPI package so non-issuers can `pip install` it
   without pulling Oversight's full crypto stack?
3. Should v0.5 also write a tiny `verify-bundle` standalone Rust binary
   (~200 LOC, depends only on the `sigstore` crate) for distribution to
   journalists / lawyers / non-technical leak responders?
