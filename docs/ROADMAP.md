# Oversight Roadmap

Last revised 2026-04-22. The launch plan is gated on product usability and
threat-model honesty, not on a calendar date.

## Where we are

1. **L3 safety fixes and collusion documentation** shipped in v0.4.5. L3
   defaults off for wording-sensitive document classes, requires explicit
   disclosure when enabled, records `canonical_content_hash`, and supports a
   boilerplate-only mode for contracts and filings.
2. **SIEM integration ahead of SOC 2** shipped in v0.4.6. `oversight_core.siem`
   and the `oversight siem export` CLI emit beacon events as Splunk HEC,
   Elastic Common Schema 8.x, or Microsoft Sentinel Log Analytics records.
   Operator guide at `docs/SIEM.md`.
3. **Registry federation hardening** shipped in v0.4.7. The v1 interop spec
   at `docs/spec/registry-v1.md` is aligned against the reference server:
   canonical-JSON algorithm, uniform error envelope, normative endpoint and
   beacon paths, `/evidence` bundle shape, and `/tlog/head|proof|range` are
   pinned. `tests/test_registry_conformance.py` runs 33 checks in-process
   or against a live URL. An operator claims v1 compatibility with
   `OVERSIGHT_REGISTRY_URL=https://registry.example.org python3 tests/test_registry_conformance.py`.
4. **Browser inspector and classic-suite decrypt** shipped on
   `oversight-protocol.github.io/oversight/viewer/`. Drag-drop `.sealed`
   parsing, WebCrypto Ed25519 signature verification, canonical JSON
   byte-identical to Python, optional registry lookups, and full
   decryption of classic-suite sealed files using WebCrypto X25519 + HKDF-SHA256
   with a vendored `@noble/ciphers` XChaCha20-Poly1305. Post-decrypt
   SHA-256 matches `content_hash` or the flow aborts. Hybrid
   (post-quantum) in-browser decrypt **shipped 2026-05-03** using a
   vendored ML-KEM-768 from `@noble/post-quantum` for the post-quantum
   half of the KEM, with X-wing-style HKDF binding over both shared
   secrets. The viewer now decrypts both `OSGT-CLASSIC-v1` and
   `OSGT-HYBRID-v1` sealed files.
5. **Outlook add-in first** for the first ecosystem integration. Drive,
   Box, SharePoint, and Teams plugins are deferred until a maintainer or
   design partner funds them.
6. **SOC 2 Type 1 scoping** becomes realistic after a design-partner
   engagement. ISO 27001 follows SOC 2. FedRAMP is dropped from near-term
   planning; it is a multi-year commercial program requiring sponsor-agency
   backing.

## Public launch sequence

1. L3 safety and collusion documentation. **Shipped in v0.4.5.**
2. Browser inspector and drag-drop share workflow. **Shipped** -
   inspector, classic-suite decrypt, and hybrid (post-quantum) decrypt
   are all live.
3. Outlook add-in. **Scaffold landed 2026-05-07** (`integrations/outlook/`,
   `docs/OUTLOOK.md`); pilot in an Outlook tenant pending.
4. One regulated-industry design-partner deployment.
5. SOC 2 Type 1 scoping in parallel with the design partner.
6. Broad public launch (HN, Reddit, conferences). Not before the inspector,
   the Outlook add-in, and a real deployment are all in hand.

---

## Shipped

### RFC 3161 qualified timestamps — v0.3

`oversight_core/timestamp.py` and `registry/server.py` perform real RFC 3161
requests. The default TSA chain tries FreeTSA first, falls back to DigiCert,
and falls back to the registry's own clock if both are unreachable. Verified
live: 4667-byte signed TimeStampToken, valid P-384 signature, correct
gen_time, correct nonce. FreeTSA is free and research-grade; GlobalSign or
GLOBALTRUST drop in for deployments that require eIDAS-qualified status.

### Rust canonical port of the hot path — v0.4

The seal, open, manifest, policy, semantic, tlog, and rekor path is
implemented as a Rust workspace under `oversight-rust/`. `cargo build
--workspace --release` passes with zero warnings. Python is the reference
implementation; Rust is canonical for production deployments. A conformance
suite proves bit-identical output for every manifest and envelope.

### Fail-closed security hardening — v0.4.4

Codex review pass across the policy engine, Rekor verification, registry
input validation, and the container format. Nine findings, nine fixes.
Failed decryption no longer consumes open counts. REGISTRY and HYBRID
policy modes fail closed instead of silent local fallback. DNS event
callbacks from non-loopback clients must carry `OVERSIGHT_DNS_EVENT_SECRET`.
Multi-recipient sealing disabled until the manifest format can honestly
bind every recipient.

### L3 safety and GUI starter — v0.4.5

`oversight_core/l3_policy.py` gates L3 on document class: legal,
regulatory, technical specifications, source code, SQL, logs, and
structured data default to off. Explicit `full`, `boilerplate`, and `off`
modes are supported. The CLI refuses to seal with L3 enabled unless the
caller acknowledges that the recipient copy is textually non-identical to
the canonical source. The manifest records `canonical_content_hash` and
`l3_policy` so disputes can reach ground truth. `oversight gui` launches
a Tkinter desktop starter covering keygen, seal, and open.

### Sigstore Rekor v2 transparency log — v0.5

Seal registrations are attested to the public Sigstore Rekor v2 log as
DSSE envelopes. The predicate type resolves to a git-tagged GitHub path
so third-party verifiers can resolve the schema without a live
`oversight.dev` endpoint. Recipient X25519 public keys are SHA-256 hashed
before going on-log. Opt-in by default via `OVERSIGHT_REKOR_ENABLED=1`;
failures are non-fatal and the local SQLite tlog stays authoritative.
Offline bundles carry the log public key, checkpoint, entry schema, and
optional RFC 3161 chain. Self-hosted Rekor v2 is supported via
`OVERSIGHT_REKOR_URL`.

### SIEM export — v0.4.6

`oversight_core/siem.py` ships a normalized `OversightEvent` model that
maps the registry `events` table onto three schema-stable formatters:
Splunk HEC envelopes, Elastic Common Schema 8.x documents, and Microsoft
Sentinel Log Analytics custom-log rows. `sentinel_authorization()`
implements the Data Collector API HMAC signing recipe. `FileSink`,
`StdoutSink`, and `HTTPJSONSink` cover the transport surface without
pulling SIEM credentials into the Oversight process by default.

The `oversight siem export` CLI streams events as JSON lines to stdout,
a file, or a generic HTTPS collector. Supports `--since`, `--limit`,
repeatable `--header`, and Splunk source/sourcetype/index overrides.
Opens the registry database read-only so it is safe to run against a
live service. Full operator guide at `docs/SIEM.md`. 11 unit tests cover
envelope shape, None-field suppression, SQLite row mapping, read-only
iteration, Sentinel HMAC determinism, and action-name coverage.

### Registry federation hardening — v0.4.7

`docs/spec/registry-v1.md` rewrites the interop contract against what
the reference server actually serves. The spec now pins:

- Canonicalization algorithm: sort keys, compact separators, UTF-8,
  matching `json.dumps(manifest, sort_keys=True, separators=(",", ":"))`
- Uniform error envelope with a defined `code` vocabulary
- Full endpoint table including normative beacon paths
  (`/p/{token_id}.png`, `/r/{token_id}`, `/v/{token_id}`)
- `/.well-known/oversight-registry` identity shape
- `/evidence/{file_id}` bundle fields
- `/tlog/head|proof|range` for federated verifiers

`tests/test_registry_conformance.py` is a 33-check harness with two
modes. In-process against a FastAPI TestClient for CI, or against a
live URL when `OVERSIGHT_REGISTRY_URL` is set. An independent operator
who passes the harness claims v1 compatibility.

CORS middleware on the live registry lets the browser inspector read
`/health`, `/.well-known/oversight-registry`, and `/evidence/{file_id}`
from the public site origin. Methods are restricted to GET and OPTIONS;
registration, DNS events, and attribution stay browser-unreachable.

### Browser inspector and classic-suite decrypt — post-v0.4.7

`site/viewer/` is a static page that parses the `.sealed` container
in the browser, verifies the issuer Ed25519 signature via WebCrypto,
and renders the manifest, watermarks, beacons, and policy. Canonical
JSON in JS is byte-identical to the Python reference, validated
against a Python-generated test vector.

Classic-suite decryption runs locally. WebCrypto performs X25519 ECDH
via JWK import and derives the key-encryption key with HKDF-SHA256;
a vendored pinned copy of `@noble/ciphers` (sha256 `b31ecc4f`) provides
the XChaCha20-Poly1305 primitive that WebCrypto does not expose. After
decrypt, the plaintext SHA-256 is compared against `manifest.content_hash`
and a mismatch aborts. Wrong private key, mismatched recipient, tampered
ciphertext, and hybrid-suite inputs all fail with explicit messages.

A tutorial `.sealed` and its recipient `identity.json` are published
under `viewer/samples/` with an in-file note that the keypair is a
public demo key.

### Operational hygiene — ongoing

History rewrite removed every occurrence of RFC 1918 addresses,
internal workspace paths, and container identifiers that had leaked
into early commits. Two internal-only files (`SESSION_RESUME.md` and
`docs/RUNBOOK.md`) were removed from every commit and every tag.

`scripts/opsec-scan.sh` scans either the whole tree or the staged
diff for the same patterns plus GitHub PATs, OpenAI and Slack tokens,
and raw private-key PEMs. `.github/workflows/opsec.yml` runs the
scanner on every pull request and push to main. `scripts/githooks/pre-commit`
is the optional local hook. `.gitignore` blocks session, handoff,
runbook, `private/`, `secrets/`, and `*.local.md` filename patterns
so notes of that flavor cannot be accidentally committed in the first
place.

---

## Next

### Outlook add-in

**Scaffold landed 2026-05-07.** `integrations/outlook/` ships the Office
add-in 1.1 manifest (`MailApp`, read-mode task pane, `ReadItem` only),
the task-pane HTML, and JS that imports the public viewer's parse /
verify / decrypt directly from `oversightprotocol.dev/viewer/`. No
second crypto stack. Both classic and hybrid suites decrypt. Decision
record at `docs/OUTLOOK.md`.

Remaining for a real pilot: 64 px / 128 px icons in
`integrations/outlook/assets/`, an Outlook tenant load-test, and the
manifest hosting deploy under `oversightprotocol.dev/integrations/outlook/`.
Sealing-from-Outlook (compose mode) is intentionally deferred to v2.

### Hardware `KeyProvider` in Rust

`docs/HARDWARE_KEYS.md` already documents the vendor-neutral setup
covering YubiKey 5C, OnlyKey, and Nitrokey 3. **Trait + `FileKeyProvider`
landed 2026-05-07** in `oversight-crypto`: `KeyProvider` abstracts the
recipient-side ECDH so a hardware backend can plug in without changing
call sites; `unwrap_dek_with_provider` is the new entry point and is
byte-identical to `unwrap_dek` for file-backed keys.

The remaining work is the `PivKeyProvider` (PKCS#11 against a YubiKey /
Nitrokey / OnlyKey PIV slot) and the `OSGT-HW-P256-v1` suite that goes
with it: P-256 ECDH wire format on the wrap side, manifest suite-id
plumbing, and the open-side decrypt path that branches on suite. The
registry records whether each recipient pubkey is file-backed or
hardware-backed so issuers can require hardware backing for sensitive
material.

### Registry in Rust

`oversight-rust/oversight-registry` is scaffolded with all endpoints
implemented under `#![forbid(unsafe_code)]`. As of 2026-05-03, the Axum
server passes the existing 33-check `tests/test_registry_conformance.py`
harness in live-URL mode against the registry v1 surface. Remaining work:
migration tooling from the Python registry, longer-running deployment tests,
and a wire-format stability declaration before declaring v1.0 ready.

---

## Mid-term

### Spec publication

- **GitHub** — live at `github.com/oversight-protocol/oversight` under
  Apache 2.0 with test vectors.
- **arXiv preprint** (~15 pages, `cs.CR`): motivation, threat model,
  protocol, cryptographic construction, security arguments, implementation,
  evaluation, limitations, related work.
- **IETF Internet-Draft** as `draft-oversight-00`. Submit to
  datatracker, present at an informal BoF of SUIT, OHAI, LAKE, or CFRG
  depending on framing. Iterate 6 to 12 months before an RFC stage.
  Multiple independent implementations are required before RFC.

### Conference targets

- USENIX Security Cycle 2 (June 2026).
- Black Hat Europe 2026 (December 2026).
- ACSAC 2026.
- Black Hat USA 2027.

Demonstration material: live seal and open in Python and Rust, live leak
simulation with real-time attribution, hybrid PQ sizing, air-gap strip
via VM and retype, hardware-key pull mid-open.

---

## 2027

- Independent security audit. Trail of Bits, NCC Group, Cure53, and
  Zellic are the plausible candidates. Typical engagement: 4 to 8
  engineer-weeks, $75K to $200K, 60-day disclosure window. Prerequisites:
  spec freeze, threat model document, fuzz campaign, internal review
  pass.
- v1.0 release, spec freeze, RFC shepherding.
- Black Hat USA 2027 Briefings.
- ISO 27001 after SOC 2 Type 2.

---

## Explicitly dropped or deferred

- **FedRAMP.** Multi-year, seven-figure, requires commercial entity and
  sponsor agency. Revisit only if a commercial pivot occurs.
- **Cloud-TEE key custody.** Ties Oversight to a single cloud vendor
  and contradicts the open-source goal. Hardware keys replace it.
- **Drive, Box, SharePoint, Teams plugins.** Deferred until a maintainer
  or design partner funds them.
- **Broad HN and Reddit launch.** Gated on Outlook add-in plus one
  design-partner deployment.

---

## Phased status

| Phase | Items | Status |
|---|---|---|
| 0 | GitHub org, Apache 2.0, SECURITY.md | Shipped |
| 1 | FreeTSA + DigiCert RFC 3161 chain | Shipped (v0.3) |
| 2 | Rust canonical port, conformance suite | Shipped (v0.4) |
| 3 | Fail-closed security hardening | Shipped (v0.4.4) |
| 4 | L3 safety, GUI starter, canonical_content_hash | Shipped (v0.4.5) |
| 5 | Rekor v2 integration, cross-language parity | Shipped (v0.5) |
| 6 | SIEM export: Splunk, Sentinel, ECS | Shipped (v0.4.6) |
| 7 | Registry v1 spec + conformance harness + CORS | Shipped (v0.4.7) |
| 8 | Browser inspector, classic-suite decrypt, opsec scanner + CI | Shipped |
| 9 | Hybrid PQ decrypt in browser | Shipped (2026-05-03) |
| 10 | Outlook add-in | Next |
| 11 | Hardware KeyProvider in Rust | In progress |
| 12 | Rust Axum registry, migration tooling | In progress |
| 13 | arXiv preprint, threat-model repo document | Mid-term |
| 14 | IETF Internet-Draft, CFRG or equivalent BoF | Mid-term |
| 15 | USENIX Security Cycle 2, Black Hat EU 2026 | Mid-term |
| 16 | Independent security audit | 2027 |
| 17 | v1.0 release, RFC shepherding, Black Hat USA 2027 | 2027 |

## Cost outlook

| Item | Cost |
|---|---|
| FreeTSA, DigiCert, Sigstore Rekor, GitHub Actions | $0 |
| Hardware keys for development and testing | ~$100 |
| Domain, DNS, public beacon hosting (annual) | ~$60 |
| Conference registration and travel | ~$6K |
| Independent security audit (2027) | $75K to $200K |

All year-one work runs on free and open infrastructure. Paid dependencies
are optional.
