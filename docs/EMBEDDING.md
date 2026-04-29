# Embedding the Oversight Verification Core

This document is the integration contract for downstream projects that want
to embed the Oversight Rust verification core. The first known consumer is
the [`oversight-mobile`](https://github.com/oversight-protocol/oversight-mobile)
Flutter + Rust verifier app, which embeds these crates via
`flutter_rust_bridge` so the desktop CLI and the mobile app share one
verification implementation. The same contract applies to any future
embedder (Electron, browser-wasm, server-side verifier, third-party tooling).

The goal is to give downstream consumers a stable, reproducible way to depend
on the verifier without forking the protocol or pinning to `main`.

## Verifier-safe crates

These seven crates are designed to be embedded and have no I/O or
sender-only surface. A consumer that wants to verify Oversight artifacts
should depend on these and only these.

| Crate | What it does |
|---|---|
| `oversight-crypto` | X25519, Ed25519, ChaCha20-Poly1305, HKDF-SHA256 primitives. Pure RustCrypto; no platform-specific code. |
| `oversight-manifest` | Manifest data structures, signature verification, canonicalization. |
| `oversight-container` | `.sealed` container parsing and authenticated decryption. |
| `oversight-tlog` | Transparency-log data structures and inclusion-proof verification. |
| `oversight-rekor` | Sigstore Rekor v2 client for fetching tree heads and inclusion proofs. |
| `oversight-watermark` | L1 zero-width and L2 whitespace watermark detection (read-only). |
| `oversight-policy` | Policy evaluation for unseal-time decisions (`allow`, `deny`, `warn`). |

These crates compile cleanly for desktop, iOS (`aarch64`), and Android
(`aarch64`, `armv7`, `x86_64`, `i686`). The 32-bit Android targets require
oversight v0.4.8 or later because of the `MAX_CIPHERTEXT_BYTES` portability
fix landed in that release.

## Crates not for embedding

These crates exist in the workspace but are not part of the embedding
contract. Depending on them from a downstream consumer will work today but
will couple the consumer to surface that is intentionally out of scope for a
verifier and that may change without an embedding-API minor bump.

| Crate | Why it is not for downstream embedding |
|---|---|
| `oversight-cli` | Desktop CLI binary. Pulls in TTY, file-tree, and Rich-formatted output. Not a library. |
| `oversight-registry` | Axum + SQLx registry server. Sender-side and operator-side; verifiers do not run a registry. |
| `oversight-formats` | PDF, DOCX, image-LSB watermark application. Sender-only; pulls in heavy format dependencies that are wrong for a verifier binary's size budget. |
| `oversight-semantic` | L3 semantic synonym rotation. Sender-only; the verifier path uses `oversight-watermark` for L1/L2 detection only. |

A verifier-only embedder that finds it needs something from these crates is
probably reaching for the wrong API; open an issue describing the use case
before depending on them.

## Pin pattern

Embedders pin to a tagged release, never to `main` and never via a path
dependency. Path dependencies break reproducibility (the build is sensitive
to whatever sits next to the consumer's checkout) and break clone-and-build
for new contributors. Git plus tag is the supported pin.

```toml
[dependencies]
oversight-crypto    = { git = "https://github.com/oversight-protocol/oversight.git", tag = "v0.4.8" }
oversight-manifest  = { git = "https://github.com/oversight-protocol/oversight.git", tag = "v0.4.8" }
oversight-container = { git = "https://github.com/oversight-protocol/oversight.git", tag = "v0.4.8" }
oversight-tlog      = { git = "https://github.com/oversight-protocol/oversight.git", tag = "v0.4.8" }
oversight-rekor     = { git = "https://github.com/oversight-protocol/oversight.git", tag = "v0.4.8" }
oversight-watermark = { git = "https://github.com/oversight-protocol/oversight.git", tag = "v0.4.8" }
oversight-policy    = { git = "https://github.com/oversight-protocol/oversight.git", tag = "v0.4.8" }
```

Cargo resolves all seven entries against the same git checkout, so the
fetch happens once and every crate is byte-identical to what the desktop
CLI shipped against. `Cargo.lock` records the resolved commit
(`af6f725c` for `v0.4.8`); a downstream consumer who commits their lock
file will get reproducible resolution across machines.

For a consumer that prefers a commit-sha pin over a tag pin, the same
pattern works with `rev` instead of `tag`. Tag is the recommended default
because tags are how the protocol announces release boundaries.

## Minimum versions

| Embedder target | Minimum oversight tag | Reason |
|---|---|---|
| Desktop / 64-bit only | `v0.4.5` | First release with hardened parser strictness. |
| Mobile with 64-bit Android only | `v0.4.5` | Same. |
| Mobile with 32-bit Android (`armv7`, `i686`) | `v0.4.8` | `MAX_CIPHERTEXT_BYTES` 4 GiB literal gated to 64-bit; falls back to `usize::MAX` on 32-bit. |
| Anyone needing the GHSA-82j2-j2ch-gfr8 CRL fix | `v0.4.8` | `rustls-webpki` lifted to 0.103.13. |

Older releases will continue to compile, but the project does not
backport security or portability fixes to anything below the current
stable line.

## Build profile expectations

The workspace's `[profile.release]` defaults are tuned for the desktop CLI:
unwinding panics, default codegen-units, debuginfo on. Embedders are free
to override the profile in their own `Cargo.toml`. The mobile companion's
release profile, for example, sets `lto = true`, `codegen-units = 1`,
`strip = true`, and `opt-level = "z"` for binary-size reasons. None of
those choices change the verifier's behavior; they are downstream concerns.

## Versioning expectations

The Rust workspace version is independent of the Python `oversight-protocol`
package version. The workspace tracks its own `[workspace.package].version`
in `oversight-rust/Cargo.toml`. Embedders that want a stable lib-API
contract should pin against the git tag of the desktop release, not the
workspace version. The git tag is the canonical Oversight release; the
workspace version is an implementation detail of the Rust members.

## Reporting integration issues

Open an issue at
[oversight-protocol/oversight](https://github.com/oversight-protocol/oversight/issues)
with the embedder name, the desktop tag the build pinned against, and the
target triple. The mobile companion is the worked example for what a
clean embedding looks like, including its CI configuration for cross-compile
to four Android ABIs and one iOS ABI.

## Referenced from

- [`oversight-protocol/oversight-mobile`](https://github.com/oversight-protocol/oversight-mobile)
  — Flutter + Rust verifier; embeds the seven verifier-safe crates via
  `flutter_rust_bridge`. As of mobile `v0.1.12`, pinned to oversight `v0.4.8`.
