# Oversight fuzz harnesses

Two libFuzzer-based harnesses for the security-critical parsers:
- `container_parser` — hammers the `.sealed` binary format parser
- `manifest_parser` — hammers the canonical-JSON manifest parser

## Setup (one time)

```bash
cargo install cargo-fuzz
```

Requires a nightly Rust toolchain for fuzzing (sanitizers, coverage):
```bash
rustup install nightly
```

## Run

```bash
cd oversight-rust/fuzz
cargo +nightly fuzz run container_parser -- -max_total_time=300
cargo +nightly fuzz run manifest_parser -- -max_total_time=300
```

## What "pass" looks like

The harness runs until you stop it. "Pass" means: no panics, no hangs,
no OOMs, no memory safety violations (Rust + libFuzzer's AddressSanitizer
catches memory bugs). Any crash input is saved to `fuzz/artifacts/...` for
reproduction.

Target: run continuously for at least 24 hours before a paid security audit
engagement, per our ROADMAP.md prerequisites.
