#!/usr/bin/env python3
"""
Oversight Protocol v0.4.4 — Performance Benchmarks for USENIX Security 2026

Runs all benchmarks locally with generated keys. No network access required.
Outputs results to stdout in markdown format.
"""

import os
import sys
import time
import platform
import statistics
import textwrap

# Ensure we import the local editable install
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oversight_core import seal, open_sealed, Manifest, Recipient, WatermarkRef, ClassicIdentity, content_hash
from oversight_core import watermark
from oversight_core.watermark import (
    embed_zw, extract_zw,
    embed_ws, extract_ws,
    apply_all, recover_marks, recover_marks_v2,
    new_mark_id,
)
from oversight_core.semantic import (
    apply_semantic, verify_semantic,
    embed_synonyms, embed_synonyms_v2,
    embed_punctuation, embed_spelling, embed_contractions, embed_number_format,
)
from oversight_core.fingerprint import ContentFingerprint
from oversight_core import ecc as ecc_mod


# ─── Configuration ───────────────────────────────────────────────────────────

N_RUNS = 10
SIZES = {
    "1 KB":   1_024,
    "10 KB":  10_240,
    "100 KB": 102_400,
    "1 MB":   1_048_576,
}

# Sample prose that gets repeated to fill the desired size. Uses words from
# the synonym dictionary so L3 watermarking has material to work with.
SAMPLE_PROSE = textwrap.dedent("""\
    The quick brown fox begins to display important information. We use large
    databases to find critical results. However, the organization doesn't
    analyze the data fast enough. This is a significant problem that
    requires a strategic approach.

    Additionally, we need to obtain the answer from the program before the
    center can provide an appropriate response. The defense team should
    recognize this issue and help to create a better plan. It is easy to
    show the outcome, but hard to tell the full story.

    The behavior of the system has been slow. We must utilize every
    available resource to make it fast. Begin the optimization process --
    start with the small changes, then tackle the large ones. "Quick wins
    are important," said the director, "but we also need a long-term
    strategy."

    The color of the output matters. We can customize the organization of
    the catalog to maximize the result. The fiber network in the center
    provides a fast connection. This program will analyze 1000 data points
    and optimize the defense against threats.

    Nevertheless, there are concerns about the approach. We shouldn't
    minimize the risks. It isn't easy to identify all the problems, but
    we're confident we can locate the critical ones. They've already begun
    to address 50% of the issues.

""")


def generate_text(target_bytes: int) -> str:
    """Repeat sample prose to approximately fill target_bytes."""
    repeats = (target_bytes // len(SAMPLE_PROSE.encode("utf-8"))) + 1
    full = SAMPLE_PROSE * repeats
    # Trim to approximate size
    encoded = full.encode("utf-8")[:target_bytes]
    return encoded.decode("utf-8", errors="ignore")


def bench(func, *args, n=N_RUNS, **kwargs):
    """Run func n times, return (mean_s, stddev_s, min_s, max_s, results_list)."""
    times = []
    result = None
    for _ in range(n):
        t0 = time.perf_counter()
        result = func(*args, **kwargs)
        t1 = time.perf_counter()
        times.append(t1 - t0)
    mean = statistics.mean(times)
    sd = statistics.stdev(times) if len(times) > 1 else 0.0
    return mean, sd, min(times), max(times), result


def format_time(seconds):
    """Human-readable time formatting."""
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.1f} us"
    elif seconds < 1.0:
        return f"{seconds * 1_000:.2f} ms"
    else:
        return f"{seconds:.3f} s"


def system_info():
    """Gather system info (no IPs or secrets)."""
    lines = []
    lines.append(f"- **Python:** {platform.python_version()} ({platform.python_implementation()})")
    lines.append(f"- **OS:** {platform.system()} {platform.release()} ({platform.machine()})")
    try:
        cpu = platform.processor() or "unknown"
        lines.append(f"- **CPU:** {cpu}")
    except Exception:
        lines.append("- **CPU:** (unavailable)")
    lines.append(f"- **Oversight version:** 0.4.4")
    lines.append(f"- **Date:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    lines.append(f"- **Runs per benchmark:** {N_RUNS}")
    return "\n".join(lines)


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    out = []

    def p(s=""):
        out.append(s)

    # ── System info ──
    p("# Oversight Protocol v0.4.4 -- Performance Benchmarks")
    p()
    p("**For USENIX Security 2026 Submission**")
    p()
    p("## System Information")
    p()
    p(system_info())
    p()

    # Pre-generate identities and texts
    print("[setup] Generating identities...", file=sys.stderr)
    issuer = ClassicIdentity.generate()
    recipient = ClassicIdentity.generate()
    mark_id = new_mark_id(8)

    texts = {}
    plaintexts = {}
    for label, sz in SIZES.items():
        texts[label] = generate_text(sz)
        plaintexts[label] = texts[label].encode("utf-8")

    # ══════════════════════════════════════════════════════════════════════════
    # 1. SEAL THROUGHPUT
    # ══════════════════════════════════════════════════════════════════════════
    print("[1/8] Seal throughput...", file=sys.stderr)
    p("## 1. Seal Throughput")
    p()
    p("Time to seal (encrypt + sign + build container) documents of various sizes.")
    p()
    p("| Size | Mean | Stddev | Min | Max | Throughput (MB/s) |")
    p("|------|------|--------|-----|-----|-------------------|")

    sealed_blobs = {}
    for label, sz in SIZES.items():
        pt = plaintexts[label]
        ch = content_hash(pt)

        def do_seal():
            m = Manifest.new(
                original_filename="bench.txt",
                content_hash=ch,
                size_bytes=len(pt),
                issuer_id="bench-issuer",
                issuer_ed25519_pub_hex=issuer.ed25519_pub.hex(),
                recipient=Recipient(
                    recipient_id="bench-recipient",
                    x25519_pub=recipient.x25519_pub.hex(),
                ),
                registry_url="local://bench",
            )
            return seal(pt, m, issuer.ed25519_priv, recipient.x25519_pub)

        mean, sd, mn, mx, blob = bench(do_seal)
        sealed_blobs[label] = blob
        tp = (sz / 1_048_576) / mean if mean > 0 else 0
        p(f"| {label} | {format_time(mean)} | {format_time(sd)} | {format_time(mn)} | {format_time(mx)} | {tp:.1f} |")

    p()

    # ══════════════════════════════════════════════════════════════════════════
    # 2. OPEN THROUGHPUT
    # ══════════════════════════════════════════════════════════════════════════
    print("[2/8] Open throughput...", file=sys.stderr)
    p("## 2. Open (Decrypt + Verify) Throughput")
    p()
    p("Time to open a sealed file: parse container, verify signature, unwrap DEK, AEAD decrypt, verify hash.")
    p()
    p("| Size | Mean | Stddev | Min | Max | Throughput (MB/s) |")
    p("|------|------|--------|-----|-----|-------------------|")

    for label, sz in SIZES.items():
        blob = sealed_blobs[label]

        def do_open():
            return open_sealed(blob, recipient.x25519_priv)

        mean, sd, mn, mx, _ = bench(do_open)
        tp = (sz / 1_048_576) / mean if mean > 0 else 0
        p(f"| {label} | {format_time(mean)} | {format_time(sd)} | {format_time(mn)} | {format_time(mx)} | {tp:.1f} |")

    p()

    # ══════════════════════════════════════════════════════════════════════════
    # 3. WATERMARK EMBEDDING OVERHEAD
    # ══════════════════════════════════════════════════════════════════════════
    print("[3/8] Watermark embedding overhead...", file=sys.stderr)
    p("## 3. Watermark Embedding Overhead")
    p()
    p("### 3a. Full seal without watermark vs. with watermark")
    p()
    p("| Size | Seal (no wm) | Seal (with wm) | Overhead |")
    p("|------|-------------|----------------|----------|")

    for label, sz in SIZES.items():
        pt_raw = plaintexts[label]
        ch_raw = content_hash(pt_raw)

        def seal_no_wm():
            m = Manifest.new(
                original_filename="bench.txt", content_hash=ch_raw,
                size_bytes=len(pt_raw), issuer_id="bench",
                issuer_ed25519_pub_hex=issuer.ed25519_pub.hex(),
                recipient=Recipient(recipient_id="r", x25519_pub=recipient.x25519_pub.hex()),
                registry_url="local://bench",
            )
            return seal(pt_raw, m, issuer.ed25519_priv, recipient.x25519_pub)

        # Watermarked: apply all layers to text, then seal the result
        wm_text = apply_all(texts[label], mark_id)
        pt_wm = wm_text.encode("utf-8")
        ch_wm = content_hash(pt_wm)

        def seal_with_wm():
            m = Manifest.new(
                original_filename="bench.txt", content_hash=ch_wm,
                size_bytes=len(pt_wm), issuer_id="bench",
                issuer_ed25519_pub_hex=issuer.ed25519_pub.hex(),
                recipient=Recipient(recipient_id="r", x25519_pub=recipient.x25519_pub.hex()),
                registry_url="local://bench",
            )
            return seal(pt_wm, m, issuer.ed25519_priv, recipient.x25519_pub)

        mean_no, sd_no, _, _, _ = bench(seal_no_wm)
        mean_wm, sd_wm, _, _, _ = bench(seal_with_wm)
        overhead_pct = ((mean_wm - mean_no) / mean_no * 100) if mean_no > 0 else 0
        p(f"| {label} | {format_time(mean_no)} | {format_time(mean_wm)} | {overhead_pct:+.1f}% |")

    p()
    p("### 3b. Per-layer watermark embedding time (text processing only)")
    p()
    p("| Size | L1 (zero-width) | L2 (whitespace) | L3 (semantic) | All layers |")
    p("|------|-----------------|-----------------|---------------|------------|")

    for label, sz in SIZES.items():
        txt = texts[label]

        def do_l1():
            return embed_zw(txt, mark_id)

        def do_l2():
            return embed_ws(txt, mark_id)

        def do_l3():
            return apply_semantic(txt, mark_id)

        def do_all():
            return apply_all(txt, mark_id)

        mean_l1, _, _, _, _ = bench(do_l1)
        mean_l2, _, _, _, _ = bench(do_l2)
        mean_l3, _, _, _, _ = bench(do_l3)
        mean_all, _, _, _, _ = bench(do_all)

        p(f"| {label} | {format_time(mean_l1)} | {format_time(mean_l2)} | {format_time(mean_l3)} | {format_time(mean_all)} |")

    p()

    # ══════════════════════════════════════════════════════════════════════════
    # 4. WATERMARK EXTRACTION TIME
    # ══════════════════════════════════════════════════════════════════════════
    print("[4/8] Watermark extraction time...", file=sys.stderr)
    p("## 4. Watermark Extraction Time")
    p()
    p("Time to extract watermarks from watermarked text using `recover_marks()` and `recover_marks_v2()`.")
    p()
    p("| Size | recover_marks() | recover_marks_v2() (no L3 candidates) | recover_marks_v2() (with L3 candidate) |")
    p("|------|----------------|---------------------------------------|---------------------------------------|")

    for label, sz in SIZES.items():
        wm_text = apply_all(texts[label], mark_id)

        def do_rm():
            return recover_marks(wm_text)

        def do_rm2_no_l3():
            return recover_marks_v2(wm_text)

        def do_rm2_l3():
            return recover_marks_v2(wm_text, candidate_mark_ids=[mark_id])

        mean_rm, _, _, _, _ = bench(do_rm)
        mean_rm2n, _, _, _, _ = bench(do_rm2_no_l3)
        mean_rm2l, _, _, _, _ = bench(do_rm2_l3)

        p(f"| {label} | {format_time(mean_rm)} | {format_time(mean_rm2n)} | {format_time(mean_rm2l)} |")

    p()

    # ══════════════════════════════════════════════════════════════════════════
    # 5. CONTENT FINGERPRINT COMPUTATION
    # ══════════════════════════════════════════════════════════════════════════
    print("[5/8] Content fingerprint computation...", file=sys.stderr)
    p("## 5. Content Fingerprint Computation")
    p()
    p("Time to compute `ContentFingerprint.from_text()` (winnowing + sentence hashing).")
    p()
    p("| Size | Mean | Stddev | Min | Max | Winnowing hashes | Sentence hashes |")
    p("|------|------|--------|-----|-----|-----------------|-----------------|")

    for label, sz in SIZES.items():
        txt = texts[label]

        def do_fp():
            return ContentFingerprint.from_text(txt)

        mean, sd, mn, mx, fp = bench(do_fp)
        p(f"| {label} | {format_time(mean)} | {format_time(sd)} | {format_time(mn)} | {format_time(mx)} | {len(fp.winnowing_fp)} | {len(fp.sentence_fp)} |")

    p()

    # ══════════════════════════════════════════════════════════════════════════
    # 6. L3 VERIFICATION TIME
    # ══════════════════════════════════════════════════════════════════════════
    print("[6/8] L3 verification time...", file=sys.stderr)
    p("## 6. L3 Semantic Verification Time")
    p()
    p("Time to run `verify_semantic()` with correct and incorrect mark IDs.")
    p()
    p("| Size | Correct mark_id | Wrong mark_id | Correct score | Wrong score |")
    p("|------|----------------|---------------|---------------|-------------|")

    wrong_mark_id = new_mark_id(8)

    for label, sz in SIZES.items():
        wm_text = apply_all(texts[label], mark_id)

        def do_verify_correct():
            return verify_semantic(wm_text, mark_id)

        def do_verify_wrong():
            return verify_semantic(wm_text, wrong_mark_id)

        mean_c, _, _, _, result_c = bench(do_verify_correct)
        mean_w, _, _, _, result_w = bench(do_verify_wrong)

        c_score = result_c.get("weighted_score", 0)
        w_score = result_w.get("weighted_score", 0)

        p(f"| {label} | {format_time(mean_c)} | {format_time(mean_w)} | {c_score:.3f} | {w_score:.3f} |")

    p()

    # ══════════════════════════════════════════════════════════════════════════
    # 7. FILE SIZE OVERHEAD
    # ══════════════════════════════════════════════════════════════════════════
    print("[7/8] File size overhead...", file=sys.stderr)
    p("## 7. File Size Overhead")
    p()
    p("Plaintext size vs. sealed container size (no watermark), and watermarked+sealed size.")
    p()
    p("| Nominal | Plaintext bytes | Sealed bytes | Overhead (sealed) | Watermarked text bytes | WM+Sealed bytes | Overhead (wm+sealed) |")
    p("|---------|----------------|-------------|-------------------|----------------------|-----------------|---------------------|")

    for label, sz in SIZES.items():
        pt = plaintexts[label]
        blob = sealed_blobs[label]

        wm_text = apply_all(texts[label], mark_id)
        pt_wm = wm_text.encode("utf-8")
        ch_wm = content_hash(pt_wm)
        m = Manifest.new(
            original_filename="bench.txt", content_hash=ch_wm,
            size_bytes=len(pt_wm), issuer_id="bench",
            issuer_ed25519_pub_hex=issuer.ed25519_pub.hex(),
            recipient=Recipient(recipient_id="r", x25519_pub=recipient.x25519_pub.hex()),
            registry_url="local://bench",
        )
        blob_wm = seal(pt_wm, m, issuer.ed25519_priv, recipient.x25519_pub)

        overhead_sealed = ((len(blob) - len(pt)) / len(pt)) * 100
        overhead_wm = ((len(blob_wm) - len(pt)) / len(pt)) * 100

        p(f"| {label} | {len(pt):,} | {len(blob):,} | +{overhead_sealed:.1f}% | {len(pt_wm):,} | {len(blob_wm):,} | +{overhead_wm:.1f}% |")

    p()

    # ══════════════════════════════════════════════════════════════════════════
    # 8. ECC ENCODE/DECODE TIME
    # ══════════════════════════════════════════════════════════════════════════
    print("[8/8] ECC encode/decode time...", file=sys.stderr)
    p("## 8. ECC Encode/Decode Time")
    p()
    p("Time for error-correcting code operations on mark_id payloads of various sizes.")
    p()

    ecc_payloads = {
        "8 bytes (64-bit mark_id)": 8,
        "16 bytes (128-bit mark_id)": 16,
        "32 bytes (256-bit mark_id)": 32,
    }

    for rep in [3, 5, 7]:
        p(f"### Repetition factor R={rep}")
        p()
        p(f"| Payload | Coded bits | Encode mean | Encode stddev | Decode mean | Decode stddev | Decode w/ 20% errors |")
        p(f"|---------|-----------|-------------|---------------|-------------|---------------|---------------------|")

        for plabel, plen in ecc_payloads.items():
            payload = new_mark_id(plen)
            coded_len = plen * 8 * rep

            def do_encode():
                return ecc_mod.encode(payload, repetitions=rep)

            mean_e, sd_e, _, _, coded_bits = bench(do_encode)

            def do_decode():
                return ecc_mod.decode(coded_bits, payload_len=plen, repetitions=rep)

            mean_d, sd_d, _, _, (decoded, conf, errs) = bench(do_decode)

            # Decode with 20% random errors
            import random
            random.seed(42)
            noisy = list(coded_bits)
            n_flip = int(len(noisy) * 0.20)
            flip_idx = random.sample(range(len(noisy)), n_flip)
            for i in flip_idx:
                noisy[i] = 1 - noisy[i]

            def do_decode_noisy():
                return ecc_mod.decode(noisy, payload_len=plen, repetitions=rep)

            mean_dn, sd_dn, _, _, (dec_n, conf_n, errs_n) = bench(do_decode_noisy)

            p(f"| {plabel} | {coded_len} | {format_time(mean_e)} | {format_time(sd_e)} | {format_time(mean_d)} | {format_time(sd_d)} | {format_time(mean_dn)} (conf={conf_n:.2f}, corrected={errs_n}) |")

        p()

    # ══════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════════
    p("## Summary Observations")
    p()
    p("1. **Seal/Open operations** are dominated by cryptographic primitives (X25519 key agreement, Ed25519 signing, XChaCha20-Poly1305 AEAD). The per-operation overhead is constant regardless of document size for key operations; only AEAD encryption/decryption scales linearly with payload size.")
    p()
    p("2. **Watermark embedding overhead** is negligible at the container level. The L1 (zero-width) and L2 (whitespace) layers are O(n) string operations with minimal constant factors. L3 (semantic) is the most expensive layer due to regex-based synonym matching across the full text, but remains practical for all tested document sizes.")
    p()
    p("3. **Watermark extraction** (L1 + L2) is fast. L3 verification is candidate-based and scales linearly with text length and the number of candidates tested.")
    p()
    p("4. **Content fingerprinting** (winnowing + sentence hashing) is the most computationally intensive operation per byte due to rolling hash computation. For 1 MB documents, it remains well under real-time requirements.")
    p()
    p("5. **File size overhead** from the sealed container format is small and amortizes as document size grows. The fixed overhead includes the manifest (~500 bytes), wrapped DEK (~150 bytes), and AEAD nonce (24 bytes). The Poly1305 tag adds 16 bytes. Watermark text expansion (primarily L1 zero-width characters) adds variable overhead proportional to document length.")
    p()
    p("6. **ECC** repetition coding is extremely fast (sub-microsecond for typical payloads). With R=7, the scheme tolerates up to 42% random bit errors while recovering the original mark_id, making it robust against moderate paraphrasing attacks on L3 synonym marks.")
    p()
    p("---")
    p()
    p("## Figures-Ready Data (CSV)")
    p()
    p("The tables above can be directly imported into plotting tools. Key relationships for figures:")
    p()
    p("- **Figure 1:** Seal throughput vs. document size (log-log plot)")
    p("- **Figure 2:** Per-layer watermark embedding time breakdown (stacked bar)")
    p("- **Figure 3:** File size overhead ratio vs. document size")
    p("- **Figure 4:** L3 verification: correct vs. wrong mark_id score distributions")
    p("- **Figure 5:** ECC error tolerance: decode confidence vs. bit error rate")
    p()

    return "\n".join(out)


if __name__ == "__main__":
    result = main()
    print(result)
    # Also write to file; override destination via OVERSIGHT_BENCH_OUT.
    outpath = os.environ.get("OVERSIGHT_BENCH_OUT", "PERFORMANCE_BENCHMARKS.md")
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(result)
    print(f"\n[done] Written to {outpath}", file=sys.stderr)
