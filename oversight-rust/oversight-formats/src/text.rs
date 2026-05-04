//! # Text format adapter
//!
//! Wraps the three watermark layers into a single embed/extract API:
//!
//! - **L1** zero-width unicode (`oversight-watermark::embed_zw` / `extract_zw`)
//! - **L2** trailing whitespace (`oversight-watermark::embed_ws` / `extract_ws`)
//! - **L3** semantic synonym rotation (`oversight-semantic::embed_synonyms` / `verify_synonyms`)
//!
//! Layer order on embed: L3 runs first (rewrites visible words), then L1
//! (zero-width chars), then L2 (trailing whitespace). L2 runs last so later
//! zero-width frame insertion cannot move trailing whitespace away from the
//! physical end of a line.

use crate::{FormatAdapter, FormatError, WatermarkCandidate};

/// Default mark_id length in bytes (8 bytes = 64 bits).
const MARK_LEN: usize = 8;

/// Default density for L1 zero-width embedding (chars between frames).
const ZW_DENSITY: usize = 40;

/// Minimum matchable words required for L3 semantic embedding.
const L3_MIN_INSTANCES: usize = 5;

/// Default L3 verification threshold.
const L3_THRESHOLD: f64 = 0.70;

/// Text format adapter. Handles plaintext (UTF-8) files.
pub struct TextAdapter;

impl FormatAdapter for TextAdapter {
    fn name(&self) -> &str {
        "text"
    }

    fn extensions(&self) -> &[&str] {
        &[
            "txt", "md", "rst", "csv", "log", "json", "xml", "yaml", "yml", "toml",
        ]
    }

    fn can_handle(&self, data: &[u8]) -> bool {
        // Text is the fallback: accept anything that's valid UTF-8 and doesn't
        // start with known binary magic bytes.
        if data.is_empty() {
            return true;
        }
        // Reject known binary formats
        if data.starts_with(b"%PDF") || data.starts_with(b"PK\x03\x04") {
            return false;
        }
        // PNG magic
        if data.len() >= 4 && data[0..4] == [0x89, b'P', b'N', b'G'] {
            return false;
        }
        // JPEG magic
        if data.len() >= 2 && data[0..2] == [0xFF, 0xD8] {
            return false;
        }
        // Must be valid UTF-8
        std::str::from_utf8(data).is_ok()
    }

    fn embed_watermark(&self, data: &[u8], mark_id: &[u8]) -> Result<Vec<u8>, FormatError> {
        let text = std::str::from_utf8(data).map_err(|e| FormatError::Utf8Str(e))?;
        let marked = embed_all_layers(text, mark_id);
        Ok(marked.into_bytes())
    }

    fn extract_watermark(&self, data: &[u8]) -> Result<Vec<WatermarkCandidate>, FormatError> {
        let text = std::str::from_utf8(data).map_err(|e| FormatError::Utf8Str(e))?;
        Ok(extract_all_layers(text))
    }

    fn normalize_for_fingerprint(&self, data: &[u8]) -> Result<String, FormatError> {
        let text = std::str::from_utf8(data).map_err(|e| FormatError::Utf8Str(e))?;
        Ok(normalize_text(text))
    }
}

// ---------------------------------------------------------------------------
// Layer orchestration
// ---------------------------------------------------------------------------

/// Apply all three watermark layers to plaintext.
///
/// Layer order: L3 first (rewrites visible words), then L1 (zero-width
/// chars), then L2 (trailing whitespace). This order ensures that semantic
/// rewriting does not fragment invisible frames and that L2 remains at line
/// endings.
pub fn embed_all_layers(text: &str, mark_id: &[u8]) -> String {
    // L3: semantic synonym rotation
    let t = oversight_semantic::embed_synonyms(text, mark_id, L3_MIN_INSTANCES);
    // L1: zero-width unicode
    let t = oversight_watermark::embed_zw(&t, mark_id, ZW_DENSITY);
    // L2: trailing whitespace
    oversight_watermark::embed_ws(&t, mark_id)
}

/// Apply only specific layers. `layers` is a slice of layer names: "L1", "L2", "L3".
pub fn embed_layers(text: &str, mark_id: &[u8], layers: &[&str]) -> String {
    let mut t = text.to_string();
    if layers.contains(&"L3") {
        t = oversight_semantic::embed_synonyms(&t, mark_id, L3_MIN_INSTANCES);
    }
    if layers.contains(&"L1") {
        t = oversight_watermark::embed_zw(&t, mark_id, ZW_DENSITY);
    }
    if layers.contains(&"L2") {
        t = oversight_watermark::embed_ws(&t, mark_id);
    }
    t
}

/// Extract watermark candidates from all layers.
///
/// L1 and L2 recover mark_id directly from invisible content.
/// L3 requires candidate mark_ids to verify against (correlation-based),
/// so it is not included here. Use `verify_l3` separately with candidate IDs.
pub fn extract_all_layers(text: &str) -> Vec<WatermarkCandidate> {
    let mut candidates = Vec::new();

    // L1: zero-width unicode extraction
    let l1_marks = oversight_watermark::extract_zw(text, MARK_LEN);
    for mark in l1_marks {
        candidates.push(WatermarkCandidate {
            mark_id: mark,
            layer: "L1".into(),
            confidence: 1.0,
        });
    }

    // L2: trailing whitespace extraction
    if let Some(mark) = oversight_watermark::extract_ws(text, MARK_LEN) {
        candidates.push(WatermarkCandidate {
            mark_id: mark,
            layer: "L2".into(),
            confidence: 1.0,
        });
    }

    // Deduplicate: if L1 and L2 agree on a mark_id, keep both entries
    // (they serve as independent corroboration).
    candidates
}

/// Verify a candidate mark_id against L3 semantic watermark.
///
/// Returns `Some(WatermarkCandidate)` if the candidate matches with score
/// above the threshold, `None` otherwise.
pub fn verify_l3(text: &str, candidate_mark_id: &[u8]) -> Option<WatermarkCandidate> {
    let (matched, score) =
        oversight_semantic::verify_synonyms(text, candidate_mark_id, L3_THRESHOLD);
    if matched {
        Some(WatermarkCandidate {
            mark_id: candidate_mark_id.to_vec(),
            layer: "L3".into(),
            confidence: score,
        })
    } else {
        None
    }
}

/// Verify a candidate mark_id against all layers. Combines direct extraction
/// (L1/L2) with correlation verification (L3).
pub fn verify_all_layers(text: &str, candidate_mark_id: &[u8]) -> Vec<WatermarkCandidate> {
    let mut results = Vec::new();

    // L1: check if any extracted mark matches the candidate
    let l1_marks = oversight_watermark::extract_zw(text, candidate_mark_id.len());
    for mark in &l1_marks {
        if mark == candidate_mark_id {
            results.push(WatermarkCandidate {
                mark_id: candidate_mark_id.to_vec(),
                layer: "L1".into(),
                confidence: 1.0,
            });
            break;
        }
    }

    // L2: check if extracted mark matches
    if let Some(mark) = oversight_watermark::extract_ws(text, candidate_mark_id.len()) {
        if mark == candidate_mark_id {
            results.push(WatermarkCandidate {
                mark_id: candidate_mark_id.to_vec(),
                layer: "L2".into(),
                confidence: 1.0,
            });
        }
    }

    // L3: semantic correlation
    if let Some(candidate) = verify_l3(text, candidate_mark_id) {
        results.push(candidate);
    }

    results
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// Normalize text for fingerprinting: strip zero-width chars, normalize
/// whitespace, lowercase.
fn normalize_text(text: &str) -> String {
    let zw_chars: &[char] = &['\u{200b}', '\u{200c}', '\u{200d}', '\u{feff}'];
    let mut out = String::with_capacity(text.len());
    let mut prev_ws = false;
    for ch in text.chars() {
        // Skip zero-width characters
        if zw_chars.contains(&ch) {
            continue;
        }
        if ch.is_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(ch.to_lowercase().next().unwrap_or(ch));
            prev_ws = false;
        }
    }
    out.trim().to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn long_text() -> String {
        (0..80)
            .map(|i| {
                format!(
                    "Line {i}: The quick brown fox jumps over the lazy dog while revenue performance and operational plans remain under review."
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn text_adapter_can_handle() {
        let adapter = TextAdapter;
        assert!(adapter.can_handle(b"Hello, world!"));
        assert!(adapter.can_handle(b""));
        assert!(!adapter.can_handle(b"%PDF-1.4"));
        assert!(!adapter.can_handle(b"PK\x03\x04"));
        assert!(!adapter.can_handle(&[0xFF, 0xD8, 0xFF, 0xE0])); // JPEG
        assert!(!adapter.can_handle(&[0x89, b'P', b'N', b'G'])); // PNG
    }

    #[test]
    fn text_adapter_extensions() {
        let adapter = TextAdapter;
        assert!(adapter.extensions().contains(&"txt"));
        assert!(adapter.extensions().contains(&"md"));
        assert!(adapter.extensions().contains(&"json"));
    }

    #[test]
    fn embed_extract_round_trip_l1_l2() {
        let mark = oversight_watermark::new_mark_id(MARK_LEN);
        let text = long_text();
        let marked = embed_layers(&text, &mark, &["L1", "L2"]);
        let candidates = extract_all_layers(&marked);

        let l1_hits: Vec<_> = candidates.iter().filter(|c| c.layer == "L1").collect();
        let l2_hits: Vec<_> = candidates.iter().filter(|c| c.layer == "L2").collect();

        assert!(!l1_hits.is_empty(), "L1 should recover at least one mark");
        assert_eq!(l1_hits[0].mark_id, mark);
        assert!(!l2_hits.is_empty(), "L2 should recover the mark");
        assert_eq!(l2_hits[0].mark_id, mark);
    }

    #[test]
    fn embed_extract_all_layers_round_trip() {
        let mark = oversight_watermark::new_mark_id(MARK_LEN);
        let text = long_text();
        let marked = embed_all_layers(&text, &mark);

        // L1 + L2 direct extraction
        let candidates = extract_all_layers(&marked);
        let l1_hits: Vec<_> = candidates.iter().filter(|c| c.layer == "L1").collect();
        assert!(!l1_hits.is_empty(), "L1 should recover");
        assert_eq!(l1_hits[0].mark_id, mark);

        // L3 verification
        let l3 = verify_l3(&marked, &mark);
        assert!(l3.is_some(), "L3 should verify the correct mark");
        assert!(l3.unwrap().confidence > 0.90);
    }

    #[test]
    fn verify_all_layers_correct_mark() {
        let mark = oversight_watermark::new_mark_id(MARK_LEN);
        let text = long_text();
        let marked = embed_all_layers(&text, &mark);
        let results = verify_all_layers(&marked, &mark);
        let layers: Vec<&str> = results.iter().map(|r| r.layer.as_str()).collect();
        assert!(layers.contains(&"L1"), "L1 should verify");
        assert!(layers.contains(&"L2"), "L2 should verify");
        assert!(layers.contains(&"L3"), "L3 should verify");
    }

    #[test]
    fn verify_all_layers_wrong_mark() {
        let good = oversight_watermark::new_mark_id(MARK_LEN);
        let bad = oversight_watermark::new_mark_id(MARK_LEN);
        let text = long_text();
        let marked = embed_all_layers(&text, &good);
        let results = verify_all_layers(&marked, &bad);
        // Wrong mark should not match any layer (with overwhelmingly high probability)
        assert!(
            results.is_empty()
                || results
                    .iter()
                    .all(|r| r.layer == "L3" && r.confidence < 0.80)
        );
    }

    #[test]
    fn adapter_embed_extract_via_trait() {
        let adapter = TextAdapter;
        let mark = oversight_watermark::new_mark_id(MARK_LEN);
        let text = long_text();
        let data = text.as_bytes();

        let marked_bytes = adapter.embed_watermark(data, &mark).unwrap();
        let candidates = adapter.extract_watermark(&marked_bytes).unwrap();

        assert!(
            !candidates.is_empty(),
            "should extract at least one candidate"
        );
        assert!(candidates.iter().any(|c| c.mark_id == mark));
    }

    #[test]
    fn normalize_strips_invisible() {
        let adapter = TextAdapter;
        let text_with_zw = "Hello\u{200b}world\u{200c}foo\u{200d}bar";
        let normalized = adapter
            .normalize_for_fingerprint(text_with_zw.as_bytes())
            .unwrap();
        assert_eq!(normalized, "helloworldfoobar");
    }

    #[test]
    fn normalize_collapses_whitespace() {
        let adapter = TextAdapter;
        let text = "  Hello   world  \n\n  foo  ";
        let normalized = adapter.normalize_for_fingerprint(text.as_bytes()).unwrap();
        assert_eq!(normalized, "hello world foo");
    }

    #[test]
    fn l1_survives_stripped_whitespace() {
        // L1 zero-width chars survive trailing-whitespace stripping
        let mark = oversight_watermark::new_mark_id(MARK_LEN);
        let text = long_text();
        let marked = embed_all_layers(&text, &mark);
        let stripped: String = marked
            .lines()
            .map(|l| l.trim_end())
            .collect::<Vec<_>>()
            .join("\n");
        let candidates = extract_all_layers(&stripped);
        let l1_hits: Vec<_> = candidates.iter().filter(|c| c.layer == "L1").collect();
        assert!(
            !l1_hits.is_empty(),
            "L1 should survive whitespace stripping"
        );
        assert_eq!(l1_hits[0].mark_id, mark);
    }
}
