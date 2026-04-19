//! # oversight-semantic
//!
//! L3 semantic watermarking — airgap-strip-survivor watermarking by
//! rotating words between synonym classes. Mirrors the Python
//! `oversight_core.semantic` and `oversight_core.synonyms_v2` modules.
//!
//! ## Threat model
//!
//! L1 (zero-width unicode) and L2 (trailing whitespace) survive copy-paste
//! but fall to a "normalize & retype" attacker who opens the file in an
//! airgapped VM, strips invisibles and whitespace, and writes a clean
//! version. L3 survives that attack because the mark lives in **which
//! words were chosen**, not in invisible characters.
//!
//! ## Algorithm
//!
//! Per match (word that's a member of a known synonym class):
//!   - Derive a deterministic variant index from the mark_id + position counter.
//!   - Replace the word with the selected variant, preserving original case.
//!
//! Recovery iterates candidate mark_ids from the registry and computes the
//! correlation score (fraction of matches that agree with the expected
//! variant sequence). Score >= 0.70 (default threshold) is attribution.

use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A synonym class: N semantically equivalent words, tagged with part of speech.
#[derive(Debug, Clone, Copy)]
pub struct SC {
    pub variants: &'static [&'static str],
    pub pos: &'static str,
}

impl SC {
    pub const fn new(variants: &'static [&'static str], pos: &'static str) -> Self {
        SC { variants, pos }
    }
}

// The 151-class dictionary, generated from Python oversight_core/synonyms_v2.py.
include!("synonyms_v2_data.rs");

/// Total number of synonym classes.
pub fn class_count() -> usize {
    CLASSES.len()
}

/// Build a lowercase-word → (class_index, variant_index, pos) lookup.
/// First occurrence wins for ambiguous words. Only indexes single-word variants.
static LOOKUP: Lazy<HashMap<&'static str, (usize, usize, &'static str)>> = Lazy::new(|| {
    let mut m = HashMap::new();
    for (ci, cls) in CLASSES.iter().enumerate() {
        for (vi, w) in cls.variants.iter().enumerate() {
            if !w.contains(' ') && !m.contains_key(*w) {
                m.insert(*w, (ci, vi, cls.pos));
            }
        }
    }
    m
});

static ZW_CHARS: &[char] = &['\u{200b}', '\u{200c}', '\u{200d}', '\u{feff}'];

fn strip_zw(s: &str) -> String {
    s.chars().filter(|c| !ZW_CHARS.contains(c)).collect()
}

// Skip regions: URLs, emails, code spans, file paths, hex blobs, base64 blobs.
static URL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"https?://\S+").unwrap());
static EMAIL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[\w.+-]+@[\w.-]+\.\w+\b").unwrap());
static INLINE_CODE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"`[^`]+`").unwrap());
static CODE_BLOCK_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?s)```.*?```").unwrap());
static UNIX_PATH_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:^|\s)(?:/|~/|\./)[^\s]+").unwrap());
static HEX_BLOB_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[A-Fa-f0-9]{16,}\b").unwrap());
static BASE64_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[A-Za-z0-9+/]{32,}={0,2}\b").unwrap());
static WORD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b([A-Za-z]+)\b").unwrap());

/// Compute which byte positions in `text` are inside skip regions.
fn skip_mask(text: &str) -> Vec<bool> {
    let mut mask = vec![false; text.len()];
    let patterns: &[&Lazy<Regex>] = &[
        &URL_RE, &EMAIL_RE, &INLINE_CODE_RE, &CODE_BLOCK_RE, &UNIX_PATH_RE,
        &HEX_BLOB_RE, &BASE64_RE,
    ];
    for pat in patterns {
        for m in pat.find_iter(text) {
            for i in m.start()..m.end() {
                if i < mask.len() {
                    mask[i] = true;
                }
            }
        }
    }
    mask
}

/// A matchable word in the text with its class/variant assignment.
#[derive(Debug, Clone)]
pub struct Match {
    pub start: usize,
    pub end: usize,
    pub orig_word: String,
    pub class_index: usize,
    pub variant_index: usize,
    pub pos: &'static str,
}

/// Walk text and yield every word that is (a) in the synonym table,
/// (b) not inside a URL/path/code/hex region.
pub fn iter_matchable_words(text: &str) -> Vec<Match> {
    let mask = skip_mask(text);
    let mut out = Vec::new();
    for m in WORD_RE.find_iter(text) {
        // Skip if any byte of the match is in a skip region.
        let mut in_skip = false;
        for i in m.start()..m.end() {
            if i < mask.len() && mask[i] {
                in_skip = true;
                break;
            }
        }
        if in_skip {
            continue;
        }
        let word = m.as_str();
        let key = word.to_lowercase();
        if let Some(&(ci, vi, pos)) = LOOKUP.get(key.as_str()) {
            out.push(Match {
                start: m.start(),
                end: m.end(),
                orig_word: word.to_string(),
                class_index: ci,
                variant_index: vi,
                pos,
            });
        }
    }
    out
}

/// Is this variant safe to round-trip through our single-word matcher?
/// Variants with whitespace or hyphens break because WORD_RE only matches
/// [A-Za-z]+ — `write-up` gets tokenized as two words and neither is in
/// the lookup, desyncing the variant sequence.
fn is_round_trippable(variant: &str) -> bool {
    !variant.contains(' ') && !variant.contains('-')
}

/// Derive a deterministic variant sequence from a mark_id using SHA-256(mark_id || counter).
/// Yields `n_matches` bytes each bounded to `class_size` (v2 uses 3 variants per class).
fn mark_id_to_variant_sequence(mark_id: &[u8], n_matches: usize, class_size: usize) -> Vec<usize> {
    let mut out = Vec::with_capacity(n_matches);
    let mut counter: u64 = 0;
    while out.len() < n_matches {
        let mut h = Sha256::new();
        h.update(mark_id);
        h.update(&counter.to_be_bytes());
        let digest = h.finalize();
        for b in digest.iter() {
            if out.len() >= n_matches {
                break;
            }
            out.push((*b as usize) % class_size);
        }
        counter += 1;
    }
    out
}

/// Preserve the case pattern of `orig` when emitting `replacement`.
/// - all upper: UPPERCASE replacement
/// - first upper rest lower: Title Case replacement
/// - otherwise: lowercase replacement
fn case_preserve(replacement: &str, orig: &str) -> String {
    if orig.chars().all(|c| c.is_uppercase() || !c.is_alphabetic()) && orig.len() > 1 {
        return replacement.to_uppercase();
    }
    let first_upper = orig.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
    let rest_lower = orig.chars().skip(1).all(|c| c.is_lowercase() || !c.is_alphabetic());
    if first_upper && rest_lower {
        let mut s = String::new();
        for (i, c) in replacement.chars().enumerate() {
            if i == 0 {
                for uc in c.to_uppercase() {
                    s.push(uc);
                }
            } else {
                s.push(c);
            }
        }
        return s;
    }
    replacement.to_lowercase()
}

/// Embed a mark_id into the text via synonym rotation.
///
/// If the text has fewer than `min_instances` matchable words, returns the
/// text unchanged — no silent partial marking (the Python impl prints a
/// warning; here we just return unchanged and let the caller decide).
pub fn embed_synonyms(text: &str, mark_id: &[u8], min_instances: usize) -> String {
    let matches = iter_matchable_words(text);
    if matches.len() < min_instances {
        return text.to_string();
    }
    let variants = mark_id_to_variant_sequence(mark_id, matches.len(), 3);
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (m, &target) in matches.iter().zip(variants.iter()) {
        let cls = &CLASSES[m.class_index];
        let mut vi = target % cls.variants.len();
        // Skip multi-word and hyphenated variants — our matcher only sees
        // single unbroken A-Za-z words, and these would desync verify.
        for _ in 0..cls.variants.len() {
            if is_round_trippable(cls.variants[vi]) {
                break;
            }
            vi = (vi + 1) % cls.variants.len();
        }
        if !is_round_trippable(cls.variants[vi]) {
            // All variants are non-round-trippable (shouldn't happen); keep original
            out.push_str(&text[cursor..m.end]);
            cursor = m.end;
            continue;
        }
        let replacement = case_preserve(cls.variants[vi], &m.orig_word);
        out.push_str(&text[cursor..m.start]);
        out.push_str(&replacement);
        cursor = m.end;
    }
    out.push_str(&text[cursor..]);
    out
}

/// Verify whether `text` carries `candidate_mark_id`. Returns (match, score).
///
/// The score is the fraction of matchable words whose variant matches the
/// expected variant for the candidate mark_id. Default threshold 0.70.
pub fn verify_synonyms(text: &str, candidate_mark_id: &[u8], threshold: f64) -> (bool, f64) {
    let text = strip_zw(text);
    let actual: Vec<(usize, usize)> = iter_matchable_words(&text)
        .into_iter()
        .map(|m| (m.class_index, m.variant_index))
        .collect();
    if actual.is_empty() {
        return (false, 0.0);
    }
    let expected = mark_id_to_variant_sequence(candidate_mark_id, actual.len(), 3);
    let mut matches = 0usize;
    let mut counted = 0usize;
    for ((ci, actual_vi), &target) in actual.iter().zip(expected.iter()) {
        let cls = &CLASSES[*ci];
        counted += 1;
        // Mirror embed's round-trippability skip: if target variant is
        // not safely single-word, advance until it is (or give up).
        let mut exp = target % cls.variants.len();
        for _ in 0..cls.variants.len() {
            if is_round_trippable(cls.variants[exp]) {
                break;
            }
            exp = (exp + 1) % cls.variants.len();
        }
        if !is_round_trippable(cls.variants[exp]) {
            // All variants non-round-trippable — embed kept original. Count as match.
            matches += 1;
            continue;
        }
        if exp == *actual_vi {
            matches += 1;
        }
    }
    let score = matches as f64 / counted as f64;
    (score >= threshold, score)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TEXT: &str = "Q3 revenue performance exceeded expectations across all business units. \
The team plans to continue the expansion strategy outlined in our report at \
https://internal.example.com/q3-2026.pdf and will begin hiring in \
/home/claude/hiring_plan.docx this month. However, there are important risks \
to consider before we commence the next phase. We need to carefully review \
the competitive situation and determine whether our current approach is the \
right one. The board will also request that we improve internal reporting \
and reduce operational overhead. It is difficult to know exactly how quickly \
the market will change, but we should respond rapidly when opportunities appear. \
Overall the results show clear momentum and a strong basis for continued growth.";

    #[test]
    fn dict_has_expected_size() {
        // We ported 50 + 43 + 20 + 30 + 8 = 151 classes.
        assert_eq!(class_count(), 151);
    }

    #[test]
    fn matcher_finds_words() {
        let matches = iter_matchable_words(TEST_TEXT);
        assert!(
            matches.len() >= 10,
            "expected at least 10 matchable words, got {}",
            matches.len()
        );
    }

    #[test]
    fn url_and_path_preserved_through_embed() {
        let mark = b"\x01\x23\x45\x67\x89\xab\xcd\xef";
        let marked = embed_synonyms(TEST_TEXT, mark, 5);
        assert!(marked.contains("https://internal.example.com/q3-2026.pdf"),
                "URL was munged");
        assert!(marked.contains("/home/claude/hiring_plan.docx"),
                "path was munged");
    }

    #[test]
    fn correct_mark_verifies_with_high_score() {
        let mark = b"\x01\x23\x45\x67\x89\xab\xcd\xef";
        let marked = embed_synonyms(TEST_TEXT, mark, 5);
        let (ok, score) = verify_synonyms(&marked, mark, 0.70);
        assert!(ok, "correct mark failed to verify");
        assert!(score > 0.95, "expected near-1.0 score, got {}", score);
    }

    #[test]
    fn wrong_mark_rejected() {
        let good = b"\x01\x23\x45\x67\x89\xab\xcd\xef";
        let bad = b"\xff\xee\xdd\xcc\xbb\xaa\x99\x88";
        let marked = embed_synonyms(TEST_TEXT, good, 5);
        let (ok, score) = verify_synonyms(&marked, bad, 0.70);
        assert!(!ok, "wrong mark verified (score={})", score);
        assert!(score < 0.70, "wrong-mark score suspiciously high: {}", score);
    }

    #[test]
    fn airgap_strip_survivor() {
        // Simulate the attacker: strip zero-width chars + normalize trailing whitespace.
        // The semantic mark should still survive.
        let mark = b"\xde\xad\xbe\xef\xfe\xed\xfa\xce";
        let marked = embed_synonyms(TEST_TEXT, mark, 5);
        // Attacker normalizes: strip zero-width + trailing whitespace
        let stripped: String = marked
            .lines()
            .map(|l| l.trim_end().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let stripped = strip_zw(&stripped);
        let (ok, score) = verify_synonyms(&stripped, mark, 0.70);
        assert!(ok, "airgap-strip broke L3 attribution (score={})", score);
    }

    #[test]
    fn case_preserve_works() {
        assert_eq!(case_preserve("start", "BEGIN"), "START");
        assert_eq!(case_preserve("start", "Begin"), "Start");
        assert_eq!(case_preserve("start", "begin"), "start");
    }

    #[test]
    fn short_text_unchanged() {
        let mark = b"\x01\x02\x03\x04\x05\x06\x07\x08";
        let short = "Hello world";
        let marked = embed_synonyms(short, mark, 5);
        assert_eq!(marked, short); // below min_instances threshold
    }
}
