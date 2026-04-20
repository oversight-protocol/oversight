//! # oversight-watermark
//!
//! Per-recipient text watermarking. Two MVP layers:
//!
//! - **L1 zero-width unicode**: embeds mark_id bits as ZWSP / ZWNJ frames.
//!   Survives copy-paste. Defeated by normalize/strip passes.
//!
//! - **L2 whitespace**: trailing-space vs trailing-tab on lines. Survives
//!   more aggressive cleaning than L1.
//!
//! Higher-fidelity layers (semantic synonym rotation, DCT image watermarks,
//! PDF/DOCX metadata) live in separate crates so each can evolve independently.

use rand_core::{OsRng, RngCore};

pub const ZW_SPACE: char = '\u{200b}'; // bit 0
pub const ZW_NONJOIN: char = '\u{200c}'; // bit 1
pub const ZW_JOIN: char = '\u{200d}'; // frame delimiter

fn bits_of(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 8);
    for byte in data {
        for i in 0..8 {
            out.push((byte >> (7 - i)) & 1);
        }
    }
    out
}

fn bytes_from_bits(bits: &[u8]) -> Vec<u8> {
    let n = (bits.len() / 8) * 8;
    let mut out = Vec::with_capacity(n / 8);
    let mut i = 0;
    while i < n {
        let mut b: u8 = 0;
        for j in 0..8 {
            b = (b << 1) | (bits[i + j] & 1);
        }
        out.push(b);
        i += 8;
    }
    out
}

/// Generate a random mark_id. 8 bytes = 64 bits = plenty for attribution.
pub fn new_mark_id(n_bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; n_bytes];
    OsRng.fill_bytes(&mut out);
    out
}

// -------------------------- L1: zero-width unicode --------------------------

/// Embed `mark_id` as repeated zero-width frames scattered through the text.
///
/// Each frame is `[ZW_JOIN] [bits as ZWSP/ZWNJ] [ZW_JOIN]`. Multiple redundant
/// frames are inserted at roughly `density`-char intervals so that any
/// surviving segment yields an attribution.
pub fn embed_zw(text: &str, mark_id: &[u8], density: usize) -> String {
    let bits = bits_of(mark_id);
    let mut frame = String::with_capacity(bits.len() + 2);
    frame.push(ZW_JOIN);
    for b in &bits {
        frame.push(if *b == 0 { ZW_SPACE } else { ZW_NONJOIN });
    }
    frame.push(ZW_JOIN);

    if text.chars().count() < density {
        let mut out = String::from(text);
        out.push_str(&frame);
        return out;
    }

    let mut out = String::with_capacity(text.len() + frame.len() * (text.len() / density));
    for (i, ch) in text.chars().enumerate() {
        out.push(ch);
        if i > 0 && i % density == 0 {
            out.push_str(&frame);
        }
    }
    out
}

/// Recover candidate mark_ids from zero-width frames in the text.
pub fn extract_zw(text: &str, mark_len_bytes: usize) -> Vec<Vec<u8>> {
    let expected_bits = mark_len_bytes * 8;
    let chars: Vec<char> = text.chars().collect();
    let mut marks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ZW_JOIN {
            let mut bits = Vec::new();
            let mut j = i + 1;
            while j < chars.len() && (chars[j] == ZW_SPACE || chars[j] == ZW_NONJOIN) {
                bits.push(if chars[j] == ZW_SPACE { 0u8 } else { 1u8 });
                j += 1;
            }
            if j < chars.len() && chars[j] == ZW_JOIN && bits.len() == expected_bits {
                marks.push(bytes_from_bits(&bits));
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    marks
}

// -------------------------- L2: trailing whitespace --------------------------

/// Encode `mark_id` bits as trailing-space (0) vs trailing-tab (1) on the
/// first N lines that don't already have trailing whitespace.
pub fn embed_ws(text: &str, mark_id: &[u8]) -> String {
    let bits = bits_of(mark_id);
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out_lines = Vec::with_capacity(lines.len());
    let mut bi = 0usize;
    for line in lines {
        if bi < bits.len() && line.trim_end() == line {
            let suffix = if bits[bi] == 0 { ' ' } else { '\t' };
            out_lines.push(format!("{}{}", line, suffix));
            bi += 1;
        } else {
            out_lines.push(line.to_string());
        }
    }
    out_lines.join("\n")
}

/// Read the whitespace mark back out. Returns None if incomplete.
pub fn extract_ws(text: &str, mark_len_bytes: usize) -> Option<Vec<u8>> {
    let needed = mark_len_bytes * 8;
    let mut bits = Vec::with_capacity(needed);
    for line in text.split('\n') {
        if line.ends_with('\t') {
            bits.push(1u8);
        } else if line.ends_with(' ') {
            bits.push(0u8);
        }
        if bits.len() >= needed {
            break;
        }
    }
    if bits.len() < needed {
        None
    } else {
        bits.truncate(needed);
        Some(bytes_from_bits(&bits))
    }
}

// -------------------------- High-level --------------------------

pub fn apply_all(text: &str, mark_id: &[u8]) -> String {
    let t = embed_zw(text, mark_id, 40);
    embed_ws(&t, mark_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l1_round_trip() {
        let text = "The quick brown fox jumps over the lazy dog. ".repeat(20);
        let mark = new_mark_id(8);
        let marked = embed_zw(&text, &mark, 40);
        let recovered = extract_zw(&marked, 8);
        assert!(!recovered.is_empty(), "no marks recovered");
        assert_eq!(recovered[0], mark);
    }

    #[test]
    fn l2_round_trip() {
        let text = (0..80)
            .map(|i| format!("line {}", i))
            .collect::<Vec<_>>()
            .join("\n");
        let mark = new_mark_id(8);
        let marked = embed_ws(&text, &mark);
        let recovered = extract_ws(&marked, 8).unwrap();
        assert_eq!(recovered, mark);
    }

    #[test]
    fn l1_survives_copy_paste_but_l2_doesnt_always() {
        // Simulate copy-paste: ZW chars survive, trailing whitespace often doesn't
        let text = "Some body text that is long enough to hold a watermark. ".repeat(20);
        let mark = new_mark_id(8);
        let marked = apply_all(&text, &mark);
        // Strip trailing whitespace (lazy copy-paste)
        let no_trailing: String = marked
            .lines()
            .map(|l| l.trim_end())
            .collect::<Vec<_>>()
            .join("\n");
        // L1 should still recover the mark from the stripped text
        let recovered = extract_zw(&no_trailing, 8);
        assert!(recovered.contains(&mark));
        // L2 should NOT recover (stripped)
        assert!(extract_ws(&no_trailing, 8).is_none());
    }

    #[test]
    fn extract_zw_returns_empty_on_unmarked_text() {
        let text = "This text has no watermark in it.";
        let recovered = extract_zw(text, 8);
        assert!(recovered.is_empty());
    }
}
