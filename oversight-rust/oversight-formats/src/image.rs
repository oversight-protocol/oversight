//! # Image format adapter
//!
//! LSB (Least Significant Bit) embedding in the Y (luma) channel of images.
//!
//! ## Algorithm
//!
//! The production Python adapter uses DCT-domain frequency watermarking (Cox
//! et al. spread-spectrum). This Rust adapter uses a simpler LSB approach for
//! the MVP, which is sufficient for controlled-distribution scenarios where
//! the image won't be heavily recompressed.
//!
//! ### Embed
//!   1. Decode image to RGB pixels.
//!   2. Convert each pixel to YCbCr; take the Y (luma) channel.
//!   3. Generate a deterministic bit sequence from `mark_id` using SHA-256.
//!   4. For each bit, modify the LSB of the corresponding Y-channel pixel.
//!   5. Convert back to RGB; encode as PNG (lossless).
//!
//! ### Extract
//!   1. Decode image to RGB; extract Y channel.
//!   2. Read LSBs from the same pixel positions.
//!   3. Reconstruct the mark_id from the bit sequence.
//!
//! ## Security constraints
//!
//! - **Imperceptible**: LSB modification changes pixel values by at most 1
//!   in the luma channel. This is invisible to the human eye (below the
//!   just-noticeable difference threshold of ~2-3 levels for 8-bit luma).
//! - **No executable content**: The adapter only modifies pixel data. No
//!   metadata, EXIF, ICC profiles, or ancillary chunks are injected.
//!
//! ## Survivability
//!
//! LSB embedding survives:
//!   - Format conversion (PNG <-> lossless formats)
//!   - Metadata stripping
//!
//! LSB embedding does NOT survive:
//!   - JPEG recompression (lossy)
//!   - Resizing / cropping
//!   - Any pixel-level transformation
//!
//! For JPEG-robust watermarking, use the DCT-domain approach from the Python
//! adapter (requires `rustdct` or `realfft` crates -- roadmap item).
//!
//! ## TODO (v0.7 roadmap)
//!
//! - [ ] Port the full Cox et al. DCT spread-spectrum watermark from Python
//! - [ ] Add perceptual hashing (pHash) for fuzzy leak-match
//! - [ ] Support JPEG output with quality parameter
//! - [ ] Add robustness testing against recompression

use crate::{FormatAdapter, FormatError, WatermarkCandidate};
use image::{DynamicImage, GenericImageView, ImageFormat, Pixel};
use sha2::{Digest, Sha256};
use std::io::Cursor;

/// Default mark_id length in bytes for extraction.
const MARK_LEN: usize = 8;

/// Magic header prepended to the embedded bitstream for reliable extraction.
/// Without a header, extraction from an unmarked image would produce garbage
/// that looks like a valid mark_id.
const MAGIC_HEADER: &[u8] = b"OS";

/// Image format adapter.
pub struct ImageAdapter;

impl FormatAdapter for ImageAdapter {
    fn name(&self) -> &str {
        "image"
    }

    fn extensions(&self) -> &[&str] {
        &["png", "jpg", "jpeg", "bmp", "tiff", "tif"]
    }

    fn can_handle(&self, data: &[u8]) -> bool {
        // PNG magic: 0x89 'P' 'N' 'G'
        if data.len() >= 4 && data[0] == 0x89 && &data[1..4] == b"PNG" {
            return true;
        }
        // JPEG magic: 0xFF 0xD8
        if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xD8 {
            return true;
        }
        // BMP magic: 'BM'
        if data.len() >= 2 && &data[0..2] == b"BM" {
            return true;
        }
        // TIFF magic: 'II' (little-endian) or 'MM' (big-endian)
        if data.len() >= 4 && (&data[0..2] == b"II" || &data[0..2] == b"MM") {
            return true;
        }
        false
    }

    fn embed_watermark(&self, data: &[u8], mark_id: &[u8]) -> Result<Vec<u8>, FormatError> {
        // Use blind-extract variant so extract_watermark works without
        // knowing the mark_id in advance.
        embed_lsb_blind(data, mark_id)
    }

    fn extract_watermark(&self, data: &[u8]) -> Result<Vec<WatermarkCandidate>, FormatError> {
        match extract_lsb(data, MARK_LEN) {
            Ok(Some(mark_id)) => Ok(vec![WatermarkCandidate {
                mark_id,
                layer: "lsb".into(),
                confidence: 1.0,
            }]),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    fn normalize_for_fingerprint(&self, data: &[u8]) -> Result<String, FormatError> {
        // For images, the "fingerprint" is a hex-encoded hash of the pixel
        // data (ignoring metadata/encoding differences).
        let img = load_image(data)?;
        let mut hasher = Sha256::new();
        for (_x, _y, pixel) in img.pixels() {
            let channels = pixel.channels();
            hasher.update(channels);
        }
        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }
}

// ---------------------------------------------------------------------------
// Image loading
// ---------------------------------------------------------------------------

fn load_image(data: &[u8]) -> Result<DynamicImage, FormatError> {
    image::load_from_memory(data)
        .map_err(|e| FormatError::Malformed(format!("image decode error: {}", e)))
}

// ---------------------------------------------------------------------------
// RGB <-> YCbCr conversion (integer approximation, BT.601)
// ---------------------------------------------------------------------------

/// Convert RGB to Y (luma) channel value.
/// Uses BT.601 coefficients: Y = 0.299*R + 0.587*G + 0.114*B
#[inline]
fn rgb_to_y(r: u8, g: u8, b: u8) -> u8 {
    let y = 0.299 * r as f64 + 0.587 * g as f64 + 0.114 * b as f64;
    y.round().min(255.0).max(0.0) as u8
}

/// Adjust an RGB pixel so that its Y-channel LSB matches `target_bit`.
///
/// We modify only the green channel (highest Y contribution at 0.587) by
/// +/- 1. This produces the smallest perceptual change since human vision
/// is most sensitive to luma, and modifying green by 1 changes Y by ~0.587,
/// which rounds to at most 1 level.
///
/// Returns (r, g, b) with the modification applied. The change is
/// imperceptible: at most 1 level in one channel.
#[inline]
fn set_y_lsb(r: u8, g: u8, b: u8, target_bit: u8) -> (u8, u8, u8) {
    let y = rgb_to_y(r, g, b);
    if (y & 1) == target_bit {
        return (r, g, b); // Already correct
    }
    // Need to flip the Y LSB. Adjust green by +1 or -1.
    let new_g = if g < 255 { g + 1 } else { g - 1 };
    // Verify the flip happened; if not (edge case), try adjusting red.
    let new_y = rgb_to_y(r, new_g, b);
    if (new_y & 1) == target_bit {
        return (r, new_g, b);
    }
    // Fallback: adjust red
    let new_r = if r < 255 { r + 1 } else { r - 1 };
    (new_r, g, b)
}

// ---------------------------------------------------------------------------
// Deterministic bit sequence from mark_id
// ---------------------------------------------------------------------------

/// Generate a deterministic sequence of pixel positions from mark_id + image
/// dimensions. Uses SHA-256(mark_id || counter) to select positions.
///
/// We embed in a pseudo-random scatter pattern rather than sequential pixels
/// to make the watermark harder to locate and strip.
fn pixel_positions(mark_id: &[u8], width: u32, height: u32, count: usize) -> Vec<(u32, u32)> {
    let total_pixels = (width as u64) * (height as u64);
    let mut positions = Vec::with_capacity(count);
    let mut counter: u64 = 0;

    while positions.len() < count {
        let mut h = Sha256::new();
        h.update(b"oversight-image-pos-v1");
        h.update(mark_id);
        h.update(&counter.to_be_bytes());
        let digest = h.finalize();

        // Each 8-byte chunk of the hash gives us one position
        for chunk in digest.chunks(8) {
            if positions.len() >= count || chunk.len() < 8 {
                break;
            }
            let val = u64::from_be_bytes(chunk.try_into().unwrap());
            let idx = val % total_pixels;
            let x = (idx % width as u64) as u32;
            let y = (idx / width as u64) as u32;
            positions.push((x, y));
        }
        counter += 1;
    }

    positions
}

// ---------------------------------------------------------------------------
// Embed
// ---------------------------------------------------------------------------

/// Embed mark_id into the image using Y-channel LSB modification.
///
/// The embedded payload is: MAGIC_HEADER || mark_id
/// Each bit of the payload is stored in the LSB of the Y channel of a
/// pseudo-randomly selected pixel.
///
/// Output is always PNG (lossless) to preserve the watermark.
pub fn embed_lsb(image_bytes: &[u8], mark_id: &[u8]) -> Result<Vec<u8>, FormatError> {
    let img = load_image(image_bytes)?;
    let (width, height) = img.dimensions();

    // Build payload: magic header + mark_id
    let mut payload = Vec::with_capacity(MAGIC_HEADER.len() + mark_id.len());
    payload.extend_from_slice(MAGIC_HEADER);
    payload.extend_from_slice(mark_id);

    let total_bits = payload.len() * 8;
    let total_pixels = (width as u64) * (height as u64);

    if total_bits as u64 > total_pixels {
        return Err(FormatError::EmbedFailed(format!(
            "image too small: need {} pixels for {} payload bits, have {}",
            total_bits, payload.len(), total_pixels
        )));
    }

    let positions = pixel_positions(mark_id, width, height, total_bits);
    let bits = bytes_to_bits(&payload);

    let mut rgba_img = img.to_rgba8();

    for (pos, &bit) in positions.iter().zip(bits.iter()) {
        let (x, y) = *pos;
        let pixel = rgba_img.get_pixel(x, y);
        let [r, g, b, a] = pixel.0;
        let (nr, ng, nb) = set_y_lsb(r, g, b, bit);
        rgba_img.put_pixel(x, y, image::Rgba([nr, ng, nb, a]));
    }

    // Encode as PNG
    let mut output = Cursor::new(Vec::new());
    rgba_img
        .write_to(&mut output, ImageFormat::Png)
        .map_err(|e| FormatError::EmbedFailed(format!("PNG encode error: {}", e)))?;

    Ok(output.into_inner())
}

// ---------------------------------------------------------------------------
// Extract
// ---------------------------------------------------------------------------

/// Extract mark_id from Y-channel LSBs.
///
/// Returns `Ok(Some(mark_id))` if the magic header is found, `Ok(None)` if
/// the image doesn't appear to be watermarked, or `Err` on decode failure.
pub fn extract_lsb(
    image_bytes: &[u8],
    expected_mark_len: usize,
) -> Result<Option<Vec<u8>>, FormatError> {
    let img = load_image(image_bytes)?;
    let (width, height) = img.dimensions();

    let payload_len = MAGIC_HEADER.len() + expected_mark_len;
    let total_bits = payload_len * 8;
    let total_pixels = (width as u64) * (height as u64);

    if total_bits as u64 > total_pixels {
        return Ok(None); // Image too small to contain a watermark
    }

    // We need a mark_id to derive positions, but we don't know it yet.
    // For extraction, we need to try candidate mark_ids. However, for the
    // self-contained extraction case, we use a fixed position sequence
    // derived from just the magic header.
    //
    // Actually, the embed function uses mark_id-derived positions, which
    // means extraction requires knowing (or guessing) the mark_id.
    // For blind extraction, we use a fixed seed instead.

    // Use a fixed extraction seed for blind extraction
    let fixed_seed = b"oversight-blind-extract-v1";
    let positions = pixel_positions(fixed_seed, width, height, total_bits);

    let rgba_img = img.to_rgba8();
    let mut bits = Vec::with_capacity(total_bits);

    for &(x, y) in &positions {
        let pixel = rgba_img.get_pixel(x, y);
        let [r, g, b, _a] = pixel.0;
        let y_val = rgb_to_y(r, g, b);
        bits.push(y_val & 1);
    }

    let payload = bits_to_bytes(&bits);

    // Check magic header
    if payload.len() >= MAGIC_HEADER.len() && &payload[..MAGIC_HEADER.len()] == MAGIC_HEADER {
        let mark_id = payload[MAGIC_HEADER.len()..].to_vec();
        Ok(Some(mark_id))
    } else {
        Ok(None) // No valid watermark found
    }
}

/// Embed with fixed-seed positions (for blind extraction support).
///
/// This variant uses a fixed seed for position selection so that extraction
/// does not require knowing the mark_id in advance.
pub fn embed_lsb_blind(image_bytes: &[u8], mark_id: &[u8]) -> Result<Vec<u8>, FormatError> {
    let img = load_image(image_bytes)?;
    let (width, height) = img.dimensions();

    let mut payload = Vec::with_capacity(MAGIC_HEADER.len() + mark_id.len());
    payload.extend_from_slice(MAGIC_HEADER);
    payload.extend_from_slice(mark_id);

    let total_bits = payload.len() * 8;
    let total_pixels = (width as u64) * (height as u64);

    if total_bits as u64 > total_pixels {
        return Err(FormatError::EmbedFailed(format!(
            "image too small: need {} pixels for {} payload bits, have {}",
            total_bits, payload.len(), total_pixels
        )));
    }

    // Use fixed seed for blind extraction
    let fixed_seed = b"oversight-blind-extract-v1";
    let positions = pixel_positions(fixed_seed, width, height, total_bits);
    let bits = bytes_to_bits(&payload);

    let mut rgba_img = img.to_rgba8();

    for (pos, &bit) in positions.iter().zip(bits.iter()) {
        let (x, y) = *pos;
        let pixel = rgba_img.get_pixel(x, y);
        let [r, g, b, a] = pixel.0;
        let (nr, ng, nb) = set_y_lsb(r, g, b, bit);
        rgba_img.put_pixel(x, y, image::Rgba([nr, ng, nb, a]));
    }

    let mut output = Cursor::new(Vec::new());
    rgba_img
        .write_to(&mut output, ImageFormat::Png)
        .map_err(|e| FormatError::EmbedFailed(format!("PNG encode error: {}", e)))?;

    Ok(output.into_inner())
}

// ---------------------------------------------------------------------------
// Bit manipulation helpers
// ---------------------------------------------------------------------------

fn bytes_to_bits(data: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(data.len() * 8);
    for byte in data {
        for i in 0..8 {
            bits.push((byte >> (7 - i)) & 1);
        }
    }
    bits
}

fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_adapter_can_handle() {
        let adapter = ImageAdapter;
        // PNG
        assert!(adapter.can_handle(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]));
        // JPEG
        assert!(adapter.can_handle(&[0xFF, 0xD8, 0xFF, 0xE0]));
        // BMP
        assert!(adapter.can_handle(b"BM\x00\x00"));
        // Not an image
        assert!(!adapter.can_handle(b"%PDF-1.4"));
        assert!(!adapter.can_handle(b"Hello!"));
        assert!(!adapter.can_handle(b""));
    }

    #[test]
    fn image_adapter_extensions() {
        let adapter = ImageAdapter;
        let exts = adapter.extensions();
        assert!(exts.contains(&"png"));
        assert!(exts.contains(&"jpg"));
        assert!(exts.contains(&"jpeg"));
        assert!(exts.contains(&"bmp"));
    }

    #[test]
    fn bytes_bits_round_trip() {
        let data = b"Hello";
        let bits = bytes_to_bits(data);
        assert_eq!(bits.len(), 40);
        let recovered = bits_to_bytes(&bits);
        assert_eq!(recovered, data);
    }

    #[test]
    fn y_channel_lsb_flip() {
        // Test that set_y_lsb correctly sets the LSB
        let (r, g, b) = (128, 128, 128);
        let y = rgb_to_y(r, g, b);
        let target = (y & 1) ^ 1; // Flip the current LSB
        let (nr, ng, nb) = set_y_lsb(r, g, b, target);
        let new_y = rgb_to_y(nr, ng, nb);
        assert_eq!(new_y & 1, target, "LSB should be flipped");
        // Verify the change is minimal
        assert!(
            (nr as i16 - r as i16).abs() <= 1
                && (ng as i16 - g as i16).abs() <= 1
                && (nb as i16 - b as i16).abs() <= 1,
            "pixel change should be at most 1 per channel"
        );
    }

    #[test]
    fn blind_embed_extract_round_trip() {
        // Create a small test image (32x32 white)
        let img = image::RgbaImage::from_fn(32, 32, |_x, _y| {
            image::Rgba([200, 200, 200, 255])
        });
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImageFormat::Png).unwrap();
        let png_bytes = buf.into_inner();

        let mark_id = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe";
        let marked = embed_lsb_blind(&png_bytes, mark_id).unwrap();

        // Verify the output is valid PNG
        assert!(marked.len() > 8);
        assert_eq!(&marked[1..4], b"PNG");

        // Extract
        let extracted = extract_lsb(&marked, 8).unwrap();
        assert!(extracted.is_some(), "should find watermark");
        assert_eq!(extracted.unwrap(), mark_id);
    }

    #[test]
    fn extract_from_unmarked_image() {
        // Create a test image with no watermark
        let img = image::RgbaImage::from_fn(32, 32, |x, y| {
            image::Rgba([(x * 8) as u8, (y * 8) as u8, 128, 255])
        });
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImageFormat::Png).unwrap();
        let png_bytes = buf.into_inner();

        let extracted = extract_lsb(&png_bytes, 8).unwrap();
        // Very likely None since random pixels won't have our magic header
        // (probability of false positive: 2^-16 per attempt)
        assert!(extracted.is_none(), "unmarked image should not yield a watermark");
    }

    #[test]
    fn pixel_imperceptibility() {
        // Verify that LSB embedding doesn't change pixels by more than 1 level
        let img = image::RgbaImage::from_fn(64, 64, |x, y| {
            let r = ((x * 4) % 256) as u8;
            let g = ((y * 4) % 256) as u8;
            let b = (((x + y) * 2) % 256) as u8;
            image::Rgba([r, g, b, 255])
        });
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImageFormat::Png).unwrap();
        let original_bytes = buf.into_inner();

        let mark_id = b"\x01\x02\x03\x04\x05\x06\x07\x08";
        let marked_bytes = embed_lsb_blind(&original_bytes, mark_id).unwrap();

        let original = image::load_from_memory(&original_bytes).unwrap().to_rgba8();
        let marked = image::load_from_memory(&marked_bytes).unwrap().to_rgba8();

        let (w, h) = original.dimensions();
        let mut max_diff: i16 = 0;
        for y in 0..h {
            for x in 0..w {
                let op = original.get_pixel(x, y).0;
                let mp = marked.get_pixel(x, y).0;
                for c in 0..3 {
                    let diff = (op[c] as i16 - mp[c] as i16).abs();
                    if diff > max_diff {
                        max_diff = diff;
                    }
                }
            }
        }
        assert!(
            max_diff <= 1,
            "maximum pixel difference should be <= 1, got {}",
            max_diff
        );
    }
}
