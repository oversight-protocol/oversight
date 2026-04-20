//! # oversight-formats
//!
//! Format-specific watermarking adapters for the Oversight Protocol.
//!
//! Each adapter implements the `FormatAdapter` trait, providing embed/extract
//! for a specific document family. The core protocol (container, crypto,
//! manifest) is format-agnostic; these adapters let watermarking work on
//! more than plain text.
//!
//! ## Adapters
//!
//! - **text** -- L1 zero-width + L2 whitespace + L3 semantic (fully functional)
//! - **pdf** -- PDF metadata injection via `lopdf` (scaffold)
//! - **docx** -- Office OOXML core properties via `zip` + `quick-xml` (scaffold)
//! - **image** -- LSB embedding in Y channel (scaffold)
//!
//! ## Usage
//!
//! ```rust
//! use oversight_formats::{FormatRegistry, FormatAdapter};
//!
//! let registry = FormatRegistry::default();
//! let data = b"Hello, world!";
//! if let Some(adapter) = registry.detect(data) {
//!     println!("Detected format: {}", adapter.name());
//! }
//! ```

use thiserror::Error;

#[cfg(feature = "text")]
pub mod text;

#[cfg(feature = "pdf")]
pub mod pdf;

#[cfg(feature = "docx")]
pub mod docx;

#[cfg(feature = "image_fmt")]
pub mod image;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by format adapters.
#[derive(Debug, Error)]
pub enum FormatError {
    #[error("unsupported format: {0}")]
    Unsupported(String),

    #[error("malformed input: {0}")]
    Malformed(String),

    #[error("watermark embedding failed: {0}")]
    EmbedFailed(String),

    #[error("watermark extraction failed: {0}")]
    ExtractFailed(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("UTF-8 decode error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("UTF-8 str error: {0}")]
    Utf8Str(#[from] std::str::Utf8Error),

    #[error("format-specific error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Watermark candidate
// ---------------------------------------------------------------------------

/// A watermark candidate recovered from a document.
#[derive(Debug, Clone)]
pub struct WatermarkCandidate {
    /// The recovered mark_id bytes.
    pub mark_id: Vec<u8>,
    /// Which layer produced this candidate (e.g. "L1", "L2", "L3", "metadata").
    pub layer: String,
    /// Confidence score (1.0 = certain, 0.0 = noise). For direct extraction
    /// layers (L1/L2/metadata) this is always 1.0; for correlation-based
    /// layers (L3/DCT) it reflects the match quality.
    pub confidence: f64,
}

// ---------------------------------------------------------------------------
// FormatAdapter trait
// ---------------------------------------------------------------------------

/// Trait implemented by each format-specific adapter.
///
/// All methods take raw byte slices so the caller never needs to know the
/// on-disk representation details.
pub trait FormatAdapter: Send + Sync {
    /// Human-readable name of this adapter (e.g. "text", "pdf").
    fn name(&self) -> &str;

    /// File extensions this adapter handles (lowercase, without dot).
    fn extensions(&self) -> &[&str];

    /// Sniff the first bytes of `data` to decide whether this adapter can
    /// handle the file. Adapters should check magic bytes / structure, not
    /// just file extension.
    fn can_handle(&self, data: &[u8]) -> bool;

    /// Embed a watermark (`mark_id`) into the document. Returns the
    /// modified document bytes.
    fn embed_watermark(&self, data: &[u8], mark_id: &[u8]) -> Result<Vec<u8>, FormatError>;

    /// Extract all watermark candidates from the document.
    fn extract_watermark(&self, data: &[u8]) -> Result<Vec<WatermarkCandidate>, FormatError>;

    /// Produce a normalized text representation suitable for content
    /// fingerprinting. Two documents with the same visible content should
    /// produce the same normalized string even if their binary
    /// representations differ (e.g. different PDF producers, different
    /// whitespace in DOCX XML).
    fn normalize_for_fingerprint(&self, data: &[u8]) -> Result<String, FormatError>;
}

// ---------------------------------------------------------------------------
// FormatRegistry
// ---------------------------------------------------------------------------

/// Registry of all available format adapters. Used by the CLI to auto-detect
/// input format and dispatch to the correct adapter.
pub struct FormatRegistry {
    adapters: Vec<Box<dyn FormatAdapter>>,
}

impl FormatRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            adapters: Vec::new(),
        }
    }

    /// Register a format adapter.
    pub fn register(&mut self, adapter: Box<dyn FormatAdapter>) {
        self.adapters.push(adapter);
    }

    /// Auto-detect the format of `data` by trying each registered adapter's
    /// `can_handle` method. Returns the first match.
    pub fn detect(&self, data: &[u8]) -> Option<&dyn FormatAdapter> {
        // Try binary-magic adapters first (PDF, DOCX/ZIP, image), then text last
        // since text's can_handle is very permissive (valid UTF-8).
        for adapter in &self.adapters {
            if adapter.name() != "text" && adapter.can_handle(data) {
                return Some(adapter.as_ref());
            }
        }
        // Fall back to text
        for adapter in &self.adapters {
            if adapter.name() == "text" && adapter.can_handle(data) {
                return Some(adapter.as_ref());
            }
        }
        None
    }

    /// Look up an adapter by file extension (lowercase, without dot).
    pub fn by_extension(&self, ext: &str) -> Option<&dyn FormatAdapter> {
        let ext_lower = ext.to_lowercase();
        for adapter in &self.adapters {
            if adapter.extensions().contains(&ext_lower.as_str()) {
                return Some(adapter.as_ref());
            }
        }
        None
    }

    /// Look up an adapter by name.
    pub fn by_name(&self, name: &str) -> Option<&dyn FormatAdapter> {
        for adapter in &self.adapters {
            if adapter.name() == name {
                return Some(adapter.as_ref());
            }
        }
        None
    }

    /// List all registered adapter names.
    pub fn adapter_names(&self) -> Vec<&str> {
        self.adapters.iter().map(|a| a.name()).collect()
    }
}

impl Default for FormatRegistry {
    /// Build a registry with all compiled-in adapters.
    fn default() -> Self {
        let mut reg = Self::new();

        #[cfg(feature = "pdf")]
        reg.register(Box::new(pdf::PdfAdapter));

        #[cfg(feature = "docx")]
        reg.register(Box::new(docx::DocxAdapter));

        #[cfg(feature = "image_fmt")]
        reg.register(Box::new(image::ImageAdapter));

        // Text goes last -- its can_handle is permissive (any valid UTF-8).
        #[cfg(feature = "text")]
        reg.register(Box::new(text::TextAdapter));

        reg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_has_adapters() {
        let reg = FormatRegistry::default();
        let names = reg.adapter_names();
        #[cfg(feature = "text")]
        assert!(names.contains(&"text"));
        #[cfg(feature = "pdf")]
        assert!(names.contains(&"pdf"));
        #[cfg(feature = "docx")]
        assert!(names.contains(&"docx"));
        #[cfg(feature = "image_fmt")]
        assert!(names.contains(&"image"));
    }

    #[test]
    fn detect_plain_text() {
        let reg = FormatRegistry::default();
        let data = b"Hello, this is plain text content.";
        let adapter = reg.detect(data);
        assert!(adapter.is_some());
        #[cfg(feature = "text")]
        assert_eq!(adapter.unwrap().name(), "text");
    }

    #[test]
    fn detect_pdf_magic() {
        let reg = FormatRegistry::default();
        let data = b"%PDF-1.4 fake pdf content";
        let adapter = reg.detect(data);
        assert!(adapter.is_some());
        #[cfg(feature = "pdf")]
        assert_eq!(adapter.unwrap().name(), "pdf");
    }

    #[test]
    fn detect_zip_magic_as_docx() {
        let reg = FormatRegistry::default();
        // PK\x03\x04 is ZIP magic (DOCX is a ZIP file)
        let data = b"PK\x03\x04 fake zip content";
        let adapter = reg.detect(data);
        assert!(adapter.is_some());
        #[cfg(feature = "docx")]
        assert_eq!(adapter.unwrap().name(), "docx");
    }

    #[test]
    fn by_extension_lookup() {
        let reg = FormatRegistry::default();
        #[cfg(feature = "text")]
        assert_eq!(reg.by_extension("txt").unwrap().name(), "text");
        #[cfg(feature = "pdf")]
        assert_eq!(reg.by_extension("pdf").unwrap().name(), "pdf");
        #[cfg(feature = "docx")]
        assert_eq!(reg.by_extension("docx").unwrap().name(), "docx");
        #[cfg(feature = "image_fmt")]
        assert_eq!(reg.by_extension("png").unwrap().name(), "image");
    }
}
