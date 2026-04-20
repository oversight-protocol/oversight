//! # PDF format adapter
//!
//! Embeds mark_id in PDF document metadata using annotation-layer injection.
//!
//! Two embedding locations (mirrors the Python `oversight_core.formats.pdf`):
//!   1. PDF `/Info` dictionary custom fields (`/OversightMark`, `/OversightIssuer`,
//!      `/OversightFileId`) -- fast to read, easy to strip.
//!   2. (Future) Invisible text watermark on every page via zero-width unicode
//!      in a hidden text object -- survives metadata stripping.
//!
//! ## Security constraints
//!
//! - **No executable content**: the adapter MUST NOT inject JavaScript (`/JS`),
//!   actions (`/AA`, `/OpenAction`), or form submissions. Only passive metadata
//!   and annotation-layer text are permitted.
//! - **No launch actions**: `/Launch`, `/URI` with non-https schemes, `/GoTo`
//!   to external files are all forbidden.
//!
//! ## Dependencies
//!
//! Uses the `lopdf` crate for low-level PDF object manipulation. This gives
//! full control over what gets written (unlike higher-level wrappers that
//! might inject unwanted objects).

use crate::{FormatAdapter, FormatError, WatermarkCandidate};
use lopdf::{Document, Object, StringFormat};

/// PDF `/Info` dictionary key for the oversight mark_id.
const METADATA_KEY: &str = "OversightMark";
/// PDF `/Info` dictionary key for the issuer ID.
const ISSUER_KEY: &str = "OversightIssuer";
/// PDF `/Info` dictionary key for the file ID.
const FILE_ID_KEY: &str = "OversightFileId";

/// PDF format adapter.
pub struct PdfAdapter;

impl FormatAdapter for PdfAdapter {
    fn name(&self) -> &str {
        "pdf"
    }

    fn extensions(&self) -> &[&str] {
        &["pdf"]
    }

    fn can_handle(&self, data: &[u8]) -> bool {
        // PDF magic: %PDF-
        data.len() >= 5 && &data[0..5] == b"%PDF-"
    }

    fn embed_watermark(&self, data: &[u8], mark_id: &[u8]) -> Result<Vec<u8>, FormatError> {
        embed_pdf_metadata(data, mark_id, None, None)
    }

    fn extract_watermark(&self, data: &[u8]) -> Result<Vec<WatermarkCandidate>, FormatError> {
        let meta = extract_pdf_metadata(data)?;
        let mut candidates = Vec::new();
        if let Some(mark_hex) = meta.mark_id {
            if let Ok(mark_bytes) = hex::decode(&mark_hex) {
                candidates.push(WatermarkCandidate {
                    mark_id: mark_bytes,
                    layer: "metadata".into(),
                    confidence: 1.0,
                });
            }
        }
        Ok(candidates)
    }

    fn normalize_for_fingerprint(&self, data: &[u8]) -> Result<String, FormatError> {
        extract_text_for_fingerprint(data)
    }
}

// ---------------------------------------------------------------------------
// Metadata extraction result
// ---------------------------------------------------------------------------

/// Oversight metadata extracted from a PDF.
#[derive(Debug, Clone, Default)]
pub struct PdfOversightMeta {
    pub mark_id: Option<String>,
    pub issuer_id: Option<String>,
    pub file_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Embed
// ---------------------------------------------------------------------------

/// Embed mark_id (and optional issuer/file IDs) into the PDF `/Info` dictionary.
///
/// SECURITY: This function only writes passive string metadata. It does NOT
/// inject JavaScript, actions, or any executable PDF objects.
pub fn embed_pdf_metadata(
    pdf_bytes: &[u8],
    mark_id: &[u8],
    issuer_id: Option<&str>,
    file_id: Option<&str>,
) -> Result<Vec<u8>, FormatError> {
    let mut doc = Document::load_mem(pdf_bytes)
        .map_err(|e| FormatError::Malformed(format!("PDF parse error: {}", e)))?;

    // Validate: refuse to process PDFs with JavaScript or launch actions.
    // This is defense-in-depth: we don't add them, but we also refuse to
    // be a vehicle for passing through existing malicious content.
    security_check(&doc)?;

    // Get or create the /Info dictionary
    // lopdf stores trailer info; we access it via the document's trailer
    let mark_hex = hex::encode(mark_id);

    // Set metadata fields in the document info dictionary
    doc.trailer.remove(b"Info"); // Remove old info reference if any

    let mut info_dict = lopdf::dictionary::Dictionary::new();
    info_dict.set(
        METADATA_KEY,
        Object::String(mark_hex.into_bytes(), StringFormat::Literal),
    );
    if let Some(issuer) = issuer_id {
        // Sanitize: strip any PDF-special characters from issuer_id
        let sanitized = sanitize_pdf_string(issuer);
        info_dict.set(
            ISSUER_KEY,
            Object::String(sanitized.into_bytes(), StringFormat::Literal),
        );
    }
    if let Some(fid) = file_id {
        let sanitized = sanitize_pdf_string(fid);
        info_dict.set(
            FILE_ID_KEY,
            Object::String(sanitized.into_bytes(), StringFormat::Literal),
        );
    }

    let info_id = doc.add_object(Object::Dictionary(info_dict));
    doc.trailer.set("Info", Object::Reference(info_id));

    let mut output = Vec::new();
    doc.save_to(&mut output)
        .map_err(|e| FormatError::EmbedFailed(format!("PDF write error: {}", e)))?;

    Ok(output)
}

// ---------------------------------------------------------------------------
// Extract
// ---------------------------------------------------------------------------

/// Extract Oversight metadata from the PDF `/Info` dictionary.
pub fn extract_pdf_metadata(pdf_bytes: &[u8]) -> Result<PdfOversightMeta, FormatError> {
    let doc = Document::load_mem(pdf_bytes)
        .map_err(|e| FormatError::Malformed(format!("PDF parse error: {}", e)))?;

    let mut meta = PdfOversightMeta::default();

    // Try to read the /Info dictionary from the trailer
    if let Ok(info_ref) = doc.trailer.get(b"Info") {
        if let Ok(info_id) = info_ref.as_reference() {
            if let Ok(info_obj) = doc.get_object(info_id) {
                if let Ok(dict) = info_obj.as_dict() {
                    meta.mark_id = get_string_from_dict(dict, METADATA_KEY);
                    meta.issuer_id = get_string_from_dict(dict, ISSUER_KEY);
                    meta.file_id = get_string_from_dict(dict, FILE_ID_KEY);
                }
            }
        }
    }

    Ok(meta)
}

/// Extract all text content from the PDF for fingerprinting and downstream
/// L1/L2/L3 watermark recovery.
///
/// TODO: Implement full text extraction using lopdf's content stream parsing.
/// For now, this extracts raw string objects from the PDF which captures
/// most text but may miss some layout-dependent content.
pub fn extract_text_for_fingerprint(pdf_bytes: &[u8]) -> Result<String, FormatError> {
    let doc = Document::load_mem(pdf_bytes)
        .map_err(|e| FormatError::Malformed(format!("PDF parse error: {}", e)))?;

    let mut text_parts: Vec<String> = Vec::new();

    // Iterate all pages and extract text from content streams
    for page_id in doc.page_iter() {
        if let Ok(content) = doc.get_page_content(page_id) {
            // The content stream is raw bytes; extract text between Tj/TJ operators
            // This is a simplified extraction -- full implementation would parse
            // the content stream operators properly.
            if let Ok(text) = String::from_utf8(content.clone()) {
                // Extract strings from Tj and TJ operators (simplified)
                for part in extract_text_from_content_stream(&text) {
                    text_parts.push(part);
                }
            }
        }
    }

    Ok(text_parts.join("\n"))
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

/// Validate that the PDF does not contain executable content.
///
/// We refuse to process PDFs with JavaScript or auto-launch actions to
/// prevent the adapter from being used as a vector for malicious content.
fn security_check(doc: &Document) -> Result<(), FormatError> {
    for (_id, obj) in doc.objects.iter() {
        if let Ok(dict) = obj.as_dict() {
            // Check for JavaScript
            if dict.has(b"JS") || dict.has(b"JavaScript") {
                return Err(FormatError::Malformed(
                    "PDF contains JavaScript -- refusing to process for security".into(),
                ));
            }
            // Check for auto-open actions
            if dict.has(b"OpenAction") || dict.has(b"AA") {
                // Check if the action is JavaScript-based
                if let Ok(action) = dict.get(b"OpenAction").or(dict.get(b"AA")) {
                    if let Ok(action_dict) = action.as_dict() {
                        if action_dict.has(b"JS") || action_dict.has(b"JavaScript") {
                            return Err(FormatError::Malformed(
                                "PDF contains JavaScript auto-action -- refusing to process".into(),
                            ));
                        }
                        // Check for Launch actions
                        if let Ok(s_type) = action_dict.get(b"S") {
                            if let Ok(name) = s_type.as_name_str() {
                                if name == "Launch" || name == "JavaScript" {
                                    return Err(FormatError::Malformed(
                                        "PDF contains Launch/JavaScript action -- refusing to process".into(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Sanitize a string for safe inclusion in PDF metadata.
/// Strips control characters and PDF-special delimiters that could cause injection.
fn sanitize_pdf_string(s: &str) -> String {
    s.chars()
        .filter(|c| {
            // Allow printable ASCII and common Unicode, reject control chars
            // and PDF-special characters that could break the string context.
            !c.is_control() && *c != '(' && *c != ')' && *c != '\\'
        })
        .collect()
}

/// Helper to get a string value from a PDF dictionary.
fn get_string_from_dict(dict: &lopdf::dictionary::Dictionary, key: &str) -> Option<String> {
    dict.get(key.as_bytes())
        .ok()
        .and_then(|obj| match obj {
            Object::String(bytes, _) => String::from_utf8(bytes.clone()).ok(),
            _ => None,
        })
}

/// Simplified text extraction from a PDF content stream.
///
/// Looks for `(text) Tj` and `[(text)] TJ` patterns. This is a best-effort
/// extraction; a complete implementation would use a proper PDF content
/// stream parser.
///
/// TODO: Replace with a proper content stream parser for production use.
fn extract_text_from_content_stream(content: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut i = 0;
    let chars: Vec<char> = content.chars().collect();
    while i < chars.len() {
        if chars[i] == '(' {
            // Find matching closing paren (handle nesting)
            let mut depth = 1;
            let mut j = i + 1;
            while j < chars.len() && depth > 0 {
                if chars[j] == '(' && (j == 0 || chars[j - 1] != '\\') {
                    depth += 1;
                } else if chars[j] == ')' && (j == 0 || chars[j - 1] != '\\') {
                    depth -= 1;
                }
                j += 1;
            }
            if depth == 0 {
                let text: String = chars[i + 1..j - 1].iter().collect();
                if !text.is_empty() {
                    parts.push(text);
                }
                i = j;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_adapter_can_handle() {
        let adapter = PdfAdapter;
        assert!(adapter.can_handle(b"%PDF-1.4 rest of pdf"));
        assert!(adapter.can_handle(b"%PDF-2.0"));
        assert!(!adapter.can_handle(b"PK\x03\x04"));
        assert!(!adapter.can_handle(b"Hello, world!"));
        assert!(!adapter.can_handle(b""));
    }

    #[test]
    fn pdf_adapter_extensions() {
        let adapter = PdfAdapter;
        assert_eq!(adapter.extensions(), &["pdf"]);
    }

    #[test]
    fn sanitize_pdf_string_strips_dangerous_chars() {
        assert_eq!(sanitize_pdf_string("hello(world)"), "helloworld");
        assert_eq!(sanitize_pdf_string("test\\injection"), "testinjection");
        assert_eq!(sanitize_pdf_string("normal text 123"), "normal text 123");
    }

    // Note: Full embed/extract round-trip tests require a valid PDF file.
    // These are integration tests that should be run with test fixtures.
    // The unit tests above verify the adapter's detection and sanitization logic.
}
