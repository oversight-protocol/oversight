//! # DOCX format adapter
//!
//! Embeds mark_id in Office OOXML (DOCX) files via two mechanisms:
//!
//!   1. **Core properties** (`docProps/core.xml`) -- `keywords` field with an
//!      `oversight:` prefix. Semi-visible in Word's document properties dialog.
//!   2. (Future) **Custom XML part** -- not visible in normal Word UI.
//!
//! For strong cross-format survival, apply L1/L2/L3 text watermarking to the
//! body text before packaging as DOCX. The XML marks are a secondary layer
//! that's easy to strip but fast to read.
//!
//! ## Security constraints
//!
//! - **Field code sanitization**: All injected strings are sanitized against
//!   OOXML field-code injection. Characters like `{`, `}`, `\`, and XML
//!   special characters are stripped or escaped.
//! - **No macros**: The adapter MUST NOT inject VBA macros, ActiveX controls,
//!   or OLE objects.
//! - **No external references**: No external hyperlinks, OLE links, or
//!   data connections are injected.
//!
//! ## Dependencies
//!
//! Uses `zip` for reading/writing the OOXML ZIP container, and `quick-xml`
//! for parsing and modifying the XML parts inside.

use crate::{FormatAdapter, FormatError, WatermarkCandidate};

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use std::io::Cursor;
use zip::read::ZipArchive;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

/// Prefix used in the `keywords` core property to store the oversight mark.
const OVERSIGHT_PREFIX: &str = "oversight:";

/// DOCX format adapter.
pub struct DocxAdapter;

impl FormatAdapter for DocxAdapter {
    fn name(&self) -> &str {
        "docx"
    }

    fn extensions(&self) -> &[&str] {
        &["docx"]
    }

    fn can_handle(&self, data: &[u8]) -> bool {
        // DOCX is a ZIP file. Check for ZIP magic bytes.
        // Further validation would check for [Content_Types].xml inside,
        // but ZIP magic is sufficient for detection dispatch.
        data.len() >= 4 && &data[0..4] == b"PK\x03\x04"
    }

    fn embed_watermark(&self, data: &[u8], mark_id: &[u8]) -> Result<Vec<u8>, FormatError> {
        embed_docx_metadata(data, mark_id, None, None)
    }

    fn extract_watermark(&self, data: &[u8]) -> Result<Vec<WatermarkCandidate>, FormatError> {
        let meta = extract_docx_metadata(data)?;
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
        extract_body_text(data)
    }
}

// ---------------------------------------------------------------------------
// Metadata types
// ---------------------------------------------------------------------------

/// Oversight metadata extracted from a DOCX file.
#[derive(Debug, Clone, Default)]
pub struct DocxOversightMeta {
    pub mark_id: Option<String>,
    pub issuer_id: Option<String>,
    pub file_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Embed
// ---------------------------------------------------------------------------

/// Embed mark_id into the DOCX `docProps/core.xml` keywords field.
///
/// The mark is stored as `oversight:<mark_id_hex>` in the `<cp:keywords>`
/// element, optionally followed by `;issuer:<id>` and `;fid:<id>`.
///
/// SECURITY: All injected values are sanitized against field-code injection
/// and XML injection before being written.
pub fn embed_docx_metadata(
    docx_bytes: &[u8],
    mark_id: &[u8],
    issuer_id: Option<&str>,
    file_id: Option<&str>,
) -> Result<Vec<u8>, FormatError> {
    let reader = Cursor::new(docx_bytes);
    let mut archive = ZipArchive::new(reader)
        .map_err(|e| FormatError::Malformed(format!("ZIP parse error: {}", e)))?;

    let output = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(output);

    // Build the oversight tag
    let mark_hex = hex::encode(mark_id);
    let mut tag = format!("{}{}", OVERSIGHT_PREFIX, sanitize_field_code(&mark_hex));
    if let Some(issuer) = issuer_id {
        tag.push_str(&format!(";issuer:{}", sanitize_field_code(issuer)));
    }
    if let Some(fid) = file_id {
        tag.push_str(&format!(";fid:{}", sanitize_field_code(fid)));
    }

    let mut found_core = false;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| FormatError::Internal(format!("ZIP entry error: {}", e)))?;
        let name = entry.name().to_string();

        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer
            .start_file(&name, options)
            .map_err(|e| FormatError::Internal(format!("ZIP write error: {}", e)))?;

        if name == "docProps/core.xml" {
            found_core = true;
            let mut contents = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut contents)
                .map_err(|e| FormatError::Io(e))?;
            let modified = inject_keywords_into_core_xml(&contents, &tag)?;
            std::io::Write::write_all(&mut writer, &modified)
                .map_err(|e| FormatError::Io(e))?;
        } else {
            // Copy entry unchanged
            let mut contents = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut contents)
                .map_err(|e| FormatError::Io(e))?;
            std::io::Write::write_all(&mut writer, &contents)
                .map_err(|e| FormatError::Io(e))?;
        }
    }

    // If there was no docProps/core.xml, create one
    if !found_core {
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer
            .start_file("docProps/core.xml", options)
            .map_err(|e| FormatError::Internal(format!("ZIP write error: {}", e)))?;
        let core_xml = create_minimal_core_xml(&tag);
        std::io::Write::write_all(&mut writer, core_xml.as_bytes())
            .map_err(|e| FormatError::Io(e))?;
    }

    let result = writer
        .finish()
        .map_err(|e| FormatError::Internal(format!("ZIP finish error: {}", e)))?;

    Ok(result.into_inner())
}

// ---------------------------------------------------------------------------
// Extract
// ---------------------------------------------------------------------------

/// Extract Oversight metadata from the DOCX `docProps/core.xml` keywords.
pub fn extract_docx_metadata(docx_bytes: &[u8]) -> Result<DocxOversightMeta, FormatError> {
    let reader = Cursor::new(docx_bytes);
    let mut archive = ZipArchive::new(reader)
        .map_err(|e| FormatError::Malformed(format!("ZIP parse error: {}", e)))?;

    let mut meta = DocxOversightMeta::default();

    // Try to read docProps/core.xml
    if let Ok(mut entry) = archive.by_name("docProps/core.xml") {
        let mut contents = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut contents)
            .map_err(|e| FormatError::Io(e))?;
        let keywords = extract_keywords_from_core_xml(&contents)?;
        if let Some(kw) = keywords {
            parse_oversight_tag(&kw, &mut meta);
        }
    }

    Ok(meta)
}

/// Extract all body text from the DOCX for fingerprinting and downstream
/// L1/L2/L3 watermark recovery.
///
/// Reads `word/document.xml` and extracts text from `<w:t>` elements.
pub fn extract_body_text(docx_bytes: &[u8]) -> Result<String, FormatError> {
    let reader = Cursor::new(docx_bytes);
    let mut archive = ZipArchive::new(reader)
        .map_err(|e| FormatError::Malformed(format!("ZIP parse error: {}", e)))?;

    let mut entry = archive
        .by_name("word/document.xml")
        .map_err(|e| FormatError::Malformed(format!("missing word/document.xml: {}", e)))?;

    let mut contents = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut contents)
        .map_err(|e| FormatError::Io(e))?;

    extract_text_elements(&contents)
}

// ---------------------------------------------------------------------------
// XML manipulation helpers
// ---------------------------------------------------------------------------

/// Inject an oversight tag into the `<cp:keywords>` element of core.xml.
///
/// If keywords already exist, appends with a space separator (unless an
/// oversight tag is already present).
fn inject_keywords_into_core_xml(xml_bytes: &[u8], tag: &str) -> Result<Vec<u8>, FormatError> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(false);

    let mut output = Vec::new();
    let mut xml_writer = Writer::new(Cursor::new(&mut output));

    let mut in_keywords = false;
    let mut found_keywords = false;
    let mut existing_keywords = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"cp:keywords" => {
                in_keywords = true;
                found_keywords = true;
                xml_writer
                    .write_event(Event::Start(e.clone()))
                    .map_err(|e| FormatError::Internal(format!("XML write error: {}", e)))?;
            }
            Ok(Event::Text(ref t)) if in_keywords => {
                existing_keywords =
                    t.unescape().unwrap_or_default().to_string();
                // Check if oversight tag already exists
                let new_kw = if existing_keywords.contains(OVERSIGHT_PREFIX) {
                    existing_keywords.clone()
                } else if existing_keywords.is_empty() {
                    tag.to_string()
                } else {
                    format!("{} {}", existing_keywords, tag)
                };
                xml_writer
                    .write_event(Event::Text(BytesText::new(&new_kw)))
                    .map_err(|e| FormatError::Internal(format!("XML write error: {}", e)))?;
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"cp:keywords" => {
                in_keywords = false;
                xml_writer
                    .write_event(Event::End(e.clone()))
                    .map_err(|e| FormatError::Internal(format!("XML write error: {}", e)))?;
            }
            Ok(Event::Eof) => break,
            Ok(e) => {
                xml_writer
                    .write_event(e)
                    .map_err(|err| FormatError::Internal(format!("XML write error: {}", err)))?;
            }
            Err(e) => {
                return Err(FormatError::Malformed(format!("XML parse error: {}", e)));
            }
        }
    }

    if !found_keywords {
        return insert_keywords_into_core_xml(xml_bytes, tag);
    }

    Ok(output)
}

fn insert_keywords_into_core_xml(xml_bytes: &[u8], tag: &str) -> Result<Vec<u8>, FormatError> {
    let xml = std::str::from_utf8(xml_bytes)
        .map_err(|e| FormatError::Malformed(format!("core.xml is not UTF-8: {}", e)))?;
    let keywords = format!(
        "<cp:keywords>{}</cp:keywords>",
        quick_xml::escape::escape(tag)
    );

    for closing in ["</cp:coreProperties>", "</coreProperties>"] {
        if let Some(idx) = xml.rfind(closing) {
            let mut out = String::with_capacity(xml.len() + keywords.len());
            out.push_str(&xml[..idx]);
            out.push_str(&keywords);
            out.push_str(&xml[idx..]);
            return Ok(out.into_bytes());
        }
    }

    Err(FormatError::Malformed(
        "docProps/core.xml missing coreProperties closing tag".into(),
    ))
}

/// Extract the text content of `<cp:keywords>` from core.xml.
fn extract_keywords_from_core_xml(xml_bytes: &[u8]) -> Result<Option<String>, FormatError> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(false);

    let mut in_keywords = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"cp:keywords" => {
                in_keywords = true;
            }
            Ok(Event::Text(ref t)) if in_keywords => {
                let text = t
                    .unescape()
                    .unwrap_or_default()
                    .to_string();
                return Ok(Some(text));
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"cp:keywords" => {
                in_keywords = false;
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(FormatError::Malformed(format!("XML parse error: {}", e)));
            }
            _ => {}
        }
    }

    Ok(None)
}

/// Extract all text from `<w:t>` elements in document.xml.
fn extract_text_elements(xml_bytes: &[u8]) -> Result<String, FormatError> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(false);

    let mut parts = Vec::new();
    let mut in_text = false;
    let mut in_paragraph = false;
    let mut paragraph_texts: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let local_name = e.name().as_ref().to_vec();
                if local_name.as_slice() == b"w:p" || local_name.ends_with(b":p") {
                    in_paragraph = true;
                    paragraph_texts.clear();
                } else if local_name.as_slice() == b"w:t" || local_name.ends_with(b":t") {
                    in_text = true;
                }
            }
            Ok(Event::Text(ref t)) if in_text => {
                let text = t
                    .unescape()
                    .unwrap_or_default()
                    .to_string();
                paragraph_texts.push(text);
            }
            Ok(Event::End(ref e)) => {
                let local_name = e.name().as_ref().to_vec();
                if local_name.as_slice() == b"w:t" || local_name.ends_with(b":t") {
                    in_text = false;
                } else if local_name.as_slice() == b"w:p" || local_name.ends_with(b":p") {
                    if in_paragraph && !paragraph_texts.is_empty() {
                        parts.push(paragraph_texts.join(""));
                    }
                    in_paragraph = false;
                    paragraph_texts.clear();
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(FormatError::Malformed(format!("XML parse error: {}", e)));
            }
            _ => {}
        }
    }

    Ok(parts.join("\n"))
}

/// Create a minimal `docProps/core.xml` with just the keywords element.
fn create_minimal_core_xml(keywords: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/"
                   xmlns:dcterms="http://purl.org/dc/terms/"
                   xmlns:dcmitype="http://purl.org/dc/dcmitype/"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <cp:keywords>{}</cp:keywords>
</cp:coreProperties>"#,
        quick_xml::escape::escape(keywords)
    )
}

/// Parse an oversight tag string like `oversight:abcdef;issuer:bob;fid:123`
/// into the metadata struct.
fn parse_oversight_tag(keywords: &str, meta: &mut DocxOversightMeta) {
    // The tag may be embedded in a longer keywords string; find the oversight: prefix
    for token in keywords.split_whitespace() {
        if token.starts_with(OVERSIGHT_PREFIX) || token.contains(OVERSIGHT_PREFIX) {
            // Parse semicolon-separated fields within this token
            let relevant = if let Some(idx) = token.find(OVERSIGHT_PREFIX) {
                &token[idx..]
            } else {
                continue;
            };
            for part in relevant.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("oversight:") {
                    meta.mark_id = Some(val.to_string());
                } else if let Some(val) = part.strip_prefix("issuer:") {
                    meta.issuer_id = Some(val.to_string());
                } else if let Some(val) = part.strip_prefix("fid:") {
                    meta.file_id = Some(val.to_string());
                }
            }
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

/// Sanitize a string for safe inclusion in DOCX field codes and XML.
///
/// Strips characters that could enable:
/// - OOXML field-code injection (`{`, `}`, `\` as field switch prefix)
/// - XML injection (`<`, `>`, `&`, `"`, `'`)
/// - Control characters
pub fn sanitize_field_code(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control()
                && *c != '{'
                && *c != '}'
                && *c != '\\'
                && *c != '<'
                && *c != '>'
                && *c != '&'
                && *c != '"'
                && *c != '\''
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docx_adapter_can_handle() {
        let adapter = DocxAdapter;
        assert!(adapter.can_handle(b"PK\x03\x04 rest of zip"));
        assert!(!adapter.can_handle(b"%PDF-1.4"));
        assert!(!adapter.can_handle(b"Hello, world!"));
        assert!(!adapter.can_handle(b""));
    }

    #[test]
    fn docx_adapter_extensions() {
        let adapter = DocxAdapter;
        assert_eq!(adapter.extensions(), &["docx"]);
    }

    #[test]
    fn sanitize_field_code_strips_dangerous() {
        assert_eq!(sanitize_field_code("normal text"), "normal text");
        assert_eq!(sanitize_field_code("{FIELD \\s}"), "FIELD s");
        assert_eq!(sanitize_field_code("<script>alert('x')</script>"), "scriptalert(x)/script");
        assert_eq!(sanitize_field_code("hello&world"), "helloworld");
    }

    #[test]
    fn parse_oversight_tag_basic() {
        let mut meta = DocxOversightMeta::default();
        parse_oversight_tag("oversight:deadbeef;issuer:bob;fid:abc123", &mut meta);
        assert_eq!(meta.mark_id.as_deref(), Some("deadbeef"));
        assert_eq!(meta.issuer_id.as_deref(), Some("bob"));
        assert_eq!(meta.file_id.as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_oversight_tag_with_other_keywords() {
        let mut meta = DocxOversightMeta::default();
        parse_oversight_tag("finance report oversight:cafebabe;issuer:alice quarterly", &mut meta);
        assert_eq!(meta.mark_id.as_deref(), Some("cafebabe"));
        assert_eq!(meta.issuer_id.as_deref(), Some("alice"));
    }

    #[test]
    fn parse_oversight_tag_no_match() {
        let mut meta = DocxOversightMeta::default();
        parse_oversight_tag("just some keywords", &mut meta);
        assert!(meta.mark_id.is_none());
        assert!(meta.issuer_id.is_none());
        assert!(meta.file_id.is_none());
    }

    #[test]
    fn minimal_core_xml_valid() {
        let xml = create_minimal_core_xml("oversight:abcdef");
        assert!(xml.contains("cp:keywords"));
        assert!(xml.contains("oversight:abcdef"));
        assert!(xml.contains("<?xml"));
    }

    #[test]
    fn inject_keywords_adds_missing_element() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">
  <dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">Report</dc:title>
</cp:coreProperties>"#;
        let out = inject_keywords_into_core_xml(xml, "oversight:abcdef").unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("<cp:keywords>oversight:abcdef</cp:keywords>"));
        assert!(s.contains("</cp:coreProperties>"));
    }
}
