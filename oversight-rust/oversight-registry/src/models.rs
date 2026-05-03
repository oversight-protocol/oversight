//! Request/response types and database row types for the registry.

use serde::{Deserialize, Serialize};

// ---- Input size limits (reject oversized payloads) ----------------------

/// Maximum length of a file_id, token_id, mark_id, or similar identifier.
pub const MAX_ID_LEN: usize = 256;
/// Maximum length of a canonical manifest JSON blob.
pub const MAX_MANIFEST_JSON_LEN: usize = 256 * 1024; // 256 KiB
/// Maximum number of beacons in a single registration.
pub const MAX_BEACONS: usize = 500;
/// Maximum number of watermarks in a single registration.
pub const MAX_WATERMARKS: usize = 500;
/// Maximum number of corpus hash entries in a single registration.
pub const MAX_CORPUS_ENTRIES: usize = 64;

// ---- Request types ------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub manifest: serde_json::Value,
    pub beacons: Vec<serde_json::Value>,
    pub watermarks: Vec<serde_json::Value>,
    #[serde(default)]
    pub corpus: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionQuery {
    pub token_id: Option<String>,
    pub mark_id: Option<String>,
    pub layer: Option<String>,
    pub perceptual_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEventRequest {
    pub token_id: String,
    pub client_ip: Option<String>,
    pub qtype: Option<String>,
    pub qname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct QueryParams {
    pub file_id: String,
}

// ---- Response types -----------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub ok: bool,
    pub file_id: String,
    pub registered_beacons: usize,
    pub tlog_index: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekor: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionResponse {
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_events: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
    pub tlog_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEventResponse {
    pub ok: bool,
    pub tlog_index: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watermarks: Option<Vec<WatermarkRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beacons: Option<Vec<BeaconRow>>,
}

// ---- DB row types -------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct BeaconRow {
    pub token_id: String,
    pub file_id: String,
    pub recipient_id: String,
    pub issuer_id: String,
    pub kind: String,
    pub registered_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WatermarkRow {
    pub mark_id: String,
    pub layer: String,
    pub file_id: String,
    pub recipient_id: String,
    pub issuer_id: String,
    pub registered_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ManifestRow {
    pub file_id: String,
    pub recipient_id: String,
    pub issuer_id: String,
    pub issuer_ed25519_pub: String,
    pub manifest_json: String,
    pub registered_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EventRow {
    pub id: i64,
    pub token_id: String,
    pub file_id: Option<String>,
    pub recipient_id: Option<String>,
    pub issuer_id: Option<String>,
    pub kind: String,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub extra: Option<String>,
    pub timestamp: i64,
    pub qualified_timestamp: Option<String>,
    pub tlog_index: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SemanticCandidateRow {
    pub mark_id: String,
    pub file_id: String,
    pub recipient_id: String,
    pub registered_at: i64,
}
