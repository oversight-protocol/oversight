//! # oversight-manifest
//!
//! The signed metadata that binds a sealed file to its recipient, watermarks,
//! beacons, and policy. It's the artifact a registry stores and a verifier checks.
//!
//! Wire format: canonical JSON (JCS, RFC 8785), UTF-8, Ed25519-signed.

use oversight_crypto::{self as crypto, CryptoError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("signature missing or empty")]
    MissingSignature,
    #[error("issuer pubkey missing or empty")]
    MissingIssuer,
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("canonicalization failed")]
    Canonicalization,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Recipient {
    pub recipient_id: String,
    pub x25519_pub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed25519_pub: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatermarkRef {
    pub layer: String,
    pub mark_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Manifest {
    pub file_id: String,
    pub issued_at: i64,
    pub version: String,
    pub suite: String,
    pub original_filename: String,
    pub content_hash: String,
    pub content_type: String,
    pub size_bytes: u64,
    pub issuer_id: String,
    pub issuer_ed25519_pub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<Recipient>,
    pub watermarks: Vec<WatermarkRef>,
    pub beacons: Vec<serde_json::Value>,
    pub policy: serde_json::Value,
    pub signature_ed25519: String,
    pub signature_ml_dsa: String,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            file_id: String::new(),
            issued_at: 0,
            version: "OVERSIGHT-v1".into(),
            suite: crypto::SUITE_CLASSIC_V1.into(),
            original_filename: String::new(),
            content_hash: String::new(),
            content_type: "application/octet-stream".into(),
            size_bytes: 0,
            issuer_id: String::new(),
            issuer_ed25519_pub: String::new(),
            recipient: None,
            watermarks: Vec::new(),
            beacons: Vec::new(),
            policy: serde_json::json!({}),
            signature_ed25519: String::new(),
            signature_ml_dsa: String::new(),
        }
    }
}

impl Manifest {
    pub fn new(
        original_filename: impl Into<String>,
        content_hash: impl Into<String>,
        size_bytes: u64,
        issuer_id: impl Into<String>,
        issuer_ed25519_pub_hex: impl Into<String>,
        recipient: Recipient,
        registry_url: impl Into<String>,
        content_type: impl Into<String>,
        not_after: Option<i64>,
        max_opens: Option<u64>,
        jurisdiction: impl Into<String>,
    ) -> Self {
        let mut policy = serde_json::json!({
            "registry_url": registry_url.into(),
            "jurisdiction": jurisdiction.into(),
        });
        if let Some(na) = not_after {
            policy["not_after"] = serde_json::json!(na);
        }
        if let Some(mx) = max_opens {
            policy["max_opens"] = serde_json::json!(mx);
        }

        Self {
            file_id: uuid::Uuid::new_v4().to_string(),
            issued_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            original_filename: original_filename.into(),
            content_hash: content_hash.into(),
            content_type: content_type.into(),
            size_bytes,
            issuer_id: issuer_id.into(),
            issuer_ed25519_pub: issuer_ed25519_pub_hex.into(),
            recipient: Some(recipient),
            policy,
            ..Default::default()
        }
    }

    /// Canonical bytes (excluding signatures) — this is what gets signed.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        let mut v = serde_json::to_value(self)?;
        // Strip signatures before canonicalizing.
        if let Some(obj) = v.as_object_mut() {
            obj.insert("signature_ed25519".into(), serde_json::json!(""));
            obj.insert("signature_ml_dsa".into(), serde_json::json!(""));
        }
        serde_jcs::to_vec(&v).map_err(|_| ManifestError::Canonicalization)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, ManifestError> {
        let v = serde_json::to_value(self)?;
        serde_jcs::to_vec(&v).map_err(|_| ManifestError::Canonicalization)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, ManifestError> {
        let m: Manifest = serde_json::from_slice(bytes)?;
        Ok(m)
    }

    pub fn sign(&mut self, issuer_ed25519_priv: &[u8]) -> Result<(), ManifestError> {
        let bytes = self.canonical_bytes()?;
        let sig = crypto::sign_message(&bytes, issuer_ed25519_priv)?;
        self.signature_ed25519 = hex::encode(sig);
        Ok(())
    }

    pub fn verify(&self) -> Result<bool, ManifestError> {
        if self.signature_ed25519.is_empty() {
            return Ok(false);
        }
        if self.issuer_ed25519_pub.is_empty() {
            return Ok(false);
        }
        let bytes = self.canonical_bytes()?;
        let sig = hex::decode(&self.signature_ed25519)?;
        let pub_key = hex::decode(&self.issuer_ed25519_pub)?;
        Ok(crypto::verify_message(&bytes, &sig, &pub_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oversight_crypto::ClassicIdentity;

    #[test]
    fn sign_verify_round_trip() {
        let issuer = ClassicIdentity::generate();
        let recipient = ClassicIdentity::generate();

        let mut m = Manifest::new(
            "doc.txt",
            crypto::content_hash(b"hello world"),
            11,
            "issuer@test",
            hex::encode(issuer.ed25519_pub),
            Recipient {
                recipient_id: "alice@test".into(),
                x25519_pub: hex::encode(recipient.x25519_pub),
                ed25519_pub: None,
            },
            "https://registry.test",
            "text/plain",
            None,
            None,
            "GLOBAL",
        );

        m.sign(issuer.ed25519_priv.as_ref()).unwrap();
        assert!(m.verify().unwrap());

        // Tamper: mutate content_hash
        m.content_hash = "tampered".into();
        assert!(!m.verify().unwrap());
    }

    #[test]
    fn json_round_trip() {
        let issuer = ClassicIdentity::generate();
        let recipient = ClassicIdentity::generate();
        let mut m = Manifest::new(
            "doc.txt",
            "abc123",
            42,
            "issuer@test",
            hex::encode(issuer.ed25519_pub),
            Recipient {
                recipient_id: "alice@test".into(),
                x25519_pub: hex::encode(recipient.x25519_pub),
                ed25519_pub: None,
            },
            "https://registry.test",
            "text/plain",
            None,
            None,
            "GLOBAL",
        );
        m.sign(issuer.ed25519_priv.as_ref()).unwrap();

        let bytes = m.to_json().unwrap();
        let parsed = Manifest::from_json(&bytes).unwrap();
        assert_eq!(m, parsed);
        assert!(parsed.verify().unwrap());
    }
}
