//! POST /register — store manifest, beacons, watermarks with signature verification.
//!
//! Security invariants:
//!   1. The manifest's Ed25519 signature MUST verify.
//!   2. Request sidecars must exactly match the signed manifest's copies.
//!   3. Re-registration of a file_id requires the same issuer pubkey.
//!   4. All inputs are size-validated before processing.

use axum::extract::State;
use axum::Json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::{validate_signed_artifacts, verify_manifest_signature};
use crate::db;
use crate::error::{RegistryError, Result};
use crate::models::*;
use crate::AppState;

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegistrationRequest>,
) -> Result<Json<RegistrationResponse>> {
    // ---- Input validation ----
    let manifest = &req.manifest;

    let file_id = manifest
        .get("file_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RegistryError::BadRequest("manifest missing file_id".into()))?;

    if file_id.len() > MAX_ID_LEN {
        return Err(RegistryError::BadRequest("file_id too long".into()));
    }

    if req.beacons.len() > MAX_BEACONS {
        return Err(RegistryError::BadRequest(format!(
            "too many beacons (max {})",
            MAX_BEACONS
        )));
    }
    if req.watermarks.len() > MAX_WATERMARKS {
        return Err(RegistryError::BadRequest(format!(
            "too many watermarks (max {})",
            MAX_WATERMARKS
        )));
    }

    // Validate manifest JSON size
    let manifest_json = serde_json::to_string(manifest)
        .map_err(|e| RegistryError::BadRequest(format!("manifest serialization: {e}")))?;
    if manifest_json.len() > MAX_MANIFEST_JSON_LEN {
        return Err(RegistryError::BadRequest("manifest too large".into()));
    }

    let recipient = manifest.get("recipient");
    let recipient_id = recipient
        .and_then(|r| r.get("recipient_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let issuer_id = manifest
        .get("issuer_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    if recipient_id.len() > MAX_ID_LEN || issuer_id.len() > MAX_ID_LEN {
        return Err(RegistryError::BadRequest("identifier too long".into()));
    }

    // ---- Signature verification ----
    let (sig_ok, issuer_pub) = verify_manifest_signature(manifest);
    if !sig_ok {
        return Err(RegistryError::BadRequest(
            "manifest signature invalid".into(),
        ));
    }
    if issuer_pub.is_empty() {
        return Err(RegistryError::BadRequest(
            "manifest missing issuer_ed25519_pub".into(),
        ));
    }

    // ---- v0.4.4 hardening: validate sidecars match signed manifest ----
    let (signed_beacons, signed_watermarks) =
        validate_signed_artifacts(manifest, &req.beacons, &req.watermarks)
            .map_err(RegistryError::BadRequest)?;

    // ---- Check existing issuer ----
    let existing_pub = db::get_manifest_issuer_pub(&state.db, file_id).await?;
    if let Some(ref existing) = existing_pub {
        if existing != &issuer_pub {
            let claimed_prefix = &issuer_pub[..issuer_pub.len().min(16)];
            let existing_prefix = &existing[..existing.len().min(16)];
            return Err(RegistryError::Conflict(format!(
                "file_id already registered under a different issuer pubkey (claimed={claimed_prefix}..., existing={existing_prefix}...)"
            )));
        }
    }

    // ---- Persist ----
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    db::upsert_manifest(
        &state.db,
        file_id,
        recipient_id,
        issuer_id,
        &issuer_pub,
        &manifest_json,
        now,
    )
    .await?;

    for beacon in &signed_beacons {
        let token_id = beacon
            .get("token_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let kind = beacon
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if token_id.is_empty() || token_id.len() > MAX_ID_LEN {
            continue;
        }
        db::upsert_beacon(&state.db, token_id, file_id, recipient_id, issuer_id, kind, now)
            .await?;
    }

    for watermark in &signed_watermarks {
        let mark_id = watermark
            .get("mark_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let layer = watermark
            .get("layer")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if mark_id.is_empty() || mark_id.len() > MAX_ID_LEN {
            continue;
        }
        db::upsert_watermark(&state.db, mark_id, layer, file_id, recipient_id, issuer_id, now)
            .await?;
    }

    // Corpus hashes (optional)
    if let Some(ref corpus) = req.corpus {
        if corpus.len() > MAX_CORPUS_ENTRIES {
            return Err(RegistryError::BadRequest(format!(
                "too many corpus entries (max {})",
                MAX_CORPUS_ENTRIES
            )));
        }
        for (hash_kind, hash_value) in corpus {
            if let Some(hv) = hash_value.as_str() {
                if !hv.is_empty() && hash_kind.len() <= MAX_ID_LEN && hv.len() <= MAX_ID_LEN {
                    db::upsert_corpus(&state.db, file_id, hash_kind, hv, now).await?;
                }
            }
        }
    }

    // ---- Transparency log ----
    let timestamp_str = crate::timestamp_stub();
    let tlog_event = serde_json::json!({
        "event": "register",
        "file_id": file_id,
        "recipient_id": recipient_id,
        "issuer_id": issuer_id,
        "issuer_pub": issuer_pub,
        "n_beacons": signed_beacons.len(),
        "n_watermarks": signed_watermarks.len(),
        "timestamp": timestamp_str,
    });
    let tlog_idx = state
        .tlog
        .append_event(&tlog_event)
        .map(|idx| idx as i64)
        .unwrap_or(-1);

    // ---- Optional Rekor attestation ----
    let rekor_result = if state.rekor_enabled {
        attest_to_rekor(&state, file_id, &issuer_pub, recipient_id, manifest, &signed_watermarks)
    } else {
        None
    };

    tracing::info!(
        file_id = %file_id,
        beacons = signed_beacons.len(),
        watermarks = signed_watermarks.len(),
        tlog_idx = tlog_idx,
        "registration complete"
    );

    Ok(Json(RegistrationResponse {
        ok: true,
        file_id: file_id.to_string(),
        registered_beacons: signed_beacons.len(),
        tlog_index: tlog_idx,
        rekor: rekor_result,
    }))
}

/// Sign a registration predicate and submit to a Rekor v2 transparency log.
/// Non-fatal: returns None on any error so the registry remains usable.
fn attest_to_rekor(
    state: &AppState,
    file_id: &str,
    issuer_pub_hex: &str,
    recipient_id: &str,
    manifest: &serde_json::Value,
    signed_watermarks: &[serde_json::Value],
) -> Option<serde_json::Value> {
    let identity = state.identity.as_ref()?;

    let recipient_pubkey_hex = manifest
        .get("recipient")
        .and_then(|r| r.get("x25519_pub"))
        .and_then(|v| v.as_str());
    let suite = manifest
        .get("suite")
        .and_then(|v| v.as_str())
        .unwrap_or("classic");
    let zero_hash = "0".repeat(64);
    let content_hash = manifest
        .get("content_hash")
        .and_then(|v| v.as_str())
        .unwrap_or(&zero_hash);

    let recipient_hash = match recipient_pubkey_hex {
        Some(pk) => oversight_rekor::hash_recipient_pubkey(pk).unwrap_or_else(|_| "0".repeat(64)),
        None => "0".repeat(64),
    };

    let mark_id_hex = signed_watermarks
        .iter()
        .find_map(|w| w.get("mark_id").and_then(|v| v.as_str()))
        .unwrap_or(file_id);

    let mut wm_map = std::collections::BTreeMap::new();
    for (i, w) in signed_watermarks.iter().enumerate() {
        let fallback = format!("layer_{i}");
        let layer = w
            .get("layer")
            .and_then(|v| v.as_str())
            .unwrap_or(&fallback);
        if let Some(mid) = w.get("mark_id").and_then(|v| v.as_str()) {
            wm_map.insert(
                layer.to_string(),
                serde_json::Value::String(mid.to_string()),
            );
        }
    }

    let predicate = oversight_rekor::OversightRegistrationPredicate {
        file_id: file_id.to_string(),
        issuer_pubkey_ed25519: issuer_pub_hex.to_string(),
        recipient_id: recipient_id.to_string(),
        recipient_pubkey_sha256: recipient_hash,
        suite: suite.to_string(),
        registered_at: crate::timestamp_stub(),
        rfc3161_tsa: None,
        rfc3161_token_b64: None,
        rfc3161_chain_b64: None,
        policy: Default::default(),
        watermarks: wm_map,
    };

    let statement = oversight_rekor::build_statement(mark_id_hex, content_hash, &predicate);

    let priv_bytes = hex::decode(&identity.ed25519_priv).ok()?;

    match oversight_rekor::sign_dsse(&statement, &priv_bytes, "") {
        Ok(envelope) => {
            let pub_bytes = hex::decode(&identity.ed25519_pub).ok()?;
            // Rekor v2 expects DER-encoded SubjectPublicKeyInfo. For Ed25519 this is
            // a fixed 12-byte prefix + 32-byte raw key.
            let der_prefix: [u8; 12] = [
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
            ];
            let mut der = Vec::with_capacity(44);
            der.extend_from_slice(&der_prefix);
            der.extend_from_slice(&pub_bytes);

            match oversight_rekor::upload::upload_dsse(&envelope, &der, &state.rekor_url) {
                Ok(result) => Some(serde_json::json!({
                    "log_url": result.log_url,
                    "log_index": result.log_index,
                    "log_id": result.log_id,
                    "integrated_time": result.integrated_time,
                    "tlog_kind": oversight_rekor::TLOG_KIND,
                    "bundle_schema": oversight_rekor::BUNDLE_SCHEMA,
                })),
                Err(e) => Some(serde_json::json!({
                    "error": format!("{e}"),
                    "tlog_kind": oversight_rekor::TLOG_KIND,
                })),
            }
        }
        Err(e) => Some(serde_json::json!({
            "error": format!("{e}"),
            "tlog_kind": oversight_rekor::TLOG_KIND,
        })),
    }
}
