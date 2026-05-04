//! GET /evidence/{file_id} - signed provenance bundle for a registered file.

use axum::extract::{Path, State};
use axum::Json;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::Arc;

use crate::db;
use crate::error::{RegistryError, Result};
use crate::models::{EventRow, MAX_ID_LEN};
use crate::AppState;

pub async fn evidence_bundle(
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    if file_id.len() > MAX_ID_LEN {
        return Err(RegistryError::BadRequest("file_id too long".into()));
    }

    let manifest_row = db::get_manifest(&state.db, &file_id)
        .await?
        .ok_or_else(|| RegistryError::NotFound("unknown file_id".into()))?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_row.manifest_json)
        .map_err(|e| RegistryError::Internal(format!("stored manifest is invalid JSON: {e}")))?;
    let beacons = db::get_beacons_by_file(&state.db, &file_id).await?;
    let watermarks = db::get_watermarks_by_file(&state.db, &file_id).await?;
    let events = db::get_events_by_file(&state.db, &file_id).await?;
    let event_values: Vec<serde_json::Value> = events
        .iter()
        .map(|event| serde_json::to_value(event).unwrap_or_else(|_| serde_json::json!({})))
        .collect();

    let identity = state
        .identity
        .as_ref()
        .ok_or_else(|| RegistryError::Internal("registry identity not initialized".into()))?;

    let mut bundle = serde_json::json!({
        "file_id": file_id,
        "bundle_generated_at": crate::timestamp_stub(),
        "registry_pub": identity.ed25519_pub,
        "manifest": manifest,
        "beacons": beacons,
        "watermarks": watermarks,
        "events": event_values,
        "tlog_head": state.tlog.signed_head(),
        "tlog_proofs": tlog_proofs_for_events(&state, &events),
        "disclaimer": "This bundle is a provenance record, not a legal finding. For court use, supplement with RFC 3161 qualified timestamps and ISO/IEC 27037 chain-of-custody.",
    });

    let signature = sign_bundle(identity.ed25519_priv.as_str(), &bundle)?;
    bundle["bundle_signature_ed25519"] = serde_json::Value::String(signature);
    Ok(Json(bundle))
}

fn tlog_proofs_for_events(state: &AppState, events: &[EventRow]) -> Vec<serde_json::Value> {
    events
        .iter()
        .enumerate()
        .filter_map(|(event_row, event)| {
            let idx = event.tlog_index?;
            if idx < 0 {
                return None;
            }
            let proof = state.tlog.inclusion_proof(idx as usize)?;
            Some(serde_json::json!({
                "event_row": event_row,
                "tlog_index": idx,
                "proof": proof,
            }))
        })
        .collect()
}

fn sign_bundle(priv_hex: &str, bundle: &serde_json::Value) -> Result<String> {
    let priv_bytes = hex::decode(priv_hex).map_err(|e| {
        RegistryError::Internal(format!("registry identity private key is invalid hex: {e}"))
    })?;
    if priv_bytes.len() != 32 {
        return Err(RegistryError::Internal(format!(
            "registry identity private key must be 32 bytes, got {}",
            priv_bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&priv_bytes);
    let signing_key = SigningKey::from_bytes(&arr);
    let msg = serde_jcs::to_vec(bundle)
        .map_err(|_| RegistryError::Internal("could not canonicalize evidence bundle".into()))?;
    Ok(hex::encode(signing_key.sign(&msg).to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::{AppState, RateLimiter, RegistryIdentity};
    use oversight_tlog::TransparencyLog;
    use sqlx::SqlitePool;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn temp_path(label: &str) -> PathBuf {
        let unique = format!(
            "oversight-registry-{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    async fn test_state() -> (Arc<AppState>, PathBuf) {
        let dir = temp_path("evidence");
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::create_pool(&dir.join("registry.sqlite")).await.unwrap();
        db::run_migrations(&pool).await.unwrap();

        let priv_hex = "11".repeat(32);
        let tlog = TransparencyLog::open_with_signer(dir.join("tlog"), Some(&priv_hex)).unwrap();
        let pub_hex = {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hex::decode(&priv_hex).unwrap());
            hex::encode(SigningKey::from_bytes(&bytes).verifying_key().to_bytes())
        };
        let state = AppState {
            db: pool,
            tlog,
            identity: Some(RegistryIdentity {
                ed25519_priv: priv_hex,
                ed25519_pub: pub_hex,
            }),
            rate_limiter: RateLimiter::new(10.0, 30.0, 100),
            trusted_proxy: false,
            dns_event_secret: None,
            rekor_enabled: false,
            rekor_url: String::new(),
        };
        (Arc::new(state), dir)
    }

    async fn seed_file(pool: &SqlitePool, state: &AppState) {
        let manifest = serde_json::json!({
            "file_id": "file-1",
            "issuer_id": "issuer-1",
            "issuer_ed25519_pub": "ab".repeat(32),
            "recipient": {"recipient_id": "recipient-1"},
        });
        db::upsert_manifest(
            pool,
            "file-1",
            "recipient-1",
            "issuer-1",
            &"ab".repeat(32),
            &serde_json::to_string(&manifest).unwrap(),
            10,
        )
        .await
        .unwrap();
        db::upsert_beacon(
            pool,
            "token-1",
            "file-1",
            "recipient-1",
            "issuer-1",
            "dns",
            10,
        )
        .await
        .unwrap();
        db::upsert_watermark(
            pool,
            "mark-1",
            "L1_zero_width",
            "file-1",
            "recipient-1",
            "issuer-1",
            10,
        )
        .await
        .unwrap();

        let event = serde_json::json!({"event": "beacon", "token_id": "token-1"});
        let tlog_index = state.tlog.append_event(&event).unwrap() as i64;
        db::insert_event(
            pool,
            "token-1",
            Some("file-1"),
            Some("recipient-1"),
            Some("issuer-1"),
            "dns",
            Some("127.0.0.1"),
            Some("test"),
            Some("{}"),
            10,
            Some("2026-05-03T00:00:00Z"),
            Some(tlog_index),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn evidence_bundle_contains_signed_tlog_proof() {
        let (state, dir) = test_state().await;
        seed_file(&state.db, &state).await;

        let Json(body) = evidence_bundle(State(state), Path("file-1".into()))
            .await
            .unwrap();
        assert_eq!(body["file_id"], "file-1");
        assert!(body["manifest"].is_object());
        assert_eq!(body["beacons"].as_array().unwrap().len(), 1);
        assert_eq!(body["watermarks"].as_array().unwrap().len(), 1);
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
        assert_eq!(body["tlog_proofs"].as_array().unwrap().len(), 1);
        assert_eq!(body["tlog_proofs"][0]["tlog_index"], 0);
        assert_eq!(
            body["bundle_signature_ed25519"].as_str().unwrap().len(),
            128
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn evidence_bundle_returns_404_for_unknown_file() {
        let (state, dir) = test_state().await;
        let err = evidence_bundle(State(state), Path("missing".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::NotFound(_)));
        let _ = std::fs::remove_dir_all(dir);
    }
}
