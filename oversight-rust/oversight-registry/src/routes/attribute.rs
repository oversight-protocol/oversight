//! POST /attribute — attribution lookup by token_id, mark_id, or perceptual_hash.

use axum::extract::State;
use axum::Json;
use std::sync::Arc;

use crate::db;
use crate::error::{RegistryError, Result};
use crate::models::*;
use crate::AppState;

pub async fn attribute(
    State(state): State<Arc<AppState>>,
    Json(q): Json<AttributionQuery>,
) -> Result<Json<AttributionResponse>> {
    // Validate input sizes
    if let Some(ref id) = q.token_id {
        if id.len() > MAX_ID_LEN {
            return Err(RegistryError::BadRequest("token_id too long".into()));
        }
    }
    if let Some(ref id) = q.mark_id {
        if id.len() > MAX_ID_LEN {
            return Err(RegistryError::BadRequest("mark_id too long".into()));
        }
    }
    if let Some(ref id) = q.layer {
        if id.len() > MAX_ID_LEN {
            return Err(RegistryError::BadRequest("layer too long".into()));
        }
    }
    if let Some(ref id) = q.perceptual_hash {
        if id.len() > MAX_ID_LEN {
            return Err(RegistryError::BadRequest("perceptual_hash too long".into()));
        }
    }

    // Determine lookup strategy (same priority as Python server)
    let (file_id, recipient_id, issuer_id) = if let Some(ref token_id) = q.token_id {
        match db::get_beacon(&state.db, token_id).await? {
            Some(row) => (row.file_id, row.recipient_id, row.issuer_id),
            None => {
                return Ok(Json(AttributionResponse {
                    found: false,
                    file_id: None,
                    recipient_id: None,
                    issuer_id: None,
                    manifest: None,
                    recent_events: None,
                }));
            }
        }
    } else if let Some(ref mark_id) = q.mark_id {
        let layer = q.layer.as_deref();
        match db::get_watermark(&state.db, mark_id, layer).await? {
            Some(row) => (row.file_id, row.recipient_id, row.issuer_id),
            None => {
                return Ok(Json(AttributionResponse {
                    found: false,
                    file_id: None,
                    recipient_id: None,
                    issuer_id: None,
                    manifest: None,
                    recent_events: None,
                }));
            }
        }
    } else if let Some(ref phash) = q.perceptual_hash {
        match db::lookup_by_perceptual_hash(&state.db, phash).await? {
            Some((fid, rid, iid)) => (
                fid,
                rid.unwrap_or_else(|| "unknown".into()),
                iid.unwrap_or_else(|| "unknown".into()),
            ),
            None => {
                return Ok(Json(AttributionResponse {
                    found: false,
                    file_id: None,
                    recipient_id: None,
                    issuer_id: None,
                    manifest: None,
                    recent_events: None,
                }));
            }
        }
    } else {
        return Err(RegistryError::BadRequest(
            "provide token_id, mark_id, or perceptual_hash".into(),
        ));
    };

    // Fetch manifest
    let manifest = match db::get_manifest(&state.db, &file_id).await? {
        Some(row) => serde_json::from_str(&row.manifest_json).ok(),
        None => None,
    };

    // Fetch recent events
    let events = db::get_recent_events(&state.db, &file_id, 50).await?;
    let event_values: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            serde_json::json!({
                "kind": e.kind,
                "source_ip": e.source_ip,
                "user_agent": e.user_agent,
                "timestamp": e.timestamp,
                "qualified_timestamp": e.qualified_timestamp,
                "tlog_index": e.tlog_index,
            })
        })
        .collect();

    Ok(Json(AttributionResponse {
        found: true,
        file_id: Some(file_id),
        recipient_id: Some(recipient_id),
        issuer_id: Some(issuer_id),
        manifest,
        recent_events: Some(event_values),
    }))
}
