//! Beacon callback endpoints: HTTP image, OCSP-style, and license checks.

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::db;
use crate::error::{RegistryError, Result};
use crate::models::MAX_ID_LEN;
use crate::AppState;

const ONE_PX_PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x62, 0x60, 0x00, 0x00, 0x00,
    0x00, 0x05, 0x00, 0x01, 0xa5, 0xf6, 0x45, 0x40, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44,
    0xae, 0x42, 0x60, 0x82,
];

pub async fn beacon_png(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token_id): Path<String>,
) -> Result<Response> {
    let token_id = token_id
        .strip_suffix(".png")
        .unwrap_or(token_id.as_str())
        .to_string();
    record_event(&state, &addr, &headers, &token_id, "http_img").await?;
    Ok(([(header::CONTENT_TYPE, "image/png")], ONE_PX_PNG).into_response())
}

pub async fn beacon_ocsp(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token_id): Path<String>,
) -> Result<StatusCode> {
    record_event(&state, &addr, &headers, &token_id, "ocsp").await?;
    Ok(StatusCode::OK)
}

pub async fn beacon_license(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    record_event(&state, &addr, &headers, &token_id, "license").await?;
    Ok(Json(serde_json::json!({"valid": true})))
}

async fn record_event(
    state: &AppState,
    addr: &SocketAddr,
    headers: &HeaderMap,
    token_id: &str,
    kind: &str,
) -> Result<i64> {
    if token_id.is_empty() || token_id.len() > MAX_ID_LEN {
        return Err(RegistryError::BadRequest("invalid token_id".into()));
    }

    let beacon = db::get_beacon(&state.db, token_id).await?;
    let file_id = beacon.as_ref().map(|b| b.file_id.as_str());
    let recipient_id = beacon.as_ref().map(|b| b.recipient_id.as_str());
    let issuer_id = beacon.as_ref().map(|b| b.issuer_id.as_str());
    let source_ip = addr.ip().to_string();
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let timestamp_str = crate::timestamp_stub();

    let tlog_event = serde_json::json!({
        "event": "beacon",
        "kind": kind,
        "token_id": token_id,
        "file_id": file_id,
        "recipient_id": recipient_id,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "timestamp": timestamp_str,
    });
    let tlog_idx = state
        .tlog
        .append_event(&tlog_event)
        .map(|idx| idx as i64)
        .unwrap_or(-1);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    db::insert_event(
        &state.db,
        token_id,
        file_id,
        recipient_id,
        issuer_id,
        kind,
        Some(&source_ip),
        Some(user_agent),
        Some("{}"),
        now,
        Some(&timestamp_str),
        Some(tlog_idx),
    )
    .await?;

    Ok(tlog_idx)
}
