//! POST /dns_event — authenticated beacon callback logging from the DNS server.

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::{bearer_or_header_token, constant_time_eq};
use crate::db;
use crate::error::{RegistryError, Result};
use crate::models::*;
use crate::AppState;

pub async fn dns_event(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(evt): Json<DnsEventRequest>,
) -> Result<Json<DnsEventResponse>> {
    verify_dns_event_auth(&state, &headers, &addr)?;

    // Validate input sizes
    if evt.token_id.is_empty() || evt.token_id.len() > MAX_ID_LEN {
        return Err(RegistryError::BadRequest("invalid token_id".into()));
    }
    if evt
        .client_ip
        .as_deref()
        .is_some_and(|v| v.len() > MAX_ID_LEN)
        || evt.qtype.as_deref().is_some_and(|v| v.len() > MAX_ID_LEN)
        || evt.qname.as_deref().is_some_and(|v| v.len() > MAX_ID_LEN)
    {
        return Err(RegistryError::BadRequest("dns event field too long".into()));
    }

    // Look up beacon ownership
    let beacon = db::get_beacon(&state.db, &evt.token_id).await?;
    let file_id = beacon.as_ref().map(|b| b.file_id.as_str());
    let recipient_id = beacon.as_ref().map(|b| b.recipient_id.as_str());
    let issuer_id = beacon.as_ref().map(|b| b.issuer_id.as_str());

    // Append to transparency log
    let timestamp_str = crate::timestamp_stub();
    let tlog_event = serde_json::json!({
        "event": "beacon",
        "kind": "dns",
        "token_id": evt.token_id,
        "file_id": file_id,
        "recipient_id": recipient_id,
        "source_ip": evt.client_ip,
        "qname": evt.qname,
        "qtype": evt.qtype,
        "timestamp": timestamp_str,
    });
    let tlog_idx = state
        .tlog
        .append_event(&tlog_event)
        .map(|idx| idx as i64)
        .unwrap_or(-1);

    // Record event in DB
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let extra = serde_json::json!({
        "qtype": evt.qtype,
        "qname": evt.qname,
    });
    let extra_str = serde_json::to_string(&extra).unwrap_or_else(|_| "{}".into());

    db::insert_event(
        &state.db,
        &evt.token_id,
        file_id,
        recipient_id,
        issuer_id,
        "dns",
        evt.client_ip.as_deref(),
        Some(""),
        Some(&extra_str),
        now,
        Some(&timestamp_str),
        Some(tlog_idx),
    )
    .await?;

    tracing::info!(
        token_id = %evt.token_id,
        file_id = ?file_id,
        tlog_idx = tlog_idx,
        "dns beacon event recorded"
    );

    Ok(Json(DnsEventResponse {
        ok: true,
        tlog_index: tlog_idx,
    }))
}

fn verify_dns_event_auth(state: &AppState, headers: &HeaderMap, addr: &SocketAddr) -> Result<()> {
    if let Some(secret) = state.dns_event_secret.as_deref() {
        if let Some(supplied) = bearer_or_header_token(headers, "x-oversight-dns-secret") {
            if constant_time_eq(supplied.as_bytes(), secret.as_bytes()) {
                return Ok(());
            }
        }
        return Err(RegistryError::Unauthorized(
            "invalid dns event authentication".into(),
        ));
    }

    if addr.ip().is_loopback() {
        return Ok(());
    }

    Err(RegistryError::BadRequest(
        "OVERSIGHT_DNS_EVENT_SECRET is required for non-loopback DNS event callbacks".into(),
    ))
}
