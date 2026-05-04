//! GET /.well-known/oversight-registry - registry identity advertisement.

use axum::extract::State;
use axum::Json;
use std::sync::Arc;

use crate::error::Result;
use crate::AppState;

pub async fn well_known(State(state): State<Arc<AppState>>) -> Result<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({
        "ed25519_pub": state.identity.as_ref().map(|i| i.ed25519_pub.as_str()),
        "version": crate::VERSION,
        "jurisdiction": std::env::var("OVERSIGHT_JURISDICTION").unwrap_or_else(|_| "GLOBAL".into()),
        "tlog_size": state.tlog.size(),
    })))
}
