//! GET /health — liveness/readiness probe.

use axum::extract::State;
use axum::Json;
use std::sync::Arc;

use crate::error::Result;
use crate::models::HealthResponse;
use crate::AppState;

pub async fn health(State(state): State<Arc<AppState>>) -> Result<Json<HealthResponse>> {
    let tlog_size = state.tlog.size();
    Ok(Json(HealthResponse {
        status: "ok".into(),
        service: "oversight-registry".into(),
        version: crate::VERSION.into(),
        tlog_size,
    }))
}
