//! GET /candidates/semantic - recent L3 semantic mark IDs for scrapers.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

use crate::db;
use crate::error::Result;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct SemanticParams {
    #[serde(default = "default_limit")]
    limit: i64,
    since: Option<i64>,
}

fn default_limit() -> i64 {
    1000
}

pub async fn candidates_semantic(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SemanticParams>,
) -> Result<Json<serde_json::Value>> {
    let limit = params.limit.clamp(1, 10_000);
    let candidates = db::get_semantic_candidates(&state.db, limit, params.since).await?;
    Ok(Json(serde_json::json!({
        "generated_at": crate::timestamp_stub(),
        "count": candidates.len(),
        "candidates": candidates,
    })))
}
