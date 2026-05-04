//! Transparency-log read endpoints for federated verifiers.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use std::io::{BufRead, BufReader};
use std::sync::Arc;

use crate::error::{RegistryError, Result};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct RangeParams {
    #[serde(default)]
    start: usize,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    500
}

pub async fn tlog_head(State(state): State<Arc<AppState>>) -> Result<Json<serde_json::Value>> {
    Ok(Json(
        serde_json::to_value(state.tlog.signed_head())
            .map_err(|e| RegistryError::Internal(format!("could not serialize tlog head: {e}")))?,
    ))
}

pub async fn tlog_proof(
    State(state): State<Arc<AppState>>,
    Path(index): Path<usize>,
) -> Result<Json<serde_json::Value>> {
    let proof = state
        .tlog
        .inclusion_proof(index)
        .ok_or_else(|| RegistryError::NotFound("index out of range".into()))?;
    Ok(Json(serde_json::to_value(proof).map_err(|e| {
        RegistryError::Internal(format!("could not serialize tlog proof: {e}"))
    })?))
}

pub async fn tlog_range(
    State(state): State<Arc<AppState>>,
    Query(params): Query<RangeParams>,
) -> Result<Json<serde_json::Value>> {
    let limit = params.limit.clamp(1, 1000);
    let leaves_path = state.tlog.data_dir().join("leaves.jsonl");
    if !leaves_path.exists() {
        return Ok(Json(serde_json::json!({
            "start": params.start,
            "count": 0,
            "entries": [],
        })));
    }

    let file = std::fs::File::open(&leaves_path)
        .map_err(|e| RegistryError::Internal(format!("could not open tlog leaves: {e}")))?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        if idx < params.start {
            continue;
        }
        if entries.len() >= limit {
            break;
        }
        let line =
            line.map_err(|e| RegistryError::Internal(format!("could not read tlog leaf: {e}")))?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
            entries.push(value);
        }
    }

    Ok(Json(serde_json::json!({
        "start": params.start,
        "count": entries.len(),
        "entries": entries,
    })))
}
