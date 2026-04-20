//! GET /query/{file_id} — watermark/beacon ownership lookup by file_id.

use axum::extract::{Path, State};
use axum::Json;
use std::sync::Arc;

use crate::db;
use crate::error::{RegistryError, Result};
use crate::models::*;
use crate::AppState;

pub async fn query_file(
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<String>,
) -> Result<Json<QueryResponse>> {
    if file_id.len() > MAX_ID_LEN {
        return Err(RegistryError::BadRequest("file_id too long".into()));
    }

    // Check manifest exists
    let manifest_row = db::get_manifest(&state.db, &file_id).await?;
    if manifest_row.is_none() {
        return Ok(Json(QueryResponse {
            found: false,
            file_id: None,
            recipient_id: None,
            issuer_id: None,
            watermarks: None,
            beacons: None,
        }));
    }
    let manifest_row = manifest_row.unwrap();

    // Fetch watermarks and beacons for this file
    let watermarks = db::get_watermarks_by_file(&state.db, &file_id).await?;
    let beacons = db::get_beacons_by_file(&state.db, &file_id).await?;

    Ok(Json(QueryResponse {
        found: true,
        file_id: Some(file_id),
        recipient_id: Some(manifest_row.recipient_id),
        issuer_id: Some(manifest_row.issuer_id),
        watermarks: Some(watermarks),
        beacons: Some(beacons),
    }))
}
