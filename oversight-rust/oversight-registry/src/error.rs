//! Unified error types and Axum error responses for the registry.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum RegistryError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("rate limit exceeded")]
    RateLimited,

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("internal: {0}")]
    Internal(String),
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            RegistryError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            RegistryError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            RegistryError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            RegistryError::RateLimited => {
                (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".into())
            }
            RegistryError::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error".into(),
            ),
            RegistryError::Internal(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg.clone())
            }
        };

        // Log server-side errors at error level; client errors at debug.
        match status.as_u16() {
            400..=499 => tracing::debug!(%status, %message, "client error"),
            _ => tracing::error!(%status, %message, "server error"),
        }

        let body = serde_json::json!({ "error": message });
        (status, Json(body)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, RegistryError>;
