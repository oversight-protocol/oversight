//! SQLite database setup, migrations, and query functions.
//!
//! Uses SQLx with WAL mode for concurrent read/write access.
//! All queries use parameterized bindings — no string interpolation.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::path::Path;
use std::str::FromStr;

use crate::error::{RegistryError, Result};
use crate::models::*;

/// Create a SQLite connection pool with WAL mode and sensible defaults.
pub async fn create_pool(db_path: &Path) -> Result<SqlitePool> {
    // Ensure parent directory exists.
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| RegistryError::Internal(format!("cannot create db directory: {e}")))?;
    }

    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
    let opts = SqliteConnectOptions::from_str(&db_url)
        .map_err(|e| RegistryError::Internal(format!("bad db url: {e}")))?
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        // Busy timeout so concurrent writers don't fail immediately.
        .busy_timeout(std::time::Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await?;

    Ok(pool)
}

/// Run schema migrations (CREATE TABLE IF NOT EXISTS).
pub async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS beacons (
            token_id TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            issuer_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            registered_at INTEGER NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS watermarks (
            mark_id TEXT NOT NULL,
            layer TEXT NOT NULL,
            file_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            issuer_id TEXT NOT NULL,
            registered_at INTEGER NOT NULL,
            PRIMARY KEY (mark_id, layer)
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS manifests (
            file_id TEXT PRIMARY KEY,
            recipient_id TEXT NOT NULL,
            issuer_id TEXT NOT NULL,
            issuer_ed25519_pub TEXT NOT NULL,
            manifest_json TEXT NOT NULL,
            registered_at INTEGER NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id TEXT NOT NULL,
            file_id TEXT,
            recipient_id TEXT,
            issuer_id TEXT,
            kind TEXT NOT NULL,
            source_ip TEXT,
            user_agent TEXT,
            extra TEXT,
            timestamp INTEGER NOT NULL,
            qualified_timestamp TEXT,
            tlog_index INTEGER
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS corpus (
            file_id TEXT NOT NULL,
            hash_kind TEXT NOT NULL,
            hash_value TEXT NOT NULL,
            metadata TEXT,
            registered_at INTEGER NOT NULL,
            PRIMARY KEY (file_id, hash_kind, hash_value)
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Indices
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_token ON events(token_id);")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_file ON events(file_id);")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_corpus_hash ON corpus(hash_kind, hash_value);")
        .execute(pool)
        .await?;

    Ok(())
}

// ---- Manifest queries ---------------------------------------------------

/// Look up the issuer pubkey for an existing file_id. Returns None if not found.
pub async fn get_manifest_issuer_pub(pool: &SqlitePool, file_id: &str) -> Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT issuer_ed25519_pub FROM manifests WHERE file_id = ?")
            .bind(file_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.0))
}

/// Insert or replace a manifest row.
pub async fn upsert_manifest(
    pool: &SqlitePool,
    file_id: &str,
    recipient_id: &str,
    issuer_id: &str,
    issuer_pub: &str,
    manifest_json: &str,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO manifests (file_id, recipient_id, issuer_id, issuer_ed25519_pub, manifest_json, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(file_id)
    .bind(recipient_id)
    .bind(issuer_id)
    .bind(issuer_pub)
    .bind(manifest_json)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Get manifest JSON by file_id.
pub async fn get_manifest(pool: &SqlitePool, file_id: &str) -> Result<Option<ManifestRow>> {
    let row = sqlx::query_as::<_, ManifestRow>(
        "SELECT file_id, recipient_id, issuer_id, issuer_ed25519_pub, manifest_json, registered_at FROM manifests WHERE file_id = ?",
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

// ---- Beacon queries -----------------------------------------------------

/// Insert or replace a beacon row.
pub async fn upsert_beacon(
    pool: &SqlitePool,
    token_id: &str,
    file_id: &str,
    recipient_id: &str,
    issuer_id: &str,
    kind: &str,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO beacons (token_id, file_id, recipient_id, issuer_id, kind, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(token_id)
    .bind(file_id)
    .bind(recipient_id)
    .bind(issuer_id)
    .bind(kind)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Look up a beacon by token_id.
pub async fn get_beacon(pool: &SqlitePool, token_id: &str) -> Result<Option<BeaconRow>> {
    let row = sqlx::query_as::<_, BeaconRow>(
        "SELECT token_id, file_id, recipient_id, issuer_id, kind, registered_at FROM beacons WHERE token_id = ?",
    )
    .bind(token_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Get all beacons for a file_id.
pub async fn get_beacons_by_file(pool: &SqlitePool, file_id: &str) -> Result<Vec<BeaconRow>> {
    let rows = sqlx::query_as::<_, BeaconRow>(
        "SELECT token_id, file_id, recipient_id, issuer_id, kind, registered_at FROM beacons WHERE file_id = ?",
    )
    .bind(file_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ---- Watermark queries --------------------------------------------------

/// Insert or replace a watermark row.
pub async fn upsert_watermark(
    pool: &SqlitePool,
    mark_id: &str,
    layer: &str,
    file_id: &str,
    recipient_id: &str,
    issuer_id: &str,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO watermarks (mark_id, layer, file_id, recipient_id, issuer_id, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(mark_id)
    .bind(layer)
    .bind(file_id)
    .bind(recipient_id)
    .bind(issuer_id)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Look up a watermark by mark_id (optionally filtered by layer).
pub async fn get_watermark(
    pool: &SqlitePool,
    mark_id: &str,
    layer: Option<&str>,
) -> Result<Option<WatermarkRow>> {
    let row = match layer {
        Some(l) => {
            sqlx::query_as::<_, WatermarkRow>(
                "SELECT mark_id, layer, file_id, recipient_id, issuer_id, registered_at FROM watermarks WHERE mark_id = ? AND layer = ?",
            )
            .bind(mark_id)
            .bind(l)
            .fetch_optional(pool)
            .await?
        }
        None => {
            sqlx::query_as::<_, WatermarkRow>(
                "SELECT mark_id, layer, file_id, recipient_id, issuer_id, registered_at FROM watermarks WHERE mark_id = ?",
            )
            .bind(mark_id)
            .fetch_optional(pool)
            .await?
        }
    };
    Ok(row)
}

/// Get all watermarks for a file_id.
pub async fn get_watermarks_by_file(pool: &SqlitePool, file_id: &str) -> Result<Vec<WatermarkRow>> {
    let rows = sqlx::query_as::<_, WatermarkRow>(
        "SELECT mark_id, layer, file_id, recipient_id, issuer_id, registered_at FROM watermarks WHERE file_id = ?",
    )
    .bind(file_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ---- Event queries ------------------------------------------------------

/// Insert a beacon callback event.
pub async fn insert_event(
    pool: &SqlitePool,
    token_id: &str,
    file_id: Option<&str>,
    recipient_id: Option<&str>,
    issuer_id: Option<&str>,
    kind: &str,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
    extra: Option<&str>,
    timestamp: i64,
    qualified_timestamp: Option<&str>,
    tlog_index: Option<i64>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO events (token_id, file_id, recipient_id, issuer_id, kind, source_ip, user_agent, extra, timestamp, qualified_timestamp, tlog_index) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(token_id)
    .bind(file_id)
    .bind(recipient_id)
    .bind(issuer_id)
    .bind(kind)
    .bind(source_ip)
    .bind(user_agent)
    .bind(extra)
    .bind(timestamp)
    .bind(qualified_timestamp)
    .bind(tlog_index)
    .execute(pool)
    .await?;
    Ok(())
}

/// Get recent events for a file_id, most recent first.
pub async fn get_recent_events(
    pool: &SqlitePool,
    file_id: &str,
    limit: i64,
) -> Result<Vec<EventRow>> {
    let rows = sqlx::query_as::<_, EventRow>(
        "SELECT id, token_id, file_id, recipient_id, issuer_id, kind, source_ip, user_agent, extra, timestamp, qualified_timestamp, tlog_index FROM events WHERE file_id = ? ORDER BY timestamp DESC LIMIT ?",
    )
    .bind(file_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Get all events for a file_id, oldest first.
pub async fn get_events_by_file(pool: &SqlitePool, file_id: &str) -> Result<Vec<EventRow>> {
    let rows = sqlx::query_as::<_, EventRow>(
        "SELECT id, token_id, file_id, recipient_id, issuer_id, kind, source_ip, user_agent, extra, timestamp, qualified_timestamp, tlog_index FROM events WHERE file_id = ? ORDER BY timestamp ASC",
    )
    .bind(file_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ---- Corpus queries -----------------------------------------------------

/// Insert or replace a corpus hash entry.
pub async fn upsert_corpus(
    pool: &SqlitePool,
    file_id: &str,
    hash_kind: &str,
    hash_value: &str,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO corpus (file_id, hash_kind, hash_value, metadata, registered_at) VALUES (?, ?, ?, NULL, ?)",
    )
    .bind(file_id)
    .bind(hash_kind)
    .bind(hash_value)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Look up a corpus entry by perceptual hash, joining with beacons for ownership.
pub async fn lookup_by_perceptual_hash(
    pool: &SqlitePool,
    hash_value: &str,
) -> Result<Option<(String, Option<String>, Option<String>)>> {
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT c.file_id, b.recipient_id, b.issuer_id FROM corpus c LEFT JOIN beacons b ON c.file_id = b.file_id WHERE c.hash_kind = 'perceptual' AND c.hash_value = ? LIMIT 1",
    )
    .bind(hash_value)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Return recent L3 semantic watermark candidates for verifier scrapers.
pub async fn get_semantic_candidates(
    pool: &SqlitePool,
    limit: i64,
    since: Option<i64>,
) -> Result<Vec<SemanticCandidateRow>> {
    let rows = match since {
        Some(since) => {
            sqlx::query_as::<_, SemanticCandidateRow>(
                "SELECT mark_id, file_id, recipient_id, registered_at FROM watermarks WHERE layer = 'L3_semantic' AND registered_at >= ? ORDER BY registered_at DESC LIMIT ?",
            )
            .bind(since)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as::<_, SemanticCandidateRow>(
                "SELECT mark_id, file_id, recipient_id, registered_at FROM watermarks WHERE layer = 'L3_semantic' ORDER BY registered_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
    };
    Ok(rows)
}
