//! Oversight v1.0 Registry Server — Axum + SQLx
//!
//! Rust port of the Python FastAPI registry (`registry/server.py`).
//!
//! Features:
//!   - SQLite with WAL mode (via SQLx) for concurrent access
//!   - Ed25519 manifest signature verification on /register
//!   - Token bucket rate limiting with X-Forwarded-For support
//!   - RFC 6962 Merkle transparency log
//!   - Optional Rekor v2 attestation
//!   - Registry Ed25519 identity for signing log entries

#![forbid(unsafe_code)]

mod auth;
mod db;
mod error;
mod models;
mod routes;

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use oversight_tlog::TransparencyLog;
use sqlx::SqlitePool;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

pub const VERSION: &str = "1.0.0";

// ---- CLI args -----------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "oversight-registry", version = VERSION, about = "Oversight attribution registry server")]
struct Args {
    /// Host to bind to (overridden by OVERSIGHT_HOST env)
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port to bind to (overridden by OVERSIGHT_PORT env)
    #[arg(long, default_value = "8080")]
    port: u16,

    /// SQLite database path (overridden by OVERSIGHT_DB env)
    #[arg(long)]
    db: Option<String>,

    /// Data directory for tlog and identity key (overridden by OVERSIGHT_DATA env)
    #[arg(long)]
    data_dir: Option<String>,
}

// ---- Application state --------------------------------------------------

pub struct AppState {
    pub db: SqlitePool,
    pub tlog: TransparencyLog,
    pub identity: Option<RegistryIdentity>,
    pub rate_limiter: RateLimiter,
    pub trusted_proxy: bool,
    pub operator_token: Option<String>,
    pub dns_event_secret: Option<String>,
    pub rekor_enabled: bool,
    pub rekor_url: String,
}

/// Registry's Ed25519 identity keypair (hex-encoded).
pub struct RegistryIdentity {
    pub ed25519_priv: String,
    pub ed25519_pub: String,
}

// ---- Rate limiter (token bucket with LRU eviction) ----------------------

pub struct RateLimiter {
    rate: f64,
    burst: f64,
    max_keys: usize,
    /// Map from client key -> (tokens, last_time)
    state: Mutex<HashMap<String, (f64, Instant)>>,
}

impl RateLimiter {
    fn new(rate: f64, burst: f64, max_keys: usize) -> Self {
        Self {
            rate,
            burst,
            max_keys,
            state: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();

        let (mut tokens, last) = state.remove(key).unwrap_or((self.burst, now));
        let elapsed = now.duration_since(last).as_secs_f64();
        tokens = (tokens + elapsed * self.rate).min(self.burst);

        if tokens < 1.0 {
            state.insert(key.to_string(), (tokens, now));
            self.evict_if_needed(&mut state);
            return false;
        }

        state.insert(key.to_string(), (tokens - 1.0, now));
        self.evict_if_needed(&mut state);
        true
    }

    fn evict_if_needed(&self, state: &mut HashMap<String, (f64, Instant)>) {
        // Simple eviction: if over capacity, remove oldest entries.
        while state.len() > self.max_keys {
            // Find the oldest entry
            if let Some(oldest_key) = state
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone())
            {
                state.remove(&oldest_key);
            } else {
                break;
            }
        }
    }
}

// ---- Helpers ------------------------------------------------------------

/// ISO 8601 UTC timestamp.
pub fn timestamp_stub() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Extract the client key for rate limiting.
fn client_key(headers: &HeaderMap, addr: Option<&SocketAddr>, trusted_proxy: bool) -> String {
    if trusted_proxy {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                let trimmed = first.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }
    addr.map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".into())
}

/// Load or create the registry Ed25519 identity keypair.
fn load_or_create_identity(data_dir: &PathBuf) -> Option<RegistryIdentity> {
    let identity_path = data_dir.join("registry-identity.json");

    if identity_path.exists() {
        match fs::read_to_string(&identity_path) {
            Ok(contents) => {
                let parsed: serde_json::Value = serde_json::from_str(&contents).ok()?;
                let priv_hex = parsed.get("ed25519_priv")?.as_str()?.to_string();
                let pub_hex = parsed.get("ed25519_pub")?.as_str()?.to_string();
                tracing::info!("loaded registry identity from {}", identity_path.display());
                return Some(RegistryIdentity {
                    ed25519_priv: priv_hex,
                    ed25519_pub: pub_hex,
                });
            }
            Err(e) => {
                tracing::error!("failed to read identity file: {e}");
                return None;
            }
        }
    }

    // Generate new identity
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();

    let priv_hex = hex::encode(sk.to_bytes());
    let pub_hex = hex::encode(pk.to_bytes());

    let identity_json = serde_json::json!({
        "ed25519_priv": priv_hex,
        "ed25519_pub": pub_hex,
        "created_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    });

    // Write with restrictive permissions. On Unix we'd use mode 0o600;
    // on Windows we write normally (ACLs handle access control).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        match opts.open(&identity_path) {
            Ok(mut f) => {
                use std::io::Write;
                if let Err(e) = f.write_all(
                    serde_json::to_string_pretty(&identity_json)
                        .unwrap_or_default()
                        .as_bytes(),
                ) {
                    tracing::error!("failed to write identity: {e}");
                    return None;
                }
            }
            Err(e) => {
                tracing::error!("failed to create identity file: {e}");
                return None;
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(e) = fs::write(
            &identity_path,
            serde_json::to_string_pretty(&identity_json).unwrap_or_default(),
        ) {
            tracing::error!("failed to write identity: {e}");
            return None;
        }
    }

    tracing::info!(
        pub_key = %pub_hex,
        "generated new registry identity at {}",
        identity_path.display()
    );

    Some(RegistryIdentity {
        ed25519_priv: priv_hex,
        ed25519_pub: pub_hex,
    })
}

fn allowed_cors_origins() -> Vec<HeaderValue> {
    let mut origins = vec![
        "https://oversight-protocol.github.io".to_string(),
        "https://oversightprotocol.dev".to_string(),
        "https://www.oversightprotocol.dev".to_string(),
        "http://localhost:8000".to_string(),
        "http://127.0.0.1:8000".to_string(),
        "http://localhost:8787".to_string(),
        "http://127.0.0.1:8787".to_string(),
    ];
    origins.extend(
        std::env::var("OVERSIGHT_CORS_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|origin| !origin.is_empty())
            .map(str::to_string),
    );
    origins
        .into_iter()
        .filter_map(|origin| HeaderValue::from_str(&origin).ok())
        .collect()
}

fn cors_layer() -> CorsLayer {
    let allowed = allowed_cors_origins();
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _| {
            allowed.iter().any(|candidate| candidate == origin)
        }))
        .allow_methods([Method::GET, Method::OPTIONS])
        .allow_headers([header::ACCEPT, header::CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(3600))
}

// ---- Rate-limit middleware ----------------------------------------------

async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let key = client_key(req.headers(), Some(&addr), state.trusted_proxy);
    if !state.rate_limiter.allow(&key) {
        tracing::debug!(client = %key, "rate limited");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(req).await)
}

// ---- Server entry point -------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing (structured logging).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "oversight_registry=info,tower_http=info".into()),
        )
        .init();

    let args = Args::parse();

    // Resolve config from env vars (higher priority) or CLI args.
    let host = std::env::var("OVERSIGHT_HOST").unwrap_or(args.host);
    let port: u16 = std::env::var("OVERSIGHT_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(args.port);

    let db_path = PathBuf::from(
        std::env::var("OVERSIGHT_DB")
            .ok()
            .or_else(|| args.db.clone())
            .unwrap_or_else(|| {
                if cfg!(windows) {
                    std::env::var("TEMP").unwrap_or_else(|_| "C:\\Temp".to_string())
                        + "\\oversight-registry.sqlite"
                } else {
                    "/tmp/oversight-registry.sqlite".to_string()
                }
            }),
    );

    let data_dir = PathBuf::from(
        std::env::var("OVERSIGHT_DATA")
            .ok()
            .or_else(|| args.data_dir.clone())
            .unwrap_or_else(|| {
                if cfg!(windows) {
                    std::env::var("TEMP").unwrap_or_else(|_| "C:\\Temp".to_string())
                        + "\\oversight-data"
                } else {
                    "/tmp/oversight-data".to_string()
                }
            }),
    );

    let trusted_proxy = std::env::var("TRUSTED_PROXY").unwrap_or_default().trim() == "1";

    let rekor_enabled = std::env::var("OVERSIGHT_REKOR_ENABLED")
        .unwrap_or_default()
        .trim()
        == "1";

    let dns_event_secret = std::env::var("OVERSIGHT_DNS_EVENT_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let operator_token = std::env::var("OVERSIGHT_OPERATOR_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let rekor_url = std::env::var("OVERSIGHT_REKOR_URL")
        .unwrap_or_else(|_| oversight_rekor::DEFAULT_REKOR_URL.to_string());

    // Ensure data directory exists.
    fs::create_dir_all(&data_dir)?;

    // Initialize database.
    tracing::info!(path = %db_path.display(), "opening database");
    let pool = db::create_pool(&db_path).await?;
    db::run_migrations(&pool).await?;

    // Initialize transparency log.
    let tlog_dir = data_dir.join("tlog");
    let identity = load_or_create_identity(&data_dir);
    let tlog = TransparencyLog::open_with_signer(
        &tlog_dir,
        identity.as_ref().map(|i| i.ed25519_priv.as_str()),
    )
    .map_err(|e| anyhow::anyhow!("tlog init: {e}"))?;

    tracing::info!(
        tlog_size = tlog.size(),
        rekor = rekor_enabled,
        trusted_proxy = trusted_proxy,
        "transparency log initialized"
    );

    let state = Arc::new(AppState {
        db: pool,
        tlog,
        identity,
        rate_limiter: RateLimiter::new(10.0, 30.0, 100_000),
        trusted_proxy,
        operator_token,
        dns_event_secret,
        rekor_enabled,
        rekor_url,
    });

    // Build router.
    let app = Router::new()
        .route("/health", get(routes::health::health))
        .route(
            "/.well-known/oversight-registry",
            get(routes::well_known::well_known),
        )
        .route("/register", post(routes::register::register))
        .route("/attribute", post(routes::attribute::attribute))
        .route("/query/:file_id", get(routes::query::query_file))
        .route("/evidence/:file_id", get(routes::evidence::evidence_bundle))
        .route("/tlog/head", get(routes::tlog::tlog_head))
        .route("/tlog/proof/:index", get(routes::tlog::tlog_proof))
        .route("/tlog/range", get(routes::tlog::tlog_range))
        .route("/p/:token_id", get(routes::beacon::beacon_png))
        .route(
            "/r/:token_id",
            get(routes::beacon::beacon_ocsp).post(routes::beacon::beacon_ocsp),
        )
        .route(
            "/ocsp/r/:token_id",
            get(routes::beacon::beacon_ocsp).post(routes::beacon::beacon_ocsp),
        )
        .route("/v/:token_id", get(routes::beacon::beacon_license))
        .route("/lic/v/:token_id", get(routes::beacon::beacon_license))
        .route(
            "/candidates/semantic",
            get(routes::semantic::candidates_semantic),
        )
        .route("/dns_event", post(routes::dns_event::dns_event))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(cors_layer())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Bind and serve.
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address: {e}"))?;

    tracing::info!(%addr, version = VERSION, "oversight-registry starting");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("oversight-registry shut down");
    Ok(())
}

/// Wait for SIGINT / SIGTERM (Unix) or Ctrl+C (all platforms).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { tracing::info!("received Ctrl+C, shutting down"); }
        _ = terminate => { tracing::info!("received SIGTERM, shutting down"); }
    }
}
