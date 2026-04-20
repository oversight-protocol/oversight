//! # oversight-policy
//!
//! Policy enforcement for opens. Mirrors the Python `oversight_core.policy`
//! module with the same TOCTOU-safe atomic check-and-bump for `max_opens`.
//!
//! ## Enforcement modes
//!
//! - **LocalOnly**: counter state in a per-file JSON, protected by an
//!   OS-level flock. Write-to-temp-then-rename for crash consistency.
//!   Single-user, no network.
//! - **Registry**: counter lives in the registry (caller handles network).
//! - **Hybrid**: prefer registry, fall back to local if offline.
//!
//! The LocalOnly mode is not secure against an attacker who can tamper with
//! the state file (they can reset the counter by deleting the file). It is
//! however safe against races from concurrent honest openers.

use fs2::FileExt;
use oversight_manifest::Manifest;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy violation: {0}")]
    Violation(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("context required for this policy but not provided")]
    ContextRequired,
    #[error("invalid file_id for counter path: {0:?}")]
    BadFileId(String),
}

pub type Result<T> = std::result::Result<T, PolicyError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    LocalOnly,
    Registry,
    Hybrid,
}

/// State the opener needs to enforce policy.
#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub jurisdiction: String,
    pub state_dir: Option<PathBuf>,
    pub registry_url: Option<String>,
    pub mode: Mode,
}

impl Default for PolicyContext {
    fn default() -> Self {
        PolicyContext {
            jurisdiction: "GLOBAL".into(),
            state_dir: None,
            registry_url: None,
            mode: Mode::LocalOnly,
        }
    }
}

impl PolicyContext {
    pub fn local_only(state_dir: impl Into<PathBuf>) -> Result<Self> {
        let dir: PathBuf = state_dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            jurisdiction: "GLOBAL".into(),
            state_dir: Some(dir),
            registry_url: None,
            mode: Mode::LocalOnly,
        })
    }

    pub fn with_jurisdiction(mut self, j: impl Into<String>) -> Self {
        self.jurisdiction = j.into();
        self
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CounterState {
    count: u64,
    last: i64,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn sanitize_file_id(file_id: &str) -> Result<()> {
    if file_id.is_empty()
        || file_id.contains('/')
        || file_id.contains('\\')
        || file_id.contains("..")
        || file_id.contains('\0')
    {
        return Err(PolicyError::BadFileId(file_id.to_string()));
    }
    Ok(())
}

fn counter_path(ctx: &PolicyContext, file_id: &str) -> Result<PathBuf> {
    sanitize_file_id(file_id)?;
    let dir = ctx
        .state_dir
        .as_ref()
        .ok_or(PolicyError::ContextRequired)?;
    Ok(dir.join(format!("{}.opens.json", file_id)))
}

fn lock_path(ctx: &PolicyContext, file_id: &str) -> Result<PathBuf> {
    sanitize_file_id(file_id)?;
    let dir = ctx
        .state_dir
        .as_ref()
        .ok_or(PolicyError::ContextRequired)?;
    Ok(dir.join(format!("{}.opens.lock", file_id)))
}

fn read_count(ctx: &PolicyContext, file_id: &str) -> u64 {
    let p = match counter_path(ctx, file_id) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    if !p.exists() {
        return 0;
    }
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(_) => return 0,
    };
    match serde_json::from_str::<CounterState>(&text) {
        Ok(cs) => cs.count,
        Err(_) => 0,
    }
}

/// Atomic check-and-bump: grab a file lock, read count, if it's below
/// max_opens bump and fsync the new value, else raise PolicyViolation.
/// Guarantees TOCTOU safety across concurrent openers of the same file.
fn local_check_and_bump(ctx: &PolicyContext, file_id: &str, max_opens: u64) -> Result<u64> {
    let state_dir = ctx.state_dir.as_ref().ok_or(PolicyError::ContextRequired)?;
    std::fs::create_dir_all(state_dir)?;

    let lock_path_buf = lock_path(ctx, file_id)?;
    let counter_path_buf = counter_path(ctx, file_id)?;

    // Open or create the lock file and acquire an exclusive OS-level lock.
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path_buf)?;
    lock_file.lock_exclusive()?;

    // Critical section: read current count, check, write new.
    let cur = read_count(ctx, file_id);
    if cur >= max_opens {
        // lock auto-releases on drop
        FileExt::unlock(&lock_file)?;
        return Err(PolicyError::Violation(format!(
            "Open limit reached: max_opens={max_opens}, already opened {cur} times"
        )));
    }
    let new_count = cur + 1;

    // Atomic write: temp file in the same directory, then rename.
    let state = CounterState {
        count: new_count,
        last: now_unix(),
    };
    let tmp_path = state_dir.join(format!(".{}.opens.tmp.{}", file_id, std::process::id()));
    {
        let mut tmp = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        tmp.write_all(serde_json::to_string(&state)?.as_bytes())?;
        tmp.flush()?;
        tmp.sync_data()?;
    }
    std::fs::rename(&tmp_path, &counter_path_buf)?;

    FileExt::unlock(&lock_file)?;
    Ok(new_count)
}

/// Cheap, read-only policy checks (time window, jurisdiction).
/// max_opens is enforced separately in `record_open` to prevent TOCTOU.
pub fn check_policy(manifest: &Manifest, ctx: Option<&PolicyContext>) -> Result<()> {
    let now = now_unix();

    if let Some(na) = manifest.policy.get("not_after").and_then(|v| v.as_i64()) {
        if now > na {
            let ago_h = (now - na) / 3600;
            return Err(PolicyError::Violation(format!(
                "File expired: not_after={na}, now={now} ({ago_h}h ago)"
            )));
        }
    }
    if let Some(nb) = manifest.policy.get("not_before").and_then(|v| v.as_i64()) {
        if now < nb {
            let in_m = (nb - now) / 60;
            return Err(PolicyError::Violation(format!(
                "File not yet released: not_before={nb}, now={now} (available in {in_m}m)"
            )));
        }
    }

    if let Some(required) = manifest.policy.get("jurisdiction").and_then(|v| v.as_str()) {
        if required != "GLOBAL" {
            if let Some(ctx) = ctx {
                if required != ctx.jurisdiction {
                    return Err(PolicyError::Violation(format!(
                        "Jurisdiction mismatch: file requires '{required}', opener is in '{}'",
                        ctx.jurisdiction
                    )));
                }
            }
        }
    }

    // max_opens NOT checked here — it's checked atomically in record_open.
    Ok(())
}

/// Atomic check-and-bump the open counter (if policy has max_opens).
/// Call after a successful recipient decrypt, before releasing plaintext, so
/// failed key guesses cannot consume the recipient's open budget.
/// Returns new count (0 if no max_opens policy).
pub fn record_open(manifest: &Manifest, ctx: Option<&PolicyContext>) -> Result<u64> {
    let ctx = match ctx {
        Some(c) => c,
        None => return Ok(0),
    };
    let mx = match manifest.policy.get("max_opens").and_then(|v| v.as_u64()) {
        Some(m) => m,
        None => return Ok(0),
    };
    match ctx.mode {
        Mode::LocalOnly => local_check_and_bump(ctx, &manifest.file_id, mx),
        Mode::Registry => Err(PolicyError::Violation(
            "registry max_opens enforcement is not implemented; refusing local fallback".into(),
        )),
        Mode::Hybrid => Err(PolicyError::Violation(
            "hybrid max_opens enforcement is not implemented; refusing silent local fallback".into(),
        )),
    }
}

// Silence unused import warning when building without tempfile dev-dep
#[allow(dead_code)]
fn _unused_lock_file_param(_: &File) {}

#[cfg(test)]
mod tests {
    use super::*;
    use oversight_manifest::{Manifest, Recipient};
    use tempfile::TempDir;

    fn make_manifest_with(policy: serde_json::Value) -> Manifest {
        let mut m = Manifest::new(
            "test.txt",
            "abc",
            10,
            "issuer",
            "00".repeat(32),
            Recipient {
                recipient_id: "alice".into(),
                x25519_pub: "00".repeat(32),
                ed25519_pub: None,
            },
            "https://registry",
            "text/plain",
            None,
            None,
            "GLOBAL",
        );
        m.policy = policy;
        m
    }

    #[test]
    fn not_after_expired_rejected() {
        let m = make_manifest_with(serde_json::json!({
            "jurisdiction": "GLOBAL",
            "not_after": 1000,  // long ago
        }));
        let err = check_policy(&m, None).unwrap_err();
        assert!(matches!(err, PolicyError::Violation(_)));
    }

    #[test]
    fn not_before_future_rejected() {
        let m = make_manifest_with(serde_json::json!({
            "jurisdiction": "GLOBAL",
            "not_before": now_unix() + 3600,  // 1h from now
        }));
        assert!(check_policy(&m, None).is_err());
    }

    #[test]
    fn jurisdiction_mismatch_rejected() {
        let m = make_manifest_with(serde_json::json!({
            "jurisdiction": "EU",
        }));
        let dir = TempDir::new().unwrap();
        let ctx = PolicyContext::local_only(dir.path()).unwrap().with_jurisdiction("US");
        assert!(check_policy(&m, Some(&ctx)).is_err());
    }

    #[test]
    fn jurisdiction_global_ok_without_ctx() {
        let m = make_manifest_with(serde_json::json!({
            "jurisdiction": "GLOBAL",
        }));
        assert!(check_policy(&m, None).is_ok());
    }

    #[test]
    fn max_opens_enforced() {
        let dir = TempDir::new().unwrap();
        let ctx = PolicyContext::local_only(dir.path()).unwrap();
        let m = make_manifest_with(serde_json::json!({
            "jurisdiction": "GLOBAL",
            "max_opens": 2,
        }));
        assert_eq!(record_open(&m, Some(&ctx)).unwrap(), 1);
        assert_eq!(record_open(&m, Some(&ctx)).unwrap(), 2);
        assert!(record_open(&m, Some(&ctx)).is_err());  // 3rd exceeds
    }

    #[test]
    fn file_id_sanitization() {
        let dir = TempDir::new().unwrap();
        let ctx = PolicyContext::local_only(dir.path()).unwrap();
        let mut m = make_manifest_with(serde_json::json!({
            "max_opens": 5,
        }));
        m.file_id = "../../../etc/passwd".into();
        assert!(record_open(&m, Some(&ctx)).is_err());
    }

    #[test]
    fn registry_modes_refuse_silent_local_fallback() {
        let m = make_manifest_with(serde_json::json!({
            "max_opens": 1,
        }));
        let ctx = PolicyContext {
            mode: Mode::Registry,
            registry_url: Some("https://registry.test".into()),
            ..Default::default()
        };
        assert!(record_open(&m, Some(&ctx)).is_err());

        let ctx = PolicyContext {
            mode: Mode::Hybrid,
            registry_url: Some("https://registry.test".into()),
            ..Default::default()
        };
        assert!(record_open(&m, Some(&ctx)).is_err());
    }
}
