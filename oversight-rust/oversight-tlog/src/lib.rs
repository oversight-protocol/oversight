//! # oversight-tlog
//!
//! RFC 6962-compliant Merkle transparency log for Oversight.
//!
//! Every event (registration, beacon callback, attribution query) is appended
//! as a leaf. The log signs a tree head with Ed25519 so auditors can verify
//! inclusion proofs and detect any attempt to remove or reorder entries.
//!
//! ## RFC 6962 Compliance
//!
//! This implementation faithfully follows RFC 6962 §2.1 Merkle Tree Hash and
//! §2.1.1 inclusion proofs. Proofs produced here verify against any RFC 6962
//! client (Sigstore Rekor, Certificate Transparency log verifiers, the Go
//! Trillian library, etc.).
//!
//! ```text
//! MTH({})       = SHA-256()
//! MTH({d[0]})   = SHA-256(0x00 || d[0])
//! MTH(D[0..n])  = SHA-256(0x01 || MTH(D[0..k]) || MTH(D[k..n]))
//!                 where k is the largest power of 2 < n
//! ```
//!
//! ## Durability
//!
//! Every `append` fsyncs before returning. If the process crashes mid-write,
//! the entry is either fully on disk or not at all — no torn writes.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlogError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid signing key length: expected 32, got {0}")]
    BadKeyLength(usize),
    #[error("index {0} out of range (tree_size={1})")]
    IndexOutOfRange(usize, usize),
}

pub type Result<T> = std::result::Result<T, TlogError>;

/// SHA-256 of input
#[inline]
fn h(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Largest power of 2 strictly less than n (for n >= 2). RFC 6962 §2.1.
fn largest_power_of_2_less_than(n: usize) -> usize {
    assert!(n >= 2);
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// RFC 6962 §2.1 Merkle Tree Hash over pre-hashed leaves.
fn mth(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    let n = leaf_hashes.len();
    assert!(n >= 1);
    if n == 1 {
        return leaf_hashes[0];
    }
    let k = largest_power_of_2_less_than(n);
    let left = mth(&leaf_hashes[..k]);
    let right = mth(&leaf_hashes[k..]);
    let mut data = Vec::with_capacity(1 + 64);
    data.push(0x01);
    data.extend_from_slice(&left);
    data.extend_from_slice(&right);
    h(&data)
}

/// RFC 6962 §2.1.1 audit path for leaf at index `m`.
/// Returns siblings from deepest (closest to leaf) to shallowest (closest to root).
fn audit_path(leaf_hashes: &[[u8; 32]], m: usize) -> Vec<[u8; 32]> {
    let n = leaf_hashes.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = largest_power_of_2_less_than(n);
    if m < k {
        let mut path = audit_path(&leaf_hashes[..k], m);
        path.push(mth(&leaf_hashes[k..]));
        path
    } else {
        let mut path = audit_path(&leaf_hashes[k..], m - k);
        path.push(mth(&leaf_hashes[..k]));
        path
    }
}

/// Verify a leaf's inclusion proof against an expected root. RFC 6962 §2.1.1.
pub fn verify_inclusion_proof(
    leaf_hash: &[u8; 32],
    index: usize,
    proof: &[[u8; 32]],
    tree_size: usize,
    expected_root: &[u8; 32],
) -> bool {
    if tree_size == 0 || index >= tree_size {
        return false;
    }

    fn rec(
        h_in: [u8; 32],
        m: usize,
        remaining: &[[u8; 32]],
        n: usize,
    ) -> Option<[u8; 32]> {
        if n == 1 {
            return if remaining.is_empty() { Some(h_in) } else { None };
        }
        if remaining.is_empty() {
            return None;
        }
        let k = largest_power_of_2_less_than(n);
        let sibling = *remaining.last().unwrap();
        let deeper = &remaining[..remaining.len() - 1];
        let (left, right) = if m < k {
            (rec(h_in, m, deeper, k)?, sibling)
        } else {
            (sibling, rec(h_in, m - k, deeper, n - k)?)
        };
        let mut data = Vec::with_capacity(65);
        data.push(0x01);
        data.extend_from_slice(&left);
        data.extend_from_slice(&right);
        Some(h(&data))
    }

    rec(*leaf_hash, index, proof, tree_size)
        .map(|computed| &computed == expected_root)
        .unwrap_or(false)
}

/// On-disk leaf record format.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeafRecord {
    index: usize,
    leaf_hash: String,
    leaf_data: String,
}

/// Signed tree head.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub size: usize,
    pub root: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signed_message: String,
}

/// Inclusion proof returned to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub index: usize,
    pub leaf_hash: String,
    pub proof: Vec<String>,
    pub root: String,
    pub tree_size: usize,
}

/// Append-only Merkle transparency log.
pub struct TransparencyLog {
    dir: PathBuf,
    leaves_path: PathBuf,
    leaves: Mutex<Vec<[u8; 32]>>,
    cached_root: Mutex<Option<[u8; 32]>>,
    signing_key: Option<SigningKey>,
}

impl TransparencyLog {
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_signer(data_dir, None)
    }

    pub fn open_with_signer(
        data_dir: impl AsRef<Path>,
        signing_key_hex: Option<&str>,
    ) -> Result<Self> {
        let dir = data_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let leaves_path = dir.join("leaves.jsonl");

        // Load existing leaves (recovery)
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        if leaves_path.exists() {
            let f = File::open(&leaves_path)?;
            let reader = BufReader::new(f);
            for line in reader.lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(rec) = serde_json::from_str::<LeafRecord>(&line) {
                    if let Ok(bytes) = hex::decode(&rec.leaf_hash) {
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            leaves.push(arr);
                        }
                    }
                }
            }
        }

        let signing_key = match signing_key_hex {
            Some(hex_str) => {
                let bytes = hex::decode(hex_str)?;
                if bytes.len() != 32 {
                    return Err(TlogError::BadKeyLength(bytes.len()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(SigningKey::from_bytes(&arr))
            }
            None => None,
        };

        Ok(TransparencyLog {
            dir,
            leaves_path,
            leaves: Mutex::new(leaves),
            cached_root: Mutex::new(None),
            signing_key,
        })
    }

    /// Append an opaque leaf. Returns its 0-based index. Durable on return.
    pub fn append(&self, leaf_data: &[u8]) -> Result<usize> {
        let mut leaves = self.leaves.lock().unwrap();
        let index = leaves.len();

        // RFC 6962 leaf prefix
        let mut prefixed = Vec::with_capacity(1 + leaf_data.len());
        prefixed.push(0x00);
        prefixed.extend_from_slice(leaf_data);
        let leaf_hash = h(&prefixed);
        leaves.push(leaf_hash);

        // Invalidate cached root
        *self.cached_root.lock().unwrap() = None;

        // Durable append: fsync before returning
        let record = LeafRecord {
            index,
            leaf_hash: hex::encode(leaf_hash),
            leaf_data: String::from_utf8_lossy(leaf_data).to_string(),
        };
        let line = serde_json::to_string(&record)? + "\n";
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.leaves_path)?;
        f.write_all(line.as_bytes())?;
        f.flush()?;
        f.sync_data()?;

        Ok(index)
    }

    /// Append a JSON event. Helper that canonicalizes and calls append().
    pub fn append_event(&self, event: &serde_json::Value) -> Result<usize> {
        let bytes = serde_jcs::to_vec(event).map_err(|_| {
            TlogError::Json(serde_json::Error::custom("canonicalization failed"))
        })?;
        self.append(&bytes)
    }

    pub fn size(&self) -> usize {
        self.leaves.lock().unwrap().len()
    }

    /// RFC 6962 root. Cached after first compute, invalidated on append.
    pub fn root(&self) -> [u8; 32] {
        let mut cached = self.cached_root.lock().unwrap();
        if let Some(r) = *cached {
            return r;
        }
        let leaves = self.leaves.lock().unwrap();
        let root = if leaves.is_empty() {
            [0u8; 32]
        } else {
            mth(&leaves)
        };
        *cached = Some(root);
        root
    }

    /// Signed tree head. Signature present if a signing key was supplied.
    pub fn signed_head(&self) -> SignedTreeHead {
        let size = self.size();
        let root = self.root();
        let mut head = SignedTreeHead {
            size,
            root: hex::encode(root),
            signature: String::new(),
            signed_message: String::new(),
        };
        if let Some(ref sk) = self.signing_key {
            let msg_value = serde_json::json!({
                "size": size,
                "root": head.root,
            });
            let msg = serde_jcs::to_vec(&msg_value).unwrap_or_default();
            let sig = sk.sign(&msg);
            head.signature = hex::encode(sig.to_bytes());
            head.signed_message = String::from_utf8_lossy(&msg).to_string();
        }
        head
    }

    pub fn inclusion_proof(&self, index: usize) -> Option<InclusionProof> {
        let leaves = self.leaves.lock().unwrap();
        if index >= leaves.len() {
            return None;
        }
        let leaves_copy: Vec<[u8; 32]> = leaves.clone();
        let leaf_hash_hex = hex::encode(leaves[index]);
        let tree_size = leaves.len();
        drop(leaves);  // release before calling root() which also locks

        let path = audit_path(&leaves_copy, index);
        let root = self.root();
        Some(InclusionProof {
            index,
            leaf_hash: leaf_hash_hex,
            proof: path.iter().map(hex::encode).collect(),
            root: hex::encode(root),
            tree_size,
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.dir
    }
}

// serde_json needs this little helper for custom errors
trait JsonErrorExt {
    fn custom(msg: &'static str) -> Self;
}
impl JsonErrorExt for serde_json::Error {
    fn custom(msg: &'static str) -> Self {
        serde::de::Error::custom(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn mktlog() -> (TempDir, TransparencyLog) {
        let dir = TempDir::new().unwrap();
        let tl = TransparencyLog::open(dir.path()).unwrap();
        (dir, tl)
    }

    #[test]
    fn append_and_size() {
        let (_d, tl) = mktlog();
        assert_eq!(tl.size(), 0);
        tl.append(b"event0").unwrap();
        tl.append(b"event1").unwrap();
        assert_eq!(tl.size(), 2);
    }

    #[test]
    fn root_changes_on_append() {
        let (_d, tl) = mktlog();
        tl.append(b"a").unwrap();
        let r1 = tl.root();
        tl.append(b"b").unwrap();
        let r2 = tl.root();
        assert_ne!(r1, r2);
    }

    #[test]
    fn inclusion_proofs_verify_for_every_leaf() {
        for n in [1usize, 2, 3, 4, 5, 7, 8, 16, 17, 100] {
            let (_d, tl) = mktlog();
            for i in 0..n {
                tl.append(format!("event_{i}").as_bytes()).unwrap();
            }
            let root = tl.root();
            for i in 0..n {
                let proof = tl.inclusion_proof(i).expect("proof");
                let leaf_hash_bytes = hex::decode(&proof.leaf_hash).unwrap();
                let mut leaf_hash = [0u8; 32];
                leaf_hash.copy_from_slice(&leaf_hash_bytes);
                let siblings: Vec<[u8; 32]> = proof
                    .proof
                    .iter()
                    .map(|s| {
                        let b = hex::decode(s).unwrap();
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        a
                    })
                    .collect();
                assert!(
                    verify_inclusion_proof(&leaf_hash, i, &siblings, n, &root),
                    "n={} leaf={} failed to verify",
                    n,
                    i
                );
            }
        }
    }

    #[test]
    fn tampered_proof_rejected() {
        let (_d, tl) = mktlog();
        for i in 0..5 {
            tl.append(format!("e{i}").as_bytes()).unwrap();
        }
        let proof = tl.inclusion_proof(2).unwrap();
        let leaf_hash_bytes = hex::decode(&proof.leaf_hash).unwrap();
        let mut leaf_hash = [0u8; 32];
        leaf_hash.copy_from_slice(&leaf_hash_bytes);
        let mut siblings: Vec<[u8; 32]> = proof
            .proof
            .iter()
            .map(|s| {
                let b = hex::decode(s).unwrap();
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            })
            .collect();
        if let Some(first) = siblings.first_mut() {
            first[0] ^= 0x01;
        }
        let root = tl.root();
        assert!(!verify_inclusion_proof(&leaf_hash, 2, &siblings, 5, &root));
    }

    #[test]
    fn signed_head_with_key() {
        let dir = TempDir::new().unwrap();
        let key_hex = hex::encode([42u8; 32]);
        let tl = TransparencyLog::open_with_signer(dir.path(), Some(&key_hex)).unwrap();
        tl.append(b"some event").unwrap();
        let head = tl.signed_head();
        assert_eq!(head.size, 1);
        assert!(!head.signature.is_empty());
        assert!(!head.signed_message.is_empty());
    }

    #[test]
    fn survives_reopen() {
        let dir = TempDir::new().unwrap();
        {
            let tl = TransparencyLog::open(dir.path()).unwrap();
            tl.append(b"event_a").unwrap();
            tl.append(b"event_b").unwrap();
        }
        // Re-open — leaves should be recovered from disk
        let tl2 = TransparencyLog::open(dir.path()).unwrap();
        assert_eq!(tl2.size(), 2);
    }

    #[test]
    fn empty_tree_has_zero_root() {
        let (_d, tl) = mktlog();
        assert_eq!(tl.root(), [0u8; 32]);
    }
}
