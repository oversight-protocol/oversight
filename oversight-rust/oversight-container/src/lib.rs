//! # oversight-container
//!
//! The `.sealed` container format: binary layout with magic bytes, signed
//! manifest, AEAD-encrypted payload, and DEK-wrapped-for-recipient.
//!
//! Binary layout:
//! ```text
//! offset  length    field
//! ------  --------  ---------------------------------------
//! 0       6         magic: b"OSGT\x01\x00"
//! 6       1         format_version (=1)
//! 7       1         suite_id (1=CLASSIC_V1, 2=HYBRID_V1, 3=HW_P256_V1)
//! 8       4         manifest_len (u32 BE)
//! 12      M         manifest (canonical JSON, signed)
//! 12+M    4         wrapped_dek_len (u32 BE)
//! ...     W         wrapped_dek (JSON)
//! ...     24        aead_nonce
//! ...     4         ciphertext_len (u32 BE)
//! ...     C         ciphertext (XChaCha20-Poly1305(plaintext))
//! ```

use oversight_crypto::{
    self as crypto, CryptoError, KeyAlgorithm, KeyProvider, WrappedDek, WrappedDekP256,
};
use oversight_manifest::{Manifest, ManifestError};
use oversight_policy::{self, PolicyContext};
use thiserror::Error;

pub const MAGIC: [u8; 6] = *b"OSGT\x01\x00";
pub const SUITE_CLASSIC_V1_ID: u8 = 1;
pub const SUITE_HYBRID_V1_ID: u8 = 2;
/// Hardware-backed P-256 ECDH suite for PIV-compatible tokens.
/// See `docs/HARDWARE_KEYS.md` and `oversight_crypto::SUITE_HW_P256_V1`.
pub const SUITE_HW_P256_V1_ID: u8 = 3;

// Hard caps to prevent DoS via attacker-controlled length fields.
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_WRAPPED_DEK_BYTES: usize = 1 * 1024 * 1024;
// 4 GiB on 64-bit; usize::MAX on 32-bit (which is just under 4 GiB anyway).
// The literal `4 * 1024 * 1024 * 1024` overflows on 32-bit targets, blocking
// 32-bit Android / iOS builds at const-eval time.
#[cfg(target_pointer_width = "64")]
pub const MAX_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024 * 1024;
#[cfg(not(target_pointer_width = "64"))]
pub const MAX_CIPHERTEXT_BYTES: usize = usize::MAX;

#[derive(Debug, Error)]
pub enum ContainerError {
    #[error("bad magic: expected {:?}, got {got:?}", MAGIC)]
    BadMagic { got: Vec<u8> },
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u8),
    #[error("truncated file: wanted {wanted} bytes for {field}, got {got}")]
    Truncated {
        wanted: usize,
        got: usize,
        field: &'static str,
    },
    #[error("oversized field {field}: {got} > {max}")]
    Oversized {
        field: &'static str,
        got: usize,
        max: usize,
    },
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Policy(#[from] oversight_policy::PolicyError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid utf-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("precondition failed: {0}")]
    Precondition(&'static str),
    #[error("suite_id header {header} does not match signed manifest suite {manifest_suite}")]
    SuiteMismatch { header: u8, manifest_suite: String },
    #[error("unsupported manifest suite: {0}")]
    UnsupportedManifestSuite(String),
    #[error("trailing bytes after ciphertext: {0}")]
    TrailingBytes(usize),
    #[error("no decryptable slot found (tried {slots} slots)")]
    NoDecryptableSlot { slots: usize },
    #[error("plaintext hash mismatch — manifest and plaintext disagree")]
    HashMismatch,
}

fn suite_id_for_manifest(suite: &str) -> Option<u8> {
    match suite {
        crypto::SUITE_CLASSIC_V1 => Some(SUITE_CLASSIC_V1_ID),
        crypto::SUITE_HYBRID_V1 => Some(SUITE_HYBRID_V1_ID),
        crypto::SUITE_HW_P256_V1 => Some(SUITE_HW_P256_V1_ID),
        _ => None,
    }
}

#[derive(Debug)]
pub struct SealedFile {
    pub manifest: Manifest,
    pub wrapped_dek: serde_json::Value,
    pub aead_nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub suite_id: u8,
}

fn read_exact<'a>(buf: &'a [u8], at: &mut usize, n: usize, field: &'static str) -> Result<&'a [u8], ContainerError> {
    if buf.len() < *at + n {
        return Err(ContainerError::Truncated {
            wanted: n,
            got: buf.len().saturating_sub(*at),
            field,
        });
    }
    let slice = &buf[*at..*at + n];
    *at += n;
    Ok(slice)
}

fn read_u32_be(buf: &[u8], at: &mut usize, field: &'static str) -> Result<u32, ContainerError> {
    let slice = read_exact(buf, at, 4, field)?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

impl SealedFile {
    pub fn to_bytes(&self) -> Result<Vec<u8>, ContainerError> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(1);
        out.push(self.suite_id);

        let manifest_json = self.manifest.to_json()?;
        out.extend_from_slice(&(manifest_json.len() as u32).to_be_bytes());
        out.extend_from_slice(&manifest_json);

        let wrapped_bytes = serde_json::to_vec(&self.wrapped_dek)?;
        out.extend_from_slice(&(wrapped_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&wrapped_bytes);

        out.extend_from_slice(&self.aead_nonce);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);

        Ok(out)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ContainerError> {
        let mut at = 0usize;
        let magic = read_exact(data, &mut at, 6, "magic")?;
        if magic != MAGIC {
            return Err(ContainerError::BadMagic { got: magic.to_vec() });
        }
        let hdr = read_exact(data, &mut at, 2, "version/suite")?;
        let fmt_ver = hdr[0];
        let suite_id = hdr[1];
        if fmt_ver != 1 {
            return Err(ContainerError::UnsupportedVersion(fmt_ver));
        }

        let mlen = read_u32_be(data, &mut at, "manifest_len")? as usize;
        if mlen > MAX_MANIFEST_BYTES {
            return Err(ContainerError::Oversized {
                field: "manifest",
                got: mlen,
                max: MAX_MANIFEST_BYTES,
            });
        }
        let manifest_bytes = read_exact(data, &mut at, mlen, "manifest")?;
        let manifest = Manifest::from_json(manifest_bytes)?;
        let expected_suite_id = suite_id_for_manifest(&manifest.suite)
            .ok_or_else(|| ContainerError::UnsupportedManifestSuite(manifest.suite.clone()))?;
        if suite_id != expected_suite_id {
            return Err(ContainerError::SuiteMismatch {
                header: suite_id,
                manifest_suite: manifest.suite.clone(),
            });
        }

        let wlen = read_u32_be(data, &mut at, "wrapped_dek_len")? as usize;
        if wlen > MAX_WRAPPED_DEK_BYTES {
            return Err(ContainerError::Oversized {
                field: "wrapped_dek",
                got: wlen,
                max: MAX_WRAPPED_DEK_BYTES,
            });
        }
        let wrapped_bytes = read_exact(data, &mut at, wlen, "wrapped_dek")?;
        let wrapped_dek: serde_json::Value = serde_json::from_slice(wrapped_bytes)?;

        let nonce_slice = read_exact(data, &mut at, 24, "aead_nonce")?;
        let mut aead_nonce = [0u8; 24];
        aead_nonce.copy_from_slice(nonce_slice);

        let clen = read_u32_be(data, &mut at, "ciphertext_len")? as usize;
        if clen > MAX_CIPHERTEXT_BYTES {
            return Err(ContainerError::Oversized {
                field: "ciphertext",
                got: clen,
                max: MAX_CIPHERTEXT_BYTES,
            });
        }
        let ciphertext = read_exact(data, &mut at, clen, "ciphertext")?.to_vec();
        if at != data.len() {
            return Err(ContainerError::TrailingBytes(data.len() - at));
        }

        Ok(SealedFile {
            manifest,
            wrapped_dek,
            aead_nonce,
            ciphertext,
            suite_id,
        })
    }
}

// -------------------------- High-level API --------------------------

/// Seal plaintext for a single recipient.
pub fn seal(
    plaintext: &[u8],
    manifest: &mut Manifest,
    issuer_ed25519_priv: &[u8],
    recipient_x25519_pub: &[u8],
) -> Result<Vec<u8>, ContainerError> {
    // Preconditions as explicit checks (not asserts — python -O safety parity).
    if manifest.content_hash != crypto::content_hash(plaintext) {
        return Err(ContainerError::Precondition(
            "manifest.content_hash != sha256(plaintext)",
        ));
    }
    if manifest.size_bytes != plaintext.len() as u64 {
        return Err(ContainerError::Precondition(
            "manifest.size_bytes != len(plaintext)",
        ));
    }
    let recipient = manifest
        .recipient
        .as_ref()
        .ok_or(ContainerError::Precondition("manifest.recipient is None"))?;
    if recipient.x25519_pub != hex::encode(recipient_x25519_pub) {
        return Err(ContainerError::Precondition(
            "manifest.recipient.x25519_pub mismatch with recipient pubkey",
        ));
    }
    if recipient_x25519_pub.len() != 32 {
        return Err(ContainerError::Precondition("recipient pubkey must be 32 bytes"));
    }
    if issuer_ed25519_priv.len() != 32 {
        return Err(ContainerError::Precondition("issuer priv key must be 32 bytes"));
    }

    manifest.sign(issuer_ed25519_priv)?;

    let dek = crypto::random_dek();
    let wrapped = crypto::wrap_dek_for_recipient(dek.as_ref(), recipient_x25519_pub)?;
    let aad = manifest.content_hash.as_bytes();
    let (nonce, ct) = crypto::aead_encrypt(dek.as_ref(), plaintext, aad)?;

    let sf = SealedFile {
        manifest: manifest.clone(),
        wrapped_dek: wrapped.to_json_hex(),
        aead_nonce: nonce,
        ciphertext: ct,
        suite_id: SUITE_CLASSIC_V1_ID,
    };
    sf.to_bytes()
}

/// Open a sealed blob. Returns (plaintext, manifest).
pub fn open_sealed(
    blob: &[u8],
    recipient_x25519_priv: &[u8],
    trusted_issuer_pubs: Option<&[String]>,
    policy_ctx: Option<&PolicyContext>,
) -> Result<(Vec<u8>, Manifest), ContainerError> {
    if recipient_x25519_priv.len() != 32 {
        return Err(ContainerError::Precondition("recipient priv key must be 32 bytes"));
    }

    let sf = SealedFile::from_bytes(blob)?;
    if !sf.manifest.verify()? {
        return Err(ContainerError::Manifest(ManifestError::MissingSignature));
    }

    if let Some(trusted) = trusted_issuer_pubs {
        if !trusted.iter().any(|p| p == &sf.manifest.issuer_ed25519_pub) {
            return Err(ContainerError::Precondition("issuer not in trusted set"));
        }
    }

    // Policy enforcement (time-based) — expanded version in oversight-policy crate later
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Some(na) = sf.manifest.policy.get("not_after").and_then(|v| v.as_i64()) {
        if now > na {
            return Err(ContainerError::Precondition("file expired (not_after)"));
        }
    }
    if let Some(nb) = sf.manifest.policy.get("not_before").and_then(|v| v.as_i64()) {
        if now < nb {
            return Err(ContainerError::Precondition("file not yet released (not_before)"));
        }
    }

    // DEK unwrap: try slots if present, else single wrap
    let dek = if let Some(slots) = sf.wrapped_dek.get("slots").and_then(|v| v.as_array()) {
        let mut recovered = None;
        for slot in slots {
            let wrapped = WrappedDek::from_json_hex(slot)?;
            if let Ok(dek) = crypto::unwrap_dek(&wrapped, recipient_x25519_priv) {
                recovered = Some(dek);
                break;
            }
        }
        recovered.ok_or(ContainerError::NoDecryptableSlot { slots: slots.len() })?
    } else {
        let wrapped = WrappedDek::from_json_hex(&sf.wrapped_dek)?;
        crypto::unwrap_dek(&wrapped, recipient_x25519_priv)?
    };

    let aad = sf.manifest.content_hash.as_bytes();
    let plaintext = crypto::aead_decrypt(dek.as_ref(), &sf.aead_nonce, &sf.ciphertext, aad)?;

    if crypto::content_hash(&plaintext) != sf.manifest.content_hash {
        return Err(ContainerError::HashMismatch);
    }

    // Count only successful recipient decryptions. Failed key guesses cannot
    // burn max_opens, but a policy failure still prevents plaintext release.
    oversight_policy::record_open(&sf.manifest, policy_ctx)?;

    Ok((plaintext, sf.manifest))
}

/// Seal `plaintext` for a hardware-backed P-256 recipient (`OSGT-HW-P256-v1`).
///
/// Mirrors [`seal`] but consumes the recipient's P-256 SEC1 uncompressed
/// public key (65 bytes) instead of an X25519 public key. The manifest's
/// `suite` field must already be set to `oversight_crypto::SUITE_HW_P256_V1`
/// and the recipient's `p256_pub` field must hex-match `recipient_p256_sec1_pub`.
/// All other invariants (content_hash, size_bytes, signature) match [`seal`].
pub fn seal_hw_p256(
    plaintext: &[u8],
    manifest: &mut Manifest,
    issuer_ed25519_priv: &[u8],
    recipient_p256_sec1_pub: &[u8],
) -> Result<Vec<u8>, ContainerError> {
    if manifest.content_hash != crypto::content_hash(plaintext) {
        return Err(ContainerError::Precondition(
            "manifest.content_hash != sha256(plaintext)",
        ));
    }
    if manifest.size_bytes != plaintext.len() as u64 {
        return Err(ContainerError::Precondition(
            "manifest.size_bytes != len(plaintext)",
        ));
    }
    if manifest.suite != crypto::SUITE_HW_P256_V1 {
        return Err(ContainerError::Precondition(
            "manifest.suite must be OSGT-HW-P256-v1 for seal_hw_p256",
        ));
    }
    let recipient = manifest
        .recipient
        .as_ref()
        .ok_or(ContainerError::Precondition("manifest.recipient is None"))?;
    let p256_pub_field = recipient
        .p256_pub
        .as_ref()
        .ok_or(ContainerError::Precondition(
            "manifest.recipient.p256_pub is None for OSGT-HW-P256-v1",
        ))?;
    if p256_pub_field != &hex::encode(recipient_p256_sec1_pub) {
        return Err(ContainerError::Precondition(
            "manifest.recipient.p256_pub mismatch with recipient pubkey",
        ));
    }
    if recipient_p256_sec1_pub.len() != crypto::P256_PUBLIC_KEY_LEN {
        return Err(ContainerError::Precondition(
            "recipient p256 pubkey must be 65 bytes (SEC1 uncompressed)",
        ));
    }
    if issuer_ed25519_priv.len() != 32 {
        return Err(ContainerError::Precondition("issuer priv key must be 32 bytes"));
    }

    manifest.sign(issuer_ed25519_priv)?;

    let dek = crypto::random_dek();
    let wrapped = crypto::wrap_dek_for_recipient_p256(dek.as_ref(), recipient_p256_sec1_pub)?;
    let aad = manifest.content_hash.as_bytes();
    let (nonce, ct) = crypto::aead_encrypt(dek.as_ref(), plaintext, aad)?;

    let sf = SealedFile {
        manifest: manifest.clone(),
        wrapped_dek: wrapped.to_json_hex(),
        aead_nonce: nonce,
        ciphertext: ct,
        suite_id: SUITE_HW_P256_V1_ID,
    };
    sf.to_bytes()
}

/// Polymorphic open that dispatches on the container's `suite_id` and
/// delegates the recipient-side ECDH to a [`KeyProvider`]. This is the entry
/// point hardware-backed open paths (PIV via PKCS#11) use without changing
/// the seal-side or container layout.
///
/// Currently dispatches:
///   - `SUITE_CLASSIC_V1_ID` (1) ← provider must be [`KeyAlgorithm::X25519`]
///   - `SUITE_HW_P256_V1_ID`  (3) ← provider must be [`KeyAlgorithm::P256`]
///
/// Hybrid (`SUITE_HYBRID_V1_ID` = 2) is not yet wired through this entry
/// point because it needs both X25519 and ML-KEM-768 secrets at unwrap time
/// (X-wing binding); a hybrid-aware provider trait extension lands with the
/// follow-up `HybridKeyProvider`.
pub fn open_sealed_with_provider(
    blob: &[u8],
    provider: &dyn KeyProvider,
    trusted_issuer_pubs: Option<&[String]>,
    policy_ctx: Option<&PolicyContext>,
) -> Result<(Vec<u8>, Manifest), ContainerError> {
    let sf = SealedFile::from_bytes(blob)?;
    if !sf.manifest.verify()? {
        return Err(ContainerError::Manifest(ManifestError::MissingSignature));
    }

    if let Some(trusted) = trusted_issuer_pubs {
        if !trusted.iter().any(|p| p == &sf.manifest.issuer_ed25519_pub) {
            return Err(ContainerError::Precondition("issuer not in trusted set"));
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if let Some(na) = sf.manifest.policy.get("not_after").and_then(|v| v.as_i64()) {
        if now > na {
            return Err(ContainerError::Precondition("file expired (not_after)"));
        }
    }
    if let Some(nb) = sf.manifest.policy.get("not_before").and_then(|v| v.as_i64()) {
        if now < nb {
            return Err(ContainerError::Precondition("file not yet released (not_before)"));
        }
    }

    let dek = match (sf.suite_id, provider.algorithm()) {
        (SUITE_CLASSIC_V1_ID, KeyAlgorithm::X25519) => {
            let wrapped = WrappedDek::from_json_hex(&sf.wrapped_dek)?;
            crypto::unwrap_dek_with_provider(&wrapped, provider)?
        }
        (SUITE_HW_P256_V1_ID, KeyAlgorithm::P256) => {
            let wrapped = WrappedDekP256::from_json_hex(&sf.wrapped_dek)?;
            crypto::unwrap_dek_with_provider_p256(&wrapped, provider)?
        }
        (SUITE_HYBRID_V1_ID, _) => {
            return Err(ContainerError::Precondition(
                "OSGT-HYBRID-v1 open via provider not yet supported; use the legacy open path",
            ));
        }
        (other_suite, _other_alg) => {
            return Err(ContainerError::Precondition(
                if other_suite == SUITE_CLASSIC_V1_ID || other_suite == SUITE_HW_P256_V1_ID {
                    "provider algorithm does not match container suite_id"
                } else {
                    "unsupported suite_id in container header"
                },
            ));
        }
    };

    let aad = sf.manifest.content_hash.as_bytes();
    let plaintext = crypto::aead_decrypt(dek.as_ref(), &sf.aead_nonce, &sf.ciphertext, aad)?;

    if crypto::content_hash(&plaintext) != sf.manifest.content_hash {
        return Err(ContainerError::HashMismatch);
    }

    oversight_policy::record_open(&sf.manifest, policy_ctx)?;

    Ok((plaintext, sf.manifest))
}

/// Fail closed until the manifest schema can explicitly bind every recipient.
pub fn seal_multi(
    plaintext: &[u8],
    manifest: &mut Manifest,
    issuer_ed25519_priv: &[u8],
    recipient_x25519_pubs: &[&[u8]],
) -> Result<Vec<u8>, ContainerError> {
    let _ = (plaintext, manifest, issuer_ed25519_priv, recipient_x25519_pubs);
    Err(ContainerError::Precondition(
        "seal_multi disabled until manifests can bind all recipients",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oversight_crypto::{ClassicIdentity, FileKeyProvider, SoftwareP256Identity, SoftwareP256KeyProvider};
    use oversight_manifest::Recipient;

    fn make_manifest(issuer: &ClassicIdentity, recipient: &ClassicIdentity, plaintext: &[u8]) -> Manifest {
        Manifest::new(
            "doc.txt",
            crypto::content_hash(plaintext),
            plaintext.len() as u64,
            "issuer@test",
            hex::encode(issuer.ed25519_pub),
            Recipient {
                recipient_id: "alice@test".into(),
                x25519_pub: hex::encode(recipient.x25519_pub),
                ed25519_pub: None,
                p256_pub: None,
            },
            "https://registry.test",
            "text/plain",
            None,
            None,
            "GLOBAL",
        )
    }

    fn make_hw_manifest(
        issuer: &ClassicIdentity,
        recipient_p256_pub_sec1: &[u8],
        plaintext: &[u8],
    ) -> Manifest {
        let mut m = Manifest::new(
            "doc.txt",
            crypto::content_hash(plaintext),
            plaintext.len() as u64,
            "issuer@test",
            hex::encode(issuer.ed25519_pub),
            Recipient {
                recipient_id: "yubi@test".into(),
                x25519_pub: String::new(),
                ed25519_pub: None,
                p256_pub: Some(hex::encode(recipient_p256_pub_sec1)),
            },
            "https://registry.test",
            "text/plain",
            None,
            None,
            "GLOBAL",
        );
        m.suite = crypto::SUITE_HW_P256_V1.to_string();
        m
    }

    #[test]
    fn seal_open_round_trip() {
        let issuer = ClassicIdentity::generate();
        let recipient = ClassicIdentity::generate();
        let plaintext = b"This is my secret document.";
        let mut m = make_manifest(&issuer, &recipient, plaintext);
        let blob = seal(plaintext, &mut m, issuer.ed25519_priv.as_ref(), &recipient.x25519_pub).unwrap();
        let (pt, manifest) = open_sealed(&blob, recipient.x25519_priv.as_ref(), None, None).unwrap();
        assert_eq!(pt, plaintext);
        assert_eq!(manifest.file_id, m.file_id);
    }

    #[test]
    fn wrong_recipient_rejected() {
        let issuer = ClassicIdentity::generate();
        let alice = ClassicIdentity::generate();
        let bob = ClassicIdentity::generate();
        let plaintext = b"secret";
        let mut m = make_manifest(&issuer, &alice, plaintext);
        let blob = seal(plaintext, &mut m, issuer.ed25519_priv.as_ref(), &alice.x25519_pub).unwrap();
        // Bob tries to open — should fail at AEAD stage
        assert!(open_sealed(&blob, bob.x25519_priv.as_ref(), None, None).is_err());
    }

    #[test]
    fn ciphertext_tamper_rejected() {
        let issuer = ClassicIdentity::generate();
        let alice = ClassicIdentity::generate();
        let plaintext = b"secret";
        let mut m = make_manifest(&issuer, &alice, plaintext);
        let mut blob = seal(plaintext, &mut m, issuer.ed25519_priv.as_ref(), &alice.x25519_pub).unwrap();
        let len = blob.len();
        blob[len - 1] ^= 0x01;
        assert!(open_sealed(&blob, alice.x25519_priv.as_ref(), None, None).is_err());
    }

    #[test]
    fn bad_magic_rejected() {
        let mut blob = vec![0u8; 100];
        blob[0..6].copy_from_slice(b"FAKE\x00\x00");
        assert!(SealedFile::from_bytes(&blob).is_err());
    }

    #[test]
    fn oversized_manifest_rejected() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&MAGIC);
        blob.push(1);
        blob.push(1);
        // Claim a 5MB manifest
        blob.extend_from_slice(&(5u32 * 1024 * 1024).to_be_bytes());
        blob.resize(100, 0);
        match SealedFile::from_bytes(&blob) {
            Err(ContainerError::Oversized { field: "manifest", .. }) => (),
            other => panic!("expected Oversized manifest error, got {:?}", other),
        }
    }

    #[test]
    fn truncated_file_rejected() {
        // Just a magic byte, nothing else
        let blob = MAGIC.to_vec();
        assert!(SealedFile::from_bytes(&blob).is_err());
    }

    #[test]
    fn seal_open_with_provider_classic_round_trip() {
        // open_sealed_with_provider must accept a FileKeyProvider against a
        // legacy classic-suite container and produce identical plaintext to
        // open_sealed. This is the backward-compat guarantee that lets
        // callers migrate to the polymorphic open path.
        let issuer = ClassicIdentity::generate();
        let recipient = ClassicIdentity::generate();
        let plaintext = b"classic via provider path";
        let mut m = make_manifest(&issuer, &recipient, plaintext);
        let blob = seal(plaintext, &mut m, issuer.ed25519_priv.as_ref(), &recipient.x25519_pub).unwrap();

        let provider = FileKeyProvider::new(recipient);
        let (pt, manifest) = open_sealed_with_provider(&blob, &provider, None, None).unwrap();
        assert_eq!(pt, plaintext);
        assert_eq!(manifest.file_id, m.file_id);
    }

    #[test]
    fn seal_hw_p256_open_with_provider_round_trip() {
        let issuer = ClassicIdentity::generate();
        let recipient = SoftwareP256Identity::generate();
        let recipient_pub_sec1 = *recipient.public_key_sec1();
        let plaintext = b"sealed for a hardware-backed recipient";

        let mut m = make_hw_manifest(&issuer, &recipient_pub_sec1, plaintext);
        let blob = seal_hw_p256(
            plaintext,
            &mut m,
            issuer.ed25519_priv.as_ref(),
            &recipient_pub_sec1,
        )
        .unwrap();

        // Container header must carry the hardware suite id.
        assert_eq!(blob[7], SUITE_HW_P256_V1_ID);

        let provider = SoftwareP256KeyProvider::new(recipient);
        let (pt, manifest) = open_sealed_with_provider(&blob, &provider, None, None).unwrap();
        assert_eq!(pt, plaintext);
        assert_eq!(manifest.suite, crypto::SUITE_HW_P256_V1);
    }

    #[test]
    fn seal_hw_p256_wrong_recipient_provider_rejected() {
        let issuer = ClassicIdentity::generate();
        let alice = SoftwareP256Identity::generate();
        let alice_pub = *alice.public_key_sec1();
        let bob = SoftwareP256Identity::generate();
        let plaintext = b"for alice only";

        let mut m = make_hw_manifest(&issuer, &alice_pub, plaintext);
        let blob = seal_hw_p256(plaintext, &mut m, issuer.ed25519_priv.as_ref(), &alice_pub).unwrap();

        let bob_provider = SoftwareP256KeyProvider::new(bob);
        assert!(
            open_sealed_with_provider(&blob, &bob_provider, None, None).is_err(),
            "Bob's provider must not unwrap a HW envelope addressed to Alice"
        );
    }

    #[test]
    fn open_with_provider_rejects_cross_suite_provider() {
        // X25519 provider must not be silently accepted for a P-256 envelope.
        let issuer = ClassicIdentity::generate();
        let alice_p256 = SoftwareP256Identity::generate();
        let alice_pub = *alice_p256.public_key_sec1();
        let plaintext = b"hw envelope";

        let mut m = make_hw_manifest(&issuer, &alice_pub, plaintext);
        let blob = seal_hw_p256(plaintext, &mut m, issuer.ed25519_priv.as_ref(), &alice_pub).unwrap();

        let wrong_alg = FileKeyProvider::new(ClassicIdentity::generate());
        let res = open_sealed_with_provider(&blob, &wrong_alg, None, None);
        assert!(res.is_err(), "X25519 provider must not be accepted for an OSGT-HW-P256-v1 container");
    }

    #[test]
    fn seal_hw_p256_rejects_classic_suite_in_manifest() {
        // If the manifest still says CLASSIC, seal_hw_p256 must refuse rather
        // than write a header that disagrees with the signed manifest.
        let issuer = ClassicIdentity::generate();
        let alice_p256 = SoftwareP256Identity::generate();
        let alice_pub = *alice_p256.public_key_sec1();
        let plaintext = b"hw envelope";

        let mut m = make_hw_manifest(&issuer, &alice_pub, plaintext);
        m.suite = crypto::SUITE_CLASSIC_V1.to_string();
        let res = seal_hw_p256(plaintext, &mut m, issuer.ed25519_priv.as_ref(), &alice_pub);
        assert!(res.is_err(), "seal_hw_p256 must require manifest.suite == OSGT-HW-P256-v1");
    }

    #[test]
    fn suite_id_for_manifest_covers_all_known_suites() {
        // Each manifest suite must map to a unique container header byte;
        // adding a new suite without updating this match would otherwise
        // silently shape-shift into an UnsupportedManifestSuite at seal time.
        assert_eq!(suite_id_for_manifest(crypto::SUITE_CLASSIC_V1), Some(SUITE_CLASSIC_V1_ID));
        assert_eq!(suite_id_for_manifest(crypto::SUITE_HYBRID_V1), Some(SUITE_HYBRID_V1_ID));
        assert_eq!(suite_id_for_manifest(crypto::SUITE_HW_P256_V1), Some(SUITE_HW_P256_V1_ID));
        assert_eq!(suite_id_for_manifest("OSGT-UNKNOWN"), None);
    }

    #[test]
    fn suite_id_tamper_rejected() {
        let issuer = ClassicIdentity::generate();
        let alice = ClassicIdentity::generate();
        let plaintext = b"secret";
        let mut m = make_manifest(&issuer, &alice, plaintext);
        let mut blob = seal(plaintext, &mut m, issuer.ed25519_priv.as_ref(), &alice.x25519_pub).unwrap();
        blob[7] ^= 0x01;
        match SealedFile::from_bytes(&blob) {
            Err(ContainerError::SuiteMismatch { header, manifest_suite }) => {
                assert_eq!(header, 0);
                assert_eq!(manifest_suite, crypto::SUITE_CLASSIC_V1);
            }
            other => panic!("expected SuiteMismatch, got {:?}", other),
        }
    }

    #[test]
    fn trailing_bytes_rejected() {
        let issuer = ClassicIdentity::generate();
        let alice = ClassicIdentity::generate();
        let plaintext = b"secret";
        let mut m = make_manifest(&issuer, &alice, plaintext);
        let mut blob = seal(plaintext, &mut m, issuer.ed25519_priv.as_ref(), &alice.x25519_pub).unwrap();
        blob.extend_from_slice(b"junk");
        match SealedFile::from_bytes(&blob) {
            Err(ContainerError::TrailingBytes(4)) => (),
            other => panic!("expected TrailingBytes, got {:?}", other),
        }
    }

    #[test]
    fn expired_file_rejected() {
        let issuer = ClassicIdentity::generate();
        let alice = ClassicIdentity::generate();
        let plaintext = b"secret";
        let mut m = make_manifest(&issuer, &alice, plaintext);
        m.policy["not_after"] = serde_json::json!(1000);  // long ago
        let blob = seal(plaintext, &mut m, issuer.ed25519_priv.as_ref(), &alice.x25519_pub).unwrap();
        match open_sealed(&blob, alice.x25519_priv.as_ref(), None, None) {
            Err(ContainerError::Precondition("file expired (not_after)")) => (),
            other => panic!("expected expiry error, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn max_opens_counts_only_successful_decrypts() {
        let issuer = ClassicIdentity::generate();
        let alice = ClassicIdentity::generate();
        let bob = ClassicIdentity::generate();
        let plaintext = b"limited";
        let mut m = make_manifest(&issuer, &alice, plaintext);
        m.policy["max_opens"] = serde_json::json!(1);
        let blob = seal(plaintext, &mut m, issuer.ed25519_priv.as_ref(), &alice.x25519_pub).unwrap();

        let dir = std::env::temp_dir().join(format!(
            "oversight-container-policy-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let ctx = oversight_policy::PolicyContext::local_only(&dir).unwrap();

        assert!(open_sealed(&blob, bob.x25519_priv.as_ref(), None, Some(&ctx)).is_err());
        assert!(open_sealed(&blob, alice.x25519_priv.as_ref(), None, Some(&ctx)).is_ok());
        assert!(open_sealed(&blob, alice.x25519_priv.as_ref(), None, Some(&ctx)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seal_multi_fails_closed_until_manifest_schema_exists() {
        let issuer = ClassicIdentity::generate();
        let alice = ClassicIdentity::generate();
        let bob = ClassicIdentity::generate();
        let carol = ClassicIdentity::generate();

        let plaintext = b"shared document for cohort";
        let mut m = Manifest::new(
            "cohort.txt",
            crypto::content_hash(plaintext),
            plaintext.len() as u64,
            "issuer@test",
            hex::encode(issuer.ed25519_pub),
            Recipient {
                recipient_id: "cohort".into(),
                x25519_pub: hex::encode(alice.x25519_pub), // placeholder
                ed25519_pub: None,
                p256_pub: None,
            },
            "https://registry.test",
            "text/plain",
            None,
            None,
            "GLOBAL",
        );
        let recipients: Vec<&[u8]> = vec![&alice.x25519_pub, &bob.x25519_pub, &carol.x25519_pub];
        match seal_multi(plaintext, &mut m, issuer.ed25519_priv.as_ref(), &recipients) {
            Err(ContainerError::Precondition(msg)) => assert!(msg.contains("seal_multi disabled")),
            other => panic!("expected seal_multi to fail closed, got {:?}", other.is_ok()),
        }
    }
}
