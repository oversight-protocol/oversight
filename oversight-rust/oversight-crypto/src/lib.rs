//! # oversight-crypto
//!
//! Cryptographic primitives for Oversight.
//!
//! ## Design
//!
//! NIST-standardized, peer-reviewed primitives only. NO custom crypto.
//!
//! ### Classical suite (SNTL-CLASSIC-v1 on-the-wire, maintained for compatibility)
//! - **X25519** — ECDH key agreement
//! - **Ed25519** — digital signatures
//! - **XChaCha20-Poly1305** — authenticated encryption (AEAD)
//! - **HKDF-SHA256** — key derivation
//!
//! ### Post-quantum hybrid suite (OSGT-HYBRID-v1)
//! - **X25519 + ML-KEM-768** — hybrid key encapsulation (requires both be broken)
//! - **Ed25519 + ML-DSA-65** — hybrid signatures
//!
//! PQ primitives are gated behind the `pq` feature and require `liboqs`.
//!
//! ## Memory safety
//!
//! All secret bytes are wrapped in `zeroize::Zeroizing` so they scrub on drop.
//! Rust's ownership rules prevent the classic "use-after-free" class of bugs
//! that plague C cryptographic libraries.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    XChaCha20Poly1305,
};
use ed25519_dalek::{
    Signature as EdSignature, Signer, SigningKey as EdSigningKey, Verifier,
    VerifyingKey as EdVerifyingKey,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};
use p256::{
    ecdh::diffie_hellman as p256_diffie_hellman,
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey as P256PublicKey, SecretKey as P256SecretKey,
};

pub const XCHACHA_KEY_LEN: usize = 32;
pub const XCHACHA_NONCE_LEN: usize = 24;
pub const X25519_KEY_LEN: usize = 32;
pub const ED25519_KEY_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const DEK_LEN: usize = 32;
/// P-256 public key in SEC1 uncompressed encoding (`0x04 || X || Y`).
pub const P256_PUBLIC_KEY_LEN: usize = 65;

pub const SUITE_CLASSIC_V1: &str = "OSGT-CLASSIC-v1";
pub const SUITE_HYBRID_V1: &str = "OSGT-HYBRID-v1";
/// Hardware-backed recipients use P-256 ECDH so PIV-compatible tokens
/// (YubiKey, Nitrokey, OnlyKey) can perform the key agreement on-device
/// without exposing the private scalar. See `docs/HARDWARE_KEYS.md`.
pub const SUITE_HW_P256_V1: &str = "OSGT-HW-P256-v1";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("AEAD decryption failed (tag mismatch or key wrong)")]
    AeadFailed,
    #[error("signature verification failed")]
    BadSignature,
    #[error("malformed hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("HKDF error")]
    Hkdf,
    #[error("missing wrapped-DEK field: {0}")]
    MissingField(&'static str),
}

// -------------------------- Identity --------------------------

/// A recipient or issuer identity: X25519 for encryption, Ed25519 for signing.
///
/// Secret material lives in `Zeroizing` so it scrubs on drop.
pub struct ClassicIdentity {
    pub x25519_priv: Zeroizing<[u8; X25519_KEY_LEN]>,
    pub x25519_pub: [u8; X25519_KEY_LEN],
    pub ed25519_priv: Zeroizing<[u8; ED25519_KEY_LEN]>,
    pub ed25519_pub: [u8; ED25519_KEY_LEN],
}

impl ClassicIdentity {
    pub fn generate() -> Self {
        let mut rng = OsRng;

        // X25519
        let mut x_priv_bytes = [0u8; X25519_KEY_LEN];
        rng.fill_bytes(&mut x_priv_bytes);
        let x_static = X25519StaticSecret::from(x_priv_bytes);
        let x_pub = X25519PublicKey::from(&x_static);

        // Ed25519
        let mut ed_seed = [0u8; ED25519_KEY_LEN];
        rng.fill_bytes(&mut ed_seed);
        let ed_signing = EdSigningKey::from_bytes(&ed_seed);
        let ed_verifying = ed_signing.verifying_key();

        Self {
            x25519_priv: Zeroizing::new(x_static.to_bytes()),
            x25519_pub: x_pub.to_bytes(),
            ed25519_priv: Zeroizing::new(ed_seed),
            ed25519_pub: ed_verifying.to_bytes(),
        }
    }

    pub fn from_raw(
        x25519_priv: [u8; X25519_KEY_LEN],
        ed25519_priv: [u8; ED25519_KEY_LEN],
    ) -> Self {
        let x_static = X25519StaticSecret::from(x25519_priv);
        let x_pub = X25519PublicKey::from(&x_static);
        let ed_signing = EdSigningKey::from_bytes(&ed25519_priv);
        let ed_verifying = ed_signing.verifying_key();
        Self {
            x25519_priv: Zeroizing::new(x25519_priv),
            x25519_pub: x_pub.to_bytes(),
            ed25519_priv: Zeroizing::new(ed25519_priv),
            ed25519_pub: ed_verifying.to_bytes(),
        }
    }
}

// -------------------------- AEAD --------------------------

/// XChaCha20-Poly1305 encrypt. Returns (nonce, ciphertext||tag).
/// 24-byte nonces are safe to random-generate (2^96 security margin).
pub fn aead_encrypt(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; XCHACHA_NONCE_LEN], Vec<u8>), CryptoError> {
    if key.len() != XCHACHA_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: XCHACHA_KEY_LEN,
            got: key.len(),
        });
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::AeadFailed)?;
    let mut nonce_arr = [0u8; XCHACHA_NONCE_LEN];
    nonce_arr.copy_from_slice(&nonce);
    Ok((nonce_arr, ct))
}

pub fn aead_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != XCHACHA_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: XCHACHA_KEY_LEN,
            got: key.len(),
        });
    }
    if nonce.len() != XCHACHA_NONCE_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: XCHACHA_NONCE_LEN,
            got: nonce.len(),
        });
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::AeadFailed)
}

// -------------------------- Key agreement --------------------------

/// Classical ECIES-style DEK wrap using X25519 + HKDF-SHA256 + XChaCha20-Poly1305.
///
/// Returns a wrapped-envelope with hex-encoded fields suitable for JSON embed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedDek {
    pub ephemeral_pub: [u8; X25519_KEY_LEN],
    pub nonce: [u8; XCHACHA_NONCE_LEN],
    pub wrapped_dek: Vec<u8>,
}

impl WrappedDek {
    pub fn to_json_hex(&self) -> serde_json::Value {
        serde_json::json!({
            "ephemeral_pub": hex::encode(self.ephemeral_pub),
            "nonce": hex::encode(self.nonce),
            "wrapped_dek": hex::encode(&self.wrapped_dek),
        })
    }

    pub fn from_json_hex(v: &serde_json::Value) -> Result<Self, CryptoError> {
        fn field(v: &serde_json::Value, name: &'static str) -> Result<String, CryptoError> {
            v.get(name)
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .ok_or(CryptoError::MissingField(name))
        }
        let eph_bytes = hex::decode(field(v, "ephemeral_pub")?)?;
        let nonce_bytes = hex::decode(field(v, "nonce")?)?;
        let wrapped = hex::decode(field(v, "wrapped_dek")?)?;
        if eph_bytes.len() != X25519_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: X25519_KEY_LEN,
                got: eph_bytes.len(),
            });
        }
        if nonce_bytes.len() != XCHACHA_NONCE_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: XCHACHA_NONCE_LEN,
                got: nonce_bytes.len(),
            });
        }
        let mut eph = [0u8; X25519_KEY_LEN];
        eph.copy_from_slice(&eph_bytes);
        let mut nonce = [0u8; XCHACHA_NONCE_LEN];
        nonce.copy_from_slice(&nonce_bytes);
        Ok(WrappedDek { ephemeral_pub: eph, nonce, wrapped_dek: wrapped })
    }
}

pub fn wrap_dek_for_recipient(
    dek: &[u8],
    recipient_x25519_pub: &[u8],
) -> Result<WrappedDek, CryptoError> {
    if recipient_x25519_pub.len() != X25519_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: X25519_KEY_LEN,
            got: recipient_x25519_pub.len(),
        });
    }
    let mut eph_bytes = [0u8; X25519_KEY_LEN];
    OsRng.fill_bytes(&mut eph_bytes);
    let eph = X25519StaticSecret::from(eph_bytes);
    let eph_pub = X25519PublicKey::from(&eph);

    let mut peer_arr = [0u8; X25519_KEY_LEN];
    peer_arr.copy_from_slice(recipient_x25519_pub);
    let peer = X25519PublicKey::from(peer_arr);

    let shared = Zeroizing::new(eph.diffie_hellman(&peer).to_bytes());

    let hk = Hkdf::<Sha256>::new(None, shared.as_ref());
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(b"oversight-v1-dek-wrap", kek.as_mut())
        .map_err(|_| CryptoError::Hkdf)?;

    let (nonce, wrapped) = aead_encrypt(kek.as_ref(), dek, b"oversight-dek")?;
    Ok(WrappedDek { ephemeral_pub: eph_pub.to_bytes(), nonce, wrapped_dek: wrapped })
}

pub fn unwrap_dek(
    wrapped: &WrappedDek,
    recipient_x25519_priv: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if recipient_x25519_priv.len() != X25519_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: X25519_KEY_LEN,
            got: recipient_x25519_priv.len(),
        });
    }
    let mut priv_arr = [0u8; X25519_KEY_LEN];
    priv_arr.copy_from_slice(recipient_x25519_priv);
    let sk = X25519StaticSecret::from(priv_arr);
    priv_arr.zeroize();

    let peer = X25519PublicKey::from(wrapped.ephemeral_pub);
    let shared = Zeroizing::new(sk.diffie_hellman(&peer).to_bytes());

    let hk = Hkdf::<Sha256>::new(None, shared.as_ref());
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(b"oversight-v1-dek-wrap", kek.as_mut())
        .map_err(|_| CryptoError::Hkdf)?;

    let plaintext = aead_decrypt(
        kek.as_ref(),
        &wrapped.nonce,
        &wrapped.wrapped_dek,
        b"oversight-dek",
    )?;
    Ok(Zeroizing::new(plaintext))
}

// -------------------------- KeyProvider --------------------------

/// Algorithm a [`KeyProvider`] uses for ECDH.
///
/// `X25519` is the default Oversight suite (`OSGT-CLASSIC-v1`).
/// `P256` is reserved for hardware-backed providers per `docs/HARDWARE_KEYS.md`
/// (suite `OSGT-HW-P256-v1`); the wrap/unwrap implementations for P256 will
/// land alongside the first hardware [`KeyProvider`] and are deliberately not
/// part of this crate yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    X25519,
    P256,
}

/// Trait abstracting the recipient-side private-key operations needed to
/// open an Oversight sealed file. Holders of a hardware token (YubiKey,
/// Nitrokey, OnlyKey via PIV) can implement this without exposing the raw
/// private key bytes; the device performs ECDH internally and only the
/// shared secret crosses the trait boundary.
///
/// This trait is intentionally narrow. The wrap (sender) side does not need
/// it: an Oversight sender only ever holds the recipient's *public* key plus
/// a fresh ephemeral keypair the sender generates locally. Hardware delegation
/// is purely an unwrap-side concern.
///
/// Implementors must zero any in-memory secret material on drop. The default
/// [`FileKeyProvider`] delegates to `Zeroizing<[u8; 32]>` for that.
pub trait KeyProvider {
    /// The ECDH curve this provider uses.
    fn algorithm(&self) -> KeyAlgorithm;

    /// The provider's public key, in the curve's standard wire format
    /// (32 bytes raw for X25519, SEC1 65 bytes uncompressed for P-256).
    fn public_key(&self) -> &[u8];

    /// Run ECDH against `peer_pub` (typically the wrapped envelope's
    /// `ephemeral_pub`) and return the resulting shared secret. The shared
    /// secret is wrapped in `Zeroizing` so it scrubs when dropped.
    ///
    /// Errors with [`CryptoError::InvalidKeyLength`] if `peer_pub` is wrong
    /// for the provider's curve, or with a backend-specific error wrapped
    /// by the impl.
    fn ecdh(&self, peer_pub: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

    /// Optional human-readable identifier for diagnostic logging. Hardware
    /// providers may surface a slot label; file-backed providers may surface
    /// the recipient_id from the identity JSON.
    fn label(&self) -> Option<&str> {
        None
    }
}

/// File-backed [`KeyProvider`] that wraps a [`ClassicIdentity`]. This is the
/// default Oversight provider: X25519 private key sits in process memory,
/// scrubbed on drop via [`Zeroizing`].
///
/// Hardware-backed providers (`PivKeyProvider`, etc.) live in separate
/// modules / feature-gated crates and implement the same trait so the
/// open/unwrap call sites do not change when callers swap providers.
pub struct FileKeyProvider {
    inner: ClassicIdentity,
    label: Option<String>,
}

impl FileKeyProvider {
    /// Wrap an existing [`ClassicIdentity`] without a label.
    pub fn new(identity: ClassicIdentity) -> Self {
        Self { inner: identity, label: None }
    }

    /// Wrap with a label (e.g., the recipient_id from the identity JSON).
    pub fn with_label(identity: ClassicIdentity, label: impl Into<String>) -> Self {
        Self { inner: identity, label: Some(label.into()) }
    }

    /// Borrow the underlying classic identity. Hardware providers won't be
    /// able to expose this; callers that depend on it are file-only.
    pub fn identity(&self) -> &ClassicIdentity {
        &self.inner
    }
}

impl KeyProvider for FileKeyProvider {
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::X25519
    }

    fn public_key(&self) -> &[u8] {
        &self.inner.x25519_pub
    }

    fn ecdh(&self, peer_pub: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if peer_pub.len() != X25519_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: X25519_KEY_LEN,
                got: peer_pub.len(),
            });
        }
        let mut peer_arr = [0u8; X25519_KEY_LEN];
        peer_arr.copy_from_slice(peer_pub);
        let peer = X25519PublicKey::from(peer_arr);

        let mut sk_bytes = [0u8; X25519_KEY_LEN];
        sk_bytes.copy_from_slice(self.inner.x25519_priv.as_ref());
        let sk = X25519StaticSecret::from(sk_bytes);
        sk_bytes.zeroize();

        let shared = sk.diffie_hellman(&peer).to_bytes();
        Ok(Zeroizing::new(shared.to_vec()))
    }

    fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
}

/// Recipient-side DEK unwrap that delegates the ECDH step to a
/// [`KeyProvider`]. Behaves identically to [`unwrap_dek`] when the provider
/// is a [`FileKeyProvider`], and is the entry point hardware-backed providers
/// will share once they ship.
pub fn unwrap_dek_with_provider(
    wrapped: &WrappedDek,
    provider: &dyn KeyProvider,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if provider.algorithm() != KeyAlgorithm::X25519 {
        // OSGT-CLASSIC-v1 wrap_dek_for_recipient produces an X25519 ephemeral
        // pub. Hardware providers on P-256 will need a sibling unwrap path
        // (OSGT-HW-P256-v1) once that suite ships; until then, refuse rather
        // than silently produce garbage.
        return Err(CryptoError::InvalidKeyLength {
            expected: X25519_KEY_LEN,
            got: provider.public_key().len(),
        });
    }

    let shared = provider.ecdh(&wrapped.ephemeral_pub)?;

    let hk = Hkdf::<Sha256>::new(None, shared.as_ref());
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(b"oversight-v1-dek-wrap", kek.as_mut())
        .map_err(|_| CryptoError::Hkdf)?;

    let plaintext = aead_decrypt(
        kek.as_ref(),
        &wrapped.nonce,
        &wrapped.wrapped_dek,
        b"oversight-dek",
    )?;
    Ok(Zeroizing::new(plaintext))
}

// -------------------------- P-256 (hardware-backed suite) -------------------

/// In-memory P-256 keypair. Mirrors [`ClassicIdentity`] but for the
/// `OSGT-HW-P256-v1` suite. Use this in tests and as a software fallback when
/// a hardware token is not plugged in. Real hardware-backed providers (PIV
/// over PKCS#11) implement [`KeyProvider`] without holding the private scalar
/// in process memory.
pub struct SoftwareP256Identity {
    secret: P256SecretKey,
    public_sec1: [u8; P256_PUBLIC_KEY_LEN],
}

impl SoftwareP256Identity {
    pub fn generate() -> Self {
        let secret = P256SecretKey::random(&mut OsRng);
        let public = secret.public_key();
        let encoded = public.to_encoded_point(false);
        let bytes = encoded.as_bytes();
        debug_assert_eq!(bytes.len(), P256_PUBLIC_KEY_LEN);
        let mut public_sec1 = [0u8; P256_PUBLIC_KEY_LEN];
        public_sec1.copy_from_slice(bytes);
        Self { secret, public_sec1 }
    }

    pub fn public_key_sec1(&self) -> &[u8; P256_PUBLIC_KEY_LEN] {
        &self.public_sec1
    }
}

/// Wrapped DEK for the `OSGT-HW-P256-v1` suite. Differs from [`WrappedDek`]
/// only in the size and encoding of the ephemeral public key (SEC1
/// uncompressed, 65 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedDekP256 {
    pub ephemeral_pub: [u8; P256_PUBLIC_KEY_LEN],
    pub nonce: [u8; XCHACHA_NONCE_LEN],
    pub wrapped_dek: Vec<u8>,
}

impl WrappedDekP256 {
    pub fn to_json_hex(&self) -> serde_json::Value {
        serde_json::json!({
            "suite": SUITE_HW_P256_V1,
            "ephemeral_pub": hex::encode(self.ephemeral_pub),
            "nonce": hex::encode(self.nonce),
            "wrapped_dek": hex::encode(&self.wrapped_dek),
        })
    }

    pub fn from_json_hex(v: &serde_json::Value) -> Result<Self, CryptoError> {
        fn field(v: &serde_json::Value, name: &'static str) -> Result<String, CryptoError> {
            v.get(name)
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .ok_or(CryptoError::MissingField(name))
        }
        let eph_bytes = hex::decode(field(v, "ephemeral_pub")?)?;
        let nonce_bytes = hex::decode(field(v, "nonce")?)?;
        let wrapped = hex::decode(field(v, "wrapped_dek")?)?;
        if eph_bytes.len() != P256_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: P256_PUBLIC_KEY_LEN,
                got: eph_bytes.len(),
            });
        }
        if nonce_bytes.len() != XCHACHA_NONCE_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: XCHACHA_NONCE_LEN,
                got: nonce_bytes.len(),
            });
        }
        let mut eph = [0u8; P256_PUBLIC_KEY_LEN];
        eph.copy_from_slice(&eph_bytes);
        let mut nonce = [0u8; XCHACHA_NONCE_LEN];
        nonce.copy_from_slice(&nonce_bytes);
        Ok(WrappedDekP256 { ephemeral_pub: eph, nonce, wrapped_dek: wrapped })
    }
}

/// Wrap a DEK for a P-256 recipient. The sender holds no hardware key; the
/// ephemeral keypair is generated locally in software and the recipient's
/// public key is consumed in SEC1 form.
pub fn wrap_dek_for_recipient_p256(
    dek: &[u8],
    recipient_p256_pub_sec1: &[u8],
) -> Result<WrappedDekP256, CryptoError> {
    if recipient_p256_pub_sec1.len() != P256_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: P256_PUBLIC_KEY_LEN,
            got: recipient_p256_pub_sec1.len(),
        });
    }
    let recipient_pub = P256PublicKey::from_sec1_bytes(recipient_p256_pub_sec1)
        .map_err(|_| CryptoError::InvalidKeyLength {
            expected: P256_PUBLIC_KEY_LEN,
            got: recipient_p256_pub_sec1.len(),
        })?;

    let eph_secret = P256SecretKey::random(&mut OsRng);
    let eph_pub = eph_secret.public_key();
    let eph_pub_encoded = eph_pub.to_encoded_point(false);
    let eph_pub_bytes = eph_pub_encoded.as_bytes();
    if eph_pub_bytes.len() != P256_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: P256_PUBLIC_KEY_LEN,
            got: eph_pub_bytes.len(),
        });
    }
    let mut eph_pub_arr = [0u8; P256_PUBLIC_KEY_LEN];
    eph_pub_arr.copy_from_slice(eph_pub_bytes);

    let shared = p256_diffie_hellman(eph_secret.to_nonzero_scalar(), recipient_pub.as_affine());
    let shared_bytes = shared.raw_secret_bytes();

    let hk = Hkdf::<Sha256>::new(None, shared_bytes.as_ref());
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(b"oversight-hw-p256-v1-dek-wrap", kek.as_mut())
        .map_err(|_| CryptoError::Hkdf)?;

    let (nonce, wrapped) = aead_encrypt(kek.as_ref(), dek, b"oversight-hw-p256-dek")?;
    Ok(WrappedDekP256 { ephemeral_pub: eph_pub_arr, nonce, wrapped_dek: wrapped })
}

/// Software-backed P-256 [`KeyProvider`]. Useful for tests and as a fallback
/// when the user does not have a hardware token available. A future
/// `PivKeyProvider` implements the same trait against PKCS#11.
pub struct SoftwareP256KeyProvider {
    inner: SoftwareP256Identity,
    label: Option<String>,
}

impl SoftwareP256KeyProvider {
    pub fn new(identity: SoftwareP256Identity) -> Self {
        Self { inner: identity, label: None }
    }

    pub fn with_label(identity: SoftwareP256Identity, label: impl Into<String>) -> Self {
        Self { inner: identity, label: Some(label.into()) }
    }

    pub fn identity(&self) -> &SoftwareP256Identity {
        &self.inner
    }
}

impl KeyProvider for SoftwareP256KeyProvider {
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::P256
    }

    fn public_key(&self) -> &[u8] {
        &self.inner.public_sec1
    }

    fn ecdh(&self, peer_pub: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if peer_pub.len() != P256_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: P256_PUBLIC_KEY_LEN,
                got: peer_pub.len(),
            });
        }
        let peer = P256PublicKey::from_sec1_bytes(peer_pub).map_err(|_| {
            CryptoError::InvalidKeyLength {
                expected: P256_PUBLIC_KEY_LEN,
                got: peer_pub.len(),
            }
        })?;
        let shared = p256_diffie_hellman(self.inner.secret.to_nonzero_scalar(), peer.as_affine());
        Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
    }

    fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
}

/// Recipient-side DEK unwrap for the `OSGT-HW-P256-v1` suite. Mirrors
/// [`unwrap_dek_with_provider`] but for P-256 envelopes.
pub fn unwrap_dek_with_provider_p256(
    wrapped: &WrappedDekP256,
    provider: &dyn KeyProvider,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if provider.algorithm() != KeyAlgorithm::P256 {
        return Err(CryptoError::InvalidKeyLength {
            expected: P256_PUBLIC_KEY_LEN,
            got: provider.public_key().len(),
        });
    }
    let shared = provider.ecdh(&wrapped.ephemeral_pub)?;

    let hk = Hkdf::<Sha256>::new(None, shared.as_ref());
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(b"oversight-hw-p256-v1-dek-wrap", kek.as_mut())
        .map_err(|_| CryptoError::Hkdf)?;

    let plaintext = aead_decrypt(
        kek.as_ref(),
        &wrapped.nonce,
        &wrapped.wrapped_dek,
        b"oversight-hw-p256-dek",
    )?;
    Ok(Zeroizing::new(plaintext))
}

// -------------------------- Signatures --------------------------

pub fn sign_message(msg: &[u8], ed25519_priv: &[u8]) -> Result<[u8; ED25519_SIG_LEN], CryptoError> {
    if ed25519_priv.len() != ED25519_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: ED25519_KEY_LEN,
            got: ed25519_priv.len(),
        });
    }
    let mut seed = [0u8; ED25519_KEY_LEN];
    seed.copy_from_slice(ed25519_priv);
    let signing = EdSigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(signing.sign(msg).to_bytes())
}

pub fn verify_message(msg: &[u8], sig: &[u8], ed25519_pub: &[u8]) -> bool {
    if sig.len() != ED25519_SIG_LEN || ed25519_pub.len() != ED25519_KEY_LEN {
        return false;
    }
    let mut pub_arr = [0u8; ED25519_KEY_LEN];
    pub_arr.copy_from_slice(ed25519_pub);
    let verifying = match EdVerifyingKey::from_bytes(&pub_arr) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut sig_arr = [0u8; ED25519_SIG_LEN];
    sig_arr.copy_from_slice(sig);
    let signature = EdSignature::from_bytes(&sig_arr);
    verifying.verify(msg, &signature).is_ok()
}

// -------------------------- Utility --------------------------

pub fn random_dek() -> Zeroizing<[u8; DEK_LEN]> {
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    OsRng.fill_bytes(dek.as_mut());
    dek
}

pub fn content_hash(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

// -------------------------- Tests --------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_round_trip() {
        let key = [42u8; XCHACHA_KEY_LEN];
        let (nonce, ct) = aead_encrypt(&key, b"hello world", b"aad-test").unwrap();
        let pt = aead_decrypt(&key, &nonce, &ct, b"aad-test").unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn aead_tamper_rejected() {
        let key = [42u8; XCHACHA_KEY_LEN];
        let (nonce, mut ct) = aead_encrypt(&key, b"hello world", b"").unwrap();
        ct[0] ^= 0x01;
        assert!(aead_decrypt(&key, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn aead_wrong_aad_rejected() {
        let key = [42u8; XCHACHA_KEY_LEN];
        let (nonce, ct) = aead_encrypt(&key, b"hello world", b"correct").unwrap();
        assert!(aead_decrypt(&key, &nonce, &ct, b"wrong").is_err());
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let alice = ClassicIdentity::generate();
        let dek = random_dek();
        let wrapped = wrap_dek_for_recipient(dek.as_ref(), &alice.x25519_pub).unwrap();
        let recovered = unwrap_dek(&wrapped, alice.x25519_priv.as_ref()).unwrap();
        assert_eq!(&recovered[..], dek.as_ref());
    }

    #[test]
    fn wrap_wrong_recipient_rejected() {
        let alice = ClassicIdentity::generate();
        let bob = ClassicIdentity::generate();
        let dek = random_dek();
        let wrapped = wrap_dek_for_recipient(dek.as_ref(), &alice.x25519_pub).unwrap();
        // Bob tries to unwrap -- AEAD tag check will fail
        assert!(unwrap_dek(&wrapped, bob.x25519_priv.as_ref()).is_err());
    }

    #[test]
    fn sign_verify_round_trip() {
        let id = ClassicIdentity::generate();
        let sig = sign_message(b"test message", id.ed25519_priv.as_ref()).unwrap();
        assert!(verify_message(b"test message", &sig, &id.ed25519_pub));
        assert!(!verify_message(b"tampered message", &sig, &id.ed25519_pub));
    }

    #[test]
    fn json_round_trip() {
        let alice = ClassicIdentity::generate();
        let dek = random_dek();
        let wrapped = wrap_dek_for_recipient(dek.as_ref(), &alice.x25519_pub).unwrap();
        let json = wrapped.to_json_hex();
        let parsed = WrappedDek::from_json_hex(&json).unwrap();
        assert_eq!(wrapped, parsed);
    }

    #[test]
    fn file_key_provider_advertises_x25519() {
        let id = ClassicIdentity::generate();
        let pub_copy = id.x25519_pub;
        let provider = FileKeyProvider::new(id);
        assert_eq!(provider.algorithm(), KeyAlgorithm::X25519);
        assert_eq!(provider.public_key(), &pub_copy);
        assert!(provider.label().is_none());
    }

    #[test]
    fn file_key_provider_label() {
        let id = ClassicIdentity::generate();
        let provider = FileKeyProvider::with_label(id, "tutorial@oversightprotocol.dev");
        assert_eq!(provider.label(), Some("tutorial@oversightprotocol.dev"));
    }

    #[test]
    fn file_key_provider_ecdh_matches_raw() {
        // The provider's ECDH must produce the same shared secret as a direct
        // x25519_dalek call against the same key material. Otherwise
        // unwrap_dek_with_provider would diverge from unwrap_dek.
        let alice = ClassicIdentity::generate();
        let bob = ClassicIdentity::generate();
        let alice_pub_copy = alice.x25519_pub;
        let mut bob_priv_copy = [0u8; X25519_KEY_LEN];
        bob_priv_copy.copy_from_slice(bob.x25519_priv.as_ref());
        let provider = FileKeyProvider::new(bob);

        let via_provider = provider.ecdh(&alice_pub_copy).unwrap();

        // Raw x25519_dalek for comparison.
        let bob_sk = X25519StaticSecret::from(bob_priv_copy);
        let raw = bob_sk.diffie_hellman(&X25519PublicKey::from(alice_pub_copy)).to_bytes();

        assert_eq!(via_provider.as_slice(), &raw[..]);
    }

    #[test]
    fn file_key_provider_rejects_wrong_peer_length() {
        let provider = FileKeyProvider::new(ClassicIdentity::generate());
        let err = provider.ecdh(&[0u8; 31]).unwrap_err();
        match err {
            CryptoError::InvalidKeyLength { expected, got } => {
                assert_eq!(expected, X25519_KEY_LEN);
                assert_eq!(got, 31);
            }
            other => panic!("expected InvalidKeyLength, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_dek_with_provider_matches_unwrap_dek() {
        // The provider path must be byte-identical to the legacy path so we
        // can migrate call sites incrementally without behavior drift.
        let alice = ClassicIdentity::generate();
        let mut alice_priv_copy = [0u8; X25519_KEY_LEN];
        alice_priv_copy.copy_from_slice(alice.x25519_priv.as_ref());
        let alice_pub_copy = alice.x25519_pub;
        let provider = FileKeyProvider::new(alice);

        let dek = random_dek();
        let wrapped = wrap_dek_for_recipient(dek.as_ref(), &alice_pub_copy).unwrap();

        let via_legacy = unwrap_dek(&wrapped, &alice_priv_copy).unwrap();
        let via_provider = unwrap_dek_with_provider(&wrapped, &provider).unwrap();

        assert_eq!(&via_legacy[..], dek.as_ref());
        assert_eq!(&via_provider[..], dek.as_ref());
        assert_eq!(&via_legacy[..], &via_provider[..]);
    }

    #[test]
    fn unwrap_dek_with_provider_wrong_recipient_rejected() {
        let alice = ClassicIdentity::generate();
        let bob = ClassicIdentity::generate();
        let alice_pub_copy = alice.x25519_pub;
        let provider_bob = FileKeyProvider::new(bob);

        let dek = random_dek();
        let wrapped = wrap_dek_for_recipient(dek.as_ref(), &alice_pub_copy).unwrap();

        // Bob's provider should fail to recover the DEK.
        let res = unwrap_dek_with_provider(&wrapped, &provider_bob);
        assert!(res.is_err(), "Bob's provider must not unwrap a DEK addressed to Alice");
    }

    // ------- P-256 (OSGT-HW-P256-v1) ----------------------------------------

    #[test]
    fn p256_identity_public_key_starts_with_sec1_uncompressed_tag() {
        // SEC1 uncompressed encoding always starts with 0x04.
        let id = SoftwareP256Identity::generate();
        assert_eq!(id.public_key_sec1()[0], 0x04);
        assert_eq!(id.public_key_sec1().len(), P256_PUBLIC_KEY_LEN);
    }

    #[test]
    fn p256_provider_advertises_p256() {
        let id = SoftwareP256Identity::generate();
        let pub_copy = *id.public_key_sec1();
        let provider = SoftwareP256KeyProvider::new(id);
        assert_eq!(provider.algorithm(), KeyAlgorithm::P256);
        assert_eq!(provider.public_key(), &pub_copy[..]);
    }

    #[test]
    fn p256_wrap_unwrap_round_trip() {
        let alice = SoftwareP256Identity::generate();
        let alice_pub = *alice.public_key_sec1();
        let provider = SoftwareP256KeyProvider::new(alice);

        let dek = random_dek();
        let wrapped = wrap_dek_for_recipient_p256(dek.as_ref(), &alice_pub).unwrap();
        let recovered = unwrap_dek_with_provider_p256(&wrapped, &provider).unwrap();
        assert_eq!(&recovered[..], dek.as_ref());
    }

    #[test]
    fn p256_wrong_recipient_rejected() {
        let alice = SoftwareP256Identity::generate();
        let alice_pub = *alice.public_key_sec1();
        let bob = SoftwareP256Identity::generate();
        let provider_bob = SoftwareP256KeyProvider::new(bob);

        let dek = random_dek();
        let wrapped = wrap_dek_for_recipient_p256(dek.as_ref(), &alice_pub).unwrap();

        let res = unwrap_dek_with_provider_p256(&wrapped, &provider_bob);
        assert!(res.is_err(), "Bob's P-256 provider must not unwrap a DEK addressed to Alice");
    }

    #[test]
    fn p256_unwrap_rejects_x25519_provider() {
        // Cross-suite mismatch: an X25519 file provider must not be accepted
        // for a P-256 envelope (silently producing garbage would be worse
        // than refusing).
        let alice_p256 = SoftwareP256Identity::generate();
        let alice_pub = *alice_p256.public_key_sec1();
        let dek = random_dek();
        let wrapped = wrap_dek_for_recipient_p256(dek.as_ref(), &alice_pub).unwrap();

        let bob_x25519 = FileKeyProvider::new(ClassicIdentity::generate());
        let res = unwrap_dek_with_provider_p256(&wrapped, &bob_x25519);
        assert!(res.is_err(), "X25519 provider must not be accepted for a P-256 envelope");
    }

    #[test]
    fn p256_unwrap_rejects_wrong_ephemeral_length() {
        let id = SoftwareP256Identity::generate();
        let provider = SoftwareP256KeyProvider::new(id);
        let err = provider.ecdh(&[0u8; 32]).unwrap_err();
        match err {
            CryptoError::InvalidKeyLength { expected, got } => {
                assert_eq!(expected, P256_PUBLIC_KEY_LEN);
                assert_eq!(got, 32);
            }
            other => panic!("expected InvalidKeyLength, got {other:?}"),
        }
    }

    #[test]
    fn p256_wrapped_dek_json_round_trip() {
        let alice = SoftwareP256Identity::generate();
        let alice_pub = *alice.public_key_sec1();
        let dek = random_dek();
        let wrapped = wrap_dek_for_recipient_p256(dek.as_ref(), &alice_pub).unwrap();
        let json = wrapped.to_json_hex();
        // Suite is recorded explicitly so a polymorphic envelope reader can
        // dispatch without inspecting the ephemeral key length.
        assert_eq!(json["suite"].as_str(), Some(SUITE_HW_P256_V1));
        let parsed = WrappedDekP256::from_json_hex(&json).unwrap();
        assert_eq!(wrapped, parsed);
    }

    #[test]
    fn p256_unwrap_x25519_provider_classic_envelope_still_works() {
        // Sanity: adding the P-256 suite must not regress the classic path.
        let alice = ClassicIdentity::generate();
        let alice_pub = alice.x25519_pub;
        let provider = FileKeyProvider::new(alice);
        let dek = random_dek();
        let wrapped = wrap_dek_for_recipient(dek.as_ref(), &alice_pub).unwrap();
        let recovered = unwrap_dek_with_provider(&wrapped, &provider).unwrap();
        assert_eq!(&recovered[..], dek.as_ref());
    }
}
