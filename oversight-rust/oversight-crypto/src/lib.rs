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
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

pub const XCHACHA_KEY_LEN: usize = 32;
pub const XCHACHA_NONCE_LEN: usize = 24;
pub const X25519_KEY_LEN: usize = 32;
pub const ED25519_KEY_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const DEK_LEN: usize = 32;

pub const SUITE_CLASSIC_V1: &str = "OSGT-CLASSIC-v1";
pub const SUITE_HYBRID_V1: &str = "OSGT-HYBRID-v1";

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
}
