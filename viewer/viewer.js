// Oversight sealed-file inspector. Offline-capable verification of
// Ed25519 signatures on .sealed manifests, plus optional registry
// lookups for recipients who want provenance confirmation against a
// public registry. No credentials, no internal endpoints, no
// telemetry.

const MAGIC = new Uint8Array([0x4f, 0x53, 0x47, 0x54, 0x01, 0x00]); // "OSGT\x01\x00"
const SUITE_NAMES = { 1: 'OSGT-CLASSIC-v1', 2: 'OSGT-HYBRID-v1', 3: 'OSGT-HW-P256-v1' };

// ---- container parsing -----------------------------------------------------

export function parseSealed(buffer) {
  const bytes = new Uint8Array(buffer);
  let off = 0;

  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[off + i] !== MAGIC[i]) {
      throw new Error('not an Oversight .sealed file (wrong magic bytes)');
    }
  }
  off += MAGIC.length;

  const formatVersion = bytes[off++];
  const suiteId = bytes[off++];
  if (formatVersion !== 1) {
    throw new Error(`unsupported format_version ${formatVersion}`);
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const manifestLen = view.getUint32(off, false); off += 4;
  if (manifestLen > 4 * 1024 * 1024) {
    throw new Error(`manifest too large (${manifestLen} bytes)`);
  }
  const manifestBytes = bytes.slice(off, off + manifestLen);
  off += manifestLen;

  const wrappedLen = view.getUint32(off, false); off += 4;
  if (wrappedLen > 1 * 1024 * 1024) {
    throw new Error(`wrapped_dek too large (${wrappedLen} bytes)`);
  }
  const wrappedDekBytes = bytes.slice(off, off + wrappedLen);
  off += wrappedLen;

  const aeadNonce = bytes.slice(off, off + 24);
  off += 24;

  const ciphertextLen = view.getUint32(off, false); off += 4;
  const ciphertextHead = bytes.slice(off, Math.min(off + 32, bytes.length));
  const ciphertextFull = bytes.slice(off, off + ciphertextLen);

  const manifestJsonText = new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes);
  const manifest = JSON.parse(manifestJsonText);

  let wrappedDek = null;
  try {
    const wrappedText = new TextDecoder('utf-8', { fatal: true }).decode(wrappedDekBytes);
    wrappedDek = JSON.parse(wrappedText);
  } catch (_) {
    // wrapped_dek may be absent or malformed; manifest verification does not need it.
  }

  return {
    formatVersion,
    suiteId,
    suiteName: SUITE_NAMES[suiteId] || `unknown(${suiteId})`,
    manifest,
    manifestBytes,
    wrappedDek,
    aeadNonce,
    ciphertextLen,
    ciphertextHead,
    _ciphertextFull: ciphertextFull,
    totalSize: bytes.length,
  };
}

// ---- canonical JSON (must match Python json.dumps sort_keys + compact + ensure_ascii) ----

function stripNone(obj) {
  if (obj === null || obj === undefined) return undefined;
  if (Array.isArray(obj)) {
    const out = [];
    for (const v of obj) {
      const s = stripNone(v);
      if (s !== undefined) out.push(s);
    }
    return out;
  }
  if (typeof obj === 'object') {
    const out = {};
    for (const k of Object.keys(obj)) {
      const s = stripNone(obj[k]);
      if (s !== undefined) out[k] = s;
    }
    return out;
  }
  return obj;
}

function escapeUnicode(s) {
  // Take JSON.stringify output and upgrade to Python's ensure_ascii=True.
  // Any char with code unit >= 0x7F becomes \uXXXX (matches Python for BMP
  // and emits surrogate-pair halves outside BMP exactly as Python does).
  return JSON.stringify(s).replace(/[\u007F-\uFFFF]/g, (c) =>
    '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')
  );
}

function canonicalize(obj) {
  if (obj === null) return 'null';
  if (typeof obj === 'boolean') return obj ? 'true' : 'false';
  if (typeof obj === 'number') {
    if (!Number.isFinite(obj)) throw new Error('non-finite number cannot be canonicalized');
    return JSON.stringify(obj);
  }
  if (typeof obj === 'string') return escapeUnicode(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalize).join(',') + ']';
  }
  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    return '{' + keys.map((k) => escapeUnicode(k) + ':' + canonicalize(obj[k])).join(',') + '}';
  }
  throw new Error('unsupported value type: ' + typeof obj);
}

export function canonicalManifestBytes(manifest) {
  // Match Manifest.canonical_bytes: strip None, zero the two signature
  // fields, sort keys, compact separators, ensure_ascii, UTF-8.
  const stripped = stripNone(manifest);
  stripped.signature_ed25519 = '';
  stripped.signature_ml_dsa = '';
  const text = canonicalize(stripped);
  return new TextEncoder().encode(text);
}

// ---- Ed25519 verification (WebCrypto) --------------------------------------

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) {
    throw new Error('invalid hex string');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

export async function verifyManifestSignature(manifest) {
  if (!manifest.signature_ed25519 || !manifest.issuer_ed25519_pub) {
    return { ok: false, reason: 'missing signature_ed25519 or issuer_ed25519_pub' };
  }
  const canonical = canonicalManifestBytes(manifest);
  const sig = hexToBytes(manifest.signature_ed25519);
  const pub = hexToBytes(manifest.issuer_ed25519_pub);

  if (!globalThis.crypto || !globalThis.crypto.subtle || !globalThis.crypto.subtle.importKey) {
    return { ok: false, reason: 'WebCrypto is not available in this environment' };
  }

  let key;
  try {
    key = await crypto.subtle.importKey(
      'raw',
      pub,
      { name: 'Ed25519' },
      false,
      ['verify']
    );
  } catch (e) {
    return {
      ok: false,
      reason: 'browser does not support WebCrypto Ed25519 (try Safari 17+, Chrome 113+, Firefox 130+): ' + e.message,
      canonical,
    };
  }

  const ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, sig, canonical);
  return { ok, canonical };
}

// ---- SHA-256 helper for display --------------------------------------------

export async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---- Classic-suite decrypt -------------------------------------------------
// Matches oversight_core/crypto.py unwrap_dek + aead_decrypt.
//
//   X25519 ECDH(recipient_priv, wrapped.ephemeral_pub) -> shared secret
//   HKDF-SHA256(shared, salt=empty, info=b"oversight-v1-dek-wrap") -> KEK
//   XChaCha20-Poly1305 decrypt(KEK, nonce=wrapped.nonce, aad=b"oversight-dek") -> DEK
//   XChaCha20-Poly1305 decrypt(DEK, nonce=aead_nonce, aad=manifest.content_hash.ascii) -> plaintext
//
// WebCrypto handles X25519 + HKDF natively. The XChaCha20-Poly1305 primitive
// ships as a self-hosted vendored copy of @noble/ciphers (noble-ciphers-chacha)
// because WebCrypto does not implement that AEAD.

function base64urlFromBytes(bytes) {
  // Uint8Array -> unpadded base64url
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function webcryptoX25519Shared(privRaw, selfPubRaw, peerPubRaw) {
  // WebCrypto X25519 does not accept 'raw' format for private keys. Build a
  // JWK that carries both d (private scalar) and x (public) per RFC 8037.
  const privJwk = {
    kty: 'OKP',
    crv: 'X25519',
    d: base64urlFromBytes(privRaw),
    x: base64urlFromBytes(selfPubRaw),
    key_ops: ['deriveBits'],
    ext: false,
  };
  const pubJwk = {
    kty: 'OKP',
    crv: 'X25519',
    x: base64urlFromBytes(peerPubRaw),
    key_ops: [],
    ext: true,
  };
  const priv = await crypto.subtle.importKey('jwk', privJwk, { name: 'X25519' }, false, ['deriveBits']);
  const pub = await crypto.subtle.importKey('jwk', pubJwk, { name: 'X25519' }, true, []);
  const bits = await crypto.subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256);
  return new Uint8Array(bits);
}

async function hkdfSha256(ikm, info, length) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

export async function decryptSealed(parsed, identity, xchachaAead, mlKem768, p256) {
  if (parsed.suiteId === 2) {
    return decryptSealedHybrid(parsed, identity, xchachaAead, mlKem768);
  }
  if (parsed.suiteId === 3) {
    return decryptSealedHwP256(parsed, identity, xchachaAead, p256);
  }
  if (parsed.suiteId !== 1) {
    throw new Error(
      `unsupported suite_id ${parsed.suiteId} (${parsed.suiteName}); `
      + 'in-browser decrypt supports classic (1), hybrid (2), and hardware P-256 (3).'
    );
  }
  if (!parsed.wrappedDek || !parsed.wrappedDek.ephemeral_pub || !parsed.wrappedDek.nonce || !parsed.wrappedDek.wrapped_dek) {
    throw new Error('wrapped_dek is malformed; cannot decrypt');
  }
  if (!identity || typeof identity !== 'object') {
    throw new Error('identity must be an object with x25519_priv and x25519_pub hex fields');
  }
  if (!identity.x25519_priv || !identity.x25519_pub) {
    throw new Error('identity is missing x25519_priv or x25519_pub');
  }
  const privRaw = hexToBytes(identity.x25519_priv);
  const selfPubRaw = hexToBytes(identity.x25519_pub);
  if (privRaw.length !== 32 || selfPubRaw.length !== 32) {
    throw new Error('x25519 priv and pub must be 32 bytes each (64 hex chars)');
  }
  // Cross-check: the manifest's recipient.x25519_pub must match this identity.
  const recipPub = (parsed.manifest.recipient || {}).x25519_pub;
  if (recipPub && recipPub.toLowerCase() !== identity.x25519_pub.toLowerCase()) {
    throw new Error(
      'identity x25519_pub does not match manifest.recipient.x25519_pub; '
      + 'this sealed file was not addressed to the supplied identity.'
    );
  }

  const ephemeralPub = hexToBytes(parsed.wrappedDek.ephemeral_pub);
  const wrappedNonce = hexToBytes(parsed.wrappedDek.nonce);
  const wrappedDek = hexToBytes(parsed.wrappedDek.wrapped_dek);

  let shared;
  try {
    shared = await webcryptoX25519Shared(privRaw, selfPubRaw, ephemeralPub);
  } catch (e) {
    throw new Error(
      'X25519 key agreement failed. Browser may not support WebCrypto X25519: ' + e.message
    );
  }

  const kek = await hkdfSha256(shared, new TextEncoder().encode('oversight-v1-dek-wrap'), 32);

  // Unwrap the DEK. noble/ciphers xchacha20poly1305(key, nonce, aad) returns
  // an object whose decrypt(ciphertext) consumes the ciphertext-with-tag.
  const kekAead = xchachaAead(kek, wrappedNonce, new TextEncoder().encode('oversight-dek'));
  let dek;
  try {
    dek = kekAead.decrypt(wrappedDek);
  } catch (e) {
    throw new Error(
      'DEK unwrap failed. The X25519 private key does not match the recipient '
      + 'declared in the manifest.'
    );
  }

  // Decrypt the outer ciphertext with AAD = content_hash (ASCII hex string).
  const aeadNonce = parsed.aeadNonce;
  if (aeadNonce.length !== 24) {
    throw new Error(`aead_nonce must be 24 bytes, got ${aeadNonce.length}`);
  }
  const ctHead = parsed.ciphertextHead;
  if (!ctHead || parsed.ciphertextLen === 0) {
    throw new Error('sealed file has no ciphertext');
  }
  // We only stored the first 32 bytes in ciphertextHead. Re-parse the full
  // ciphertext from the original buffer using the already-computed offset.
  if (!parsed._ciphertextFull) {
    throw new Error(
      'internal: full ciphertext not retained. Re-parse with parseSealed before decrypting.'
    );
  }
  const ciphertext = parsed._ciphertextFull;
  const contentAad = new TextEncoder().encode(parsed.manifest.content_hash);
  const outerAead = xchachaAead(dek, aeadNonce, contentAad);
  let plaintext;
  try {
    plaintext = outerAead.decrypt(ciphertext);
  } catch (e) {
    throw new Error('ciphertext decrypt failed (tag mismatch). The manifest may have been tampered with.');
  }

  // Post-decrypt integrity check: SHA-256(plaintext) must match manifest.content_hash.
  const actual = await sha256Hex(plaintext);
  if (actual.toLowerCase() !== String(parsed.manifest.content_hash || '').toLowerCase()) {
    throw new Error(
      'plaintext hash does not match manifest.content_hash after decryption'
    );
  }

  return plaintext;
}

// ---- Hybrid-suite decrypt (post-quantum) -----------------------------------
// Matches oversight_core/crypto.py:hybrid_unwrap_dek + aead_decrypt.
//
//   ss_x  = X25519(recipient_priv, wrapped.x25519_ephemeral_pub)        (WebCrypto)
//   ss_pq = ML-KEM-768.decap(recipient_mlkem_priv, wrapped.mlkem_ct)    (vendored noble)
//   IKM   = ss_x || ss_pq || x25519_eph_pub || mlkem_ct                 (X-wing binding)
//   KEK   = HKDF-SHA256(IKM, info=b"oversight-hybrid-v1-dek-wrap", L=32)
//   DEK   = XChaCha20-Poly1305.decrypt(KEK, wrapped.nonce, wrapped_dek, aad=b"oversight-hybrid-dek")
//   plain = XChaCha20-Poly1305.decrypt(DEK, parsed.aead_nonce, ciphertext, aad=manifest.content_hash.ascii)
//
// An attacker must break BOTH X25519 AND ML-KEM-768 to recover the KEK.

export async function decryptSealedHybrid(parsed, identity, xchachaAead, mlKem768) {
  if (parsed.suiteId !== 2) {
    throw new Error(`decryptSealedHybrid called with non-hybrid suite_id=${parsed.suiteId}`);
  }
  if (!mlKem768 || typeof mlKem768.decapsulate !== 'function') {
    throw new Error(
      'hybrid decrypt requires ml_kem768 to be passed in. '
      + "Import { ml_kem768 } from './vendor/noble-post-quantum-ml-kem-0.6.1.js' "
      + 'and pass it as the 4th argument to decryptSealed.'
    );
  }
  const w = parsed.wrappedDek || {};
  for (const k of ['x25519_ephemeral_pub', 'mlkem_ciphertext', 'nonce', 'wrapped_dek']) {
    if (!w[k]) {
      throw new Error(`hybrid wrapped_dek envelope missing field: ${k}`);
    }
  }
  if (!identity || typeof identity !== 'object') {
    throw new Error('identity must be an object with x25519_priv, x25519_pub, mlkem_priv, mlkem_pub');
  }
  for (const k of ['x25519_priv', 'x25519_pub', 'mlkem_priv', 'mlkem_pub']) {
    if (!identity[k]) {
      throw new Error(`hybrid identity is missing required field: ${k}`);
    }
  }

  const x25519Priv = hexToBytes(identity.x25519_priv);
  const x25519SelfPub = hexToBytes(identity.x25519_pub);
  const mlkemPriv = hexToBytes(identity.mlkem_priv);
  const mlkemPub = hexToBytes(identity.mlkem_pub);

  if (x25519Priv.length !== 32 || x25519SelfPub.length !== 32) {
    throw new Error('x25519 priv and pub must be 32 bytes each (64 hex chars)');
  }
  // FIPS 203 ML-KEM-768: secret key 2400 bytes, public key 1184 bytes.
  if (mlkemPriv.length !== 2400) {
    throw new Error(`ML-KEM-768 priv must be 2400 bytes (4800 hex chars), got ${mlkemPriv.length}`);
  }
  if (mlkemPub.length !== 1184) {
    throw new Error(`ML-KEM-768 pub must be 1184 bytes (2368 hex chars), got ${mlkemPub.length}`);
  }

  // Cross-check that the identity matches the manifest's recipient.
  const recip = parsed.manifest.recipient || {};
  if (recip.x25519_pub && recip.x25519_pub.toLowerCase() !== identity.x25519_pub.toLowerCase()) {
    throw new Error(
      'identity x25519_pub does not match manifest.recipient.x25519_pub; '
      + 'this hybrid sealed file was not addressed to the supplied identity.'
    );
  }
  if (recip.mlkem_pub && recip.mlkem_pub.toLowerCase() !== identity.mlkem_pub.toLowerCase()) {
    throw new Error(
      'identity mlkem_pub does not match manifest.recipient.mlkem_pub; '
      + 'this hybrid sealed file was not addressed to the supplied identity.'
    );
  }

  const ephPub = hexToBytes(w.x25519_ephemeral_pub);
  const mlkemCt = hexToBytes(w.mlkem_ciphertext);
  const wrappedNonce = hexToBytes(w.nonce);
  const wrappedDek = hexToBytes(w.wrapped_dek);
  if (mlkemCt.length !== 1088) {
    throw new Error(`ML-KEM-768 ciphertext must be 1088 bytes, got ${mlkemCt.length}`);
  }

  let ssX;
  try {
    ssX = await webcryptoX25519Shared(x25519Priv, x25519SelfPub, ephPub);
  } catch (e) {
    throw new Error(
      'X25519 key agreement failed. Browser may not support WebCrypto X25519: ' + e.message
    );
  }

  let ssPq;
  try {
    ssPq = mlKem768.decapsulate(mlkemCt, mlkemPriv);
  } catch (e) {
    throw new Error('ML-KEM-768 decapsulation failed: ' + e.message);
  }
  if (!(ssPq instanceof Uint8Array) || ssPq.length !== 32) {
    throw new Error(`ML-KEM-768 shared secret must be 32 bytes, got ${ssPq && ssPq.length}`);
  }

  // X-wing-style binding: bind KEK to the full encapsulation, not just the secrets.
  const ikm = new Uint8Array(ssX.length + ssPq.length + ephPub.length + mlkemCt.length);
  let off = 0;
  ikm.set(ssX, off); off += ssX.length;
  ikm.set(ssPq, off); off += ssPq.length;
  ikm.set(ephPub, off); off += ephPub.length;
  ikm.set(mlkemCt, off);

  const kek = await hkdfSha256(ikm, new TextEncoder().encode('oversight-hybrid-v1-dek-wrap'), 32);

  const kekAead = xchachaAead(kek, wrappedNonce, new TextEncoder().encode('oversight-hybrid-dek'));
  let dek;
  try {
    dek = kekAead.decrypt(wrappedDek);
  } catch (e) {
    throw new Error(
      'Hybrid DEK unwrap failed. Either x25519_priv or mlkem_priv does not match the '
      + 'recipient declared in the manifest.'
    );
  }

  // Outer ciphertext: identical construction to classic.
  const aeadNonce = parsed.aeadNonce;
  if (aeadNonce.length !== 24) {
    throw new Error(`aead_nonce must be 24 bytes, got ${aeadNonce.length}`);
  }
  if (!parsed._ciphertextFull || parsed.ciphertextLen === 0) {
    throw new Error('sealed file has no ciphertext');
  }
  const contentAad = new TextEncoder().encode(parsed.manifest.content_hash);
  const outerAead = xchachaAead(dek, aeadNonce, contentAad);
  let plaintext;
  try {
    plaintext = outerAead.decrypt(parsed._ciphertextFull);
  } catch (e) {
    throw new Error('ciphertext decrypt failed (tag mismatch). The manifest may have been tampered with.');
  }

  const actual = await sha256Hex(plaintext);
  if (actual.toLowerCase() !== String(parsed.manifest.content_hash || '').toLowerCase()) {
    throw new Error('plaintext hash does not match manifest.content_hash after decryption');
  }

  return plaintext;
}

// ---- Hardware-backed P-256 decrypt (OSGT-HW-P256-v1) -----------------------
// Matches oversight_core/crypto.py:unwrap_dek_p256 and
// oversight-rust/oversight-crypto::unwrap_dek_with_provider_p256.
//
//   ss = ECDH(recipient_p256_priv, wrapped.ephemeral_pub)   (vendored noble/curves)
//   KEK = HKDF-SHA256(ss, info=b"oversight-hw-p256-v1-dek-wrap", L=32)
//   DEK = XChaCha20-Poly1305.decrypt(KEK, wrapped.nonce, wrapped_dek, aad=b"oversight-hw-p256-dek")
//
// `p256` is the noble/curves P-256 module. The recipient identity must include
// `p256_priv_scalar` (32-byte raw scalar, hex) and `p256_pub` (65-byte SEC1
// uncompressed, hex).

export async function decryptSealedHwP256(parsed, identity, xchachaAead, p256) {
  if (parsed.suiteId !== 3) {
    throw new Error(`decryptSealedHwP256 called with non-HW-P256 suite_id=${parsed.suiteId}`);
  }
  if (!p256 || typeof p256.getSharedSecret !== 'function') {
    throw new Error(
      'hardware P-256 decrypt requires the noble/curves p256 module. '
      + "Import { p256 } from './vendor/noble-curves-nist-2.2.0.js' "
      + 'and pass it as the 5th argument to decryptSealed.'
    );
  }
  const w = parsed.wrappedDek || {};
  for (const k of ['ephemeral_pub', 'nonce', 'wrapped_dek']) {
    if (!w[k]) {
      throw new Error(`HW-P256 wrapped_dek envelope missing field: ${k}`);
    }
  }
  if (!identity || typeof identity !== 'object') {
    throw new Error('identity must be an object with p256_priv_scalar and p256_pub');
  }
  if (!identity.p256_priv_scalar || !identity.p256_pub) {
    throw new Error('HW-P256 identity is missing p256_priv_scalar or p256_pub');
  }

  const privScalar = hexToBytes(identity.p256_priv_scalar);
  const selfPub = hexToBytes(identity.p256_pub);
  if (privScalar.length !== 32) {
    throw new Error(`p256 priv scalar must be 32 bytes (64 hex chars), got ${privScalar.length}`);
  }
  if (selfPub.length !== 65) {
    throw new Error(`p256 pub must be 65 bytes SEC1 uncompressed (130 hex chars), got ${selfPub.length}`);
  }

  // Cross-check the identity matches the manifest's recipient.
  const recip = parsed.manifest.recipient || {};
  if (recip.p256_pub && recip.p256_pub.toLowerCase() !== identity.p256_pub.toLowerCase()) {
    throw new Error(
      'identity p256_pub does not match manifest.recipient.p256_pub; '
      + 'this hardware sealed file was not addressed to the supplied identity.'
    );
  }

  const ephPub = hexToBytes(w.ephemeral_pub);
  if (ephPub.length !== 65) {
    throw new Error(`P-256 ephemeral_pub must be 65 bytes (SEC1 uncompressed), got ${ephPub.length}`);
  }
  const wrappedNonce = hexToBytes(w.nonce);
  const wrappedDek = hexToBytes(w.wrapped_dek);

  // ECDH. noble's getSharedSecret returns the full point; we want only the
  // X coordinate (32 bytes), which is the standard ECDH shared-secret value
  // matching what Python's cryptography.exchange(ec.ECDH(), peer) returns.
  let raw;
  try {
    raw = p256.getSharedSecret(privScalar, ephPub, false); // false = uncompressed (65 bytes)
  } catch (e) {
    throw new Error('P-256 ECDH failed: ' + e.message);
  }
  let sharedX;
  if (raw.length === 65) {
    sharedX = raw.subarray(1, 33);          // 0x04 || X || Y -> X
  } else if (raw.length === 33) {
    sharedX = raw.subarray(1);              // 0x02/0x03 || X -> X
  } else if (raw.length === 32) {
    sharedX = raw;                          // already X-only
  } else {
    throw new Error(`unexpected P-256 shared secret length: ${raw.length}`);
  }

  const kek = await hkdfSha256(sharedX, new TextEncoder().encode('oversight-hw-p256-v1-dek-wrap'), 32);

  const kekAead = xchachaAead(kek, wrappedNonce, new TextEncoder().encode('oversight-hw-p256-dek'));
  let dek;
  try {
    dek = kekAead.decrypt(wrappedDek);
  } catch (e) {
    throw new Error(
      'Hardware P-256 DEK unwrap failed. The supplied private scalar does not match '
      + 'the recipient declared in the manifest.'
    );
  }

  const aeadNonce = parsed.aeadNonce;
  if (aeadNonce.length !== 24) {
    throw new Error(`aead_nonce must be 24 bytes, got ${aeadNonce.length}`);
  }
  if (!parsed._ciphertextFull || parsed.ciphertextLen === 0) {
    throw new Error('sealed file has no ciphertext');
  }
  const contentAad = new TextEncoder().encode(parsed.manifest.content_hash);
  const outerAead = xchachaAead(dek, aeadNonce, contentAad);
  let plaintext;
  try {
    plaintext = outerAead.decrypt(parsed._ciphertextFull);
  } catch (e) {
    throw new Error('ciphertext decrypt failed (tag mismatch). The manifest may have been tampered with.');
  }

  const actual = await sha256Hex(plaintext);
  if (actual.toLowerCase() !== String(parsed.manifest.content_hash || '').toLowerCase()) {
    throw new Error('plaintext hash does not match manifest.content_hash after decryption');
  }

  return plaintext;
}
