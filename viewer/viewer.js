// Oversight sealed-file inspector. Offline-capable verification of
// Ed25519 signatures on .sealed manifests, plus optional registry
// lookups for recipients who want provenance confirmation against a
// public registry. No credentials, no internal endpoints, no
// telemetry.

const MAGIC = new Uint8Array([0x4f, 0x53, 0x47, 0x54, 0x01, 0x00]); // "OSGT\x01\x00"
const SUITE_NAMES = { 1: 'OSGT-CLASSIC-v1', 2: 'OSGT-HYBRID-v1' };

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

export async function decryptSealed(parsed, identity, xchachaAead) {
  if (parsed.suiteId !== 1) {
    throw new Error(
      'in-browser decrypt currently supports the classic suite only '
      + `(got suite_id=${parsed.suiteId}, ${parsed.suiteName}). `
      + 'Hybrid (post-quantum) decrypt is on the roadmap.'
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
