// End-to-end test of viewer.js hybrid decrypt against the generated sample.
// Run with:
//   node tools/test_hybrid_decrypt_node.mjs --viewer-dir ../site/viewer
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

function argValue(name, fallback) {
  const idx = process.argv.indexOf(name);
  if (idx >= 0 && idx + 1 < process.argv.length) return process.argv[idx + 1];
  return fallback;
}

const viewerDir = resolve(argValue('--viewer-dir', process.env.OVERSIGHT_VIEWER_DIR || 'site/viewer'));
const sealedPath = resolve(argValue('--sealed', join(viewerDir, 'samples/tutorial-hybrid.sealed')));
const identityPath = resolve(argValue('--identity', join(viewerDir, 'samples/tutorial-hybrid-identity.json')));

const VIEWER = pathToFileURL(join(viewerDir, 'viewer.js')).href;
const NOBLE_CHACHA = pathToFileURL(join(viewerDir, 'vendor/noble-ciphers-chacha-1.3.0.js')).href;
const NOBLE_MLKEM = pathToFileURL(join(viewerDir, 'vendor/noble-post-quantum-ml-kem-0.6.1.js')).href;

const { parseSealed, verifyManifestSignature, decryptSealed } = await import(VIEWER);
const { xchacha20poly1305 } = await import(NOBLE_CHACHA);
const { ml_kem768 } = await import(NOBLE_MLKEM);

const sealedBuf = readFileSync(sealedPath);
const identity = JSON.parse(readFileSync(identityPath, 'utf8'));

const parsed = parseSealed(sealedBuf.buffer.slice(sealedBuf.byteOffset, sealedBuf.byteOffset + sealedBuf.byteLength));
console.log('parsed.suiteName        :', parsed.suiteName);
console.log('parsed.manifest.suite   :', parsed.manifest.suite);
console.log('parsed.content_hash     :', parsed.manifest.content_hash);
console.log('parsed.ciphertextLen    :', parsed.ciphertextLen);
console.log('parsed.wrappedDek keys  :', Object.keys(parsed.wrappedDek || {}).join(','));

const sigCheck = await verifyManifestSignature(parsed.manifest);
console.log('Ed25519 signature verify:', sigCheck.ok, sigCheck.reason || '');

const plaintext = await decryptSealed(parsed, identity, xchacha20poly1305, ml_kem768);
const text = new TextDecoder().decode(plaintext);
console.log('decrypted plaintext     :', JSON.stringify(text));

const expected = 'hello hybrid post-quantum oversight\n';
const pass = sigCheck.ok && text === expected;
console.log('TEST                    :', pass ? 'PASS' : 'FAIL');
process.exit(pass ? 0 : 1);
