// Oversight Inspector for Outlook — task pane logic.
//
// Reuses the public viewer's parse/verify/decrypt pipeline so there is no
// second crypto path. Office.js is used only for attachment access; all
// cryptography happens against the vendored noble libraries the public
// inspector already ships.
//
// Architecture decision: see ../../docs/OUTLOOK.md.

import { parseSealed, verifyManifestSignature, decryptSealed } from 'https://oversightprotocol.dev/viewer/viewer.js';
import { xchacha20poly1305 } from 'https://oversightprotocol.dev/viewer/vendor/noble-ciphers-chacha-1.3.0.js';
import { ml_kem768 }         from 'https://oversightprotocol.dev/viewer/vendor/noble-post-quantum-ml-kem-0.6.1.js';

const SEAL_EXTS = ['.sealed', '.oversight'];

let parsed = null;
let plaintext = null;

function setStatus(text, kind) {
  const el = document.getElementById('status');
  el.textContent = text;
  el.className = 'badge ' + (kind || 'wait');
}

function setError(msg) {
  const el = document.getElementById('error');
  if (msg) {
    el.textContent = msg;
    el.style.display = 'block';
  } else {
    el.style.display = 'none';
  }
}

function show(id, on) {
  document.getElementById(id).style.display = on ? '' : 'none';
}

function isSealedName(name) {
  const n = (name || '').toLowerCase();
  return SEAL_EXTS.some(ext => n.endsWith(ext));
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function populateAttachmentSelect(attachments) {
  const sel = document.getElementById('attachment-select');
  sel.innerHTML = '';
  for (const att of attachments) {
    const opt = document.createElement('option');
    opt.value = att.id;
    opt.textContent = `${att.name} (${att.size} bytes)`;
    opt.dataset.name = att.name;
    sel.appendChild(opt);
  }
}

function renderManifest(manifest, sigOk) {
  const kv = document.getElementById('manifest-kv');
  kv.innerHTML = '';
  const rows = [
    ['suite', manifest.suite || ''],
    ['issuer_id', manifest.issuer_id || ''],
    ['recipient', (manifest.recipient && manifest.recipient.id) || ''],
    ['content_type', manifest.content_type || ''],
    ['content_hash', manifest.content_hash || ''],
    ['signature', sigOk ? 'verified' : 'INVALID'],
  ];
  for (const [k, v] of rows) {
    const ks = document.createElement('span'); ks.textContent = k;
    const vs = document.createElement('span');
    const code = document.createElement('code'); code.textContent = v;
    vs.appendChild(code);
    kv.appendChild(ks); kv.appendChild(vs);
  }
}

Office.onReady(info => {
  if (info.host !== Office.HostType.Outlook) {
    setStatus('not running in Outlook', 'bad');
    setError('This task pane only runs inside Outlook.');
    return;
  }
  refreshFromCurrentItem();

  // Re-run when the user opens a different message in the same task pane session.
  if (Office.context.mailbox && Office.context.mailbox.addHandlerAsync) {
    try {
      Office.context.mailbox.addHandlerAsync(
        Office.EventType.ItemChanged,
        refreshFromCurrentItem,
      );
    } catch (_) {
      // Older clients don't expose ItemChanged; the task pane will simply
      // need to be reopened on the next message.
    }
  }
});

function refreshFromCurrentItem() {
  setError('');
  show('attachment-row', false);
  show('manifest-row', false);
  show('decrypt-row', false);
  show('plaintext-out', false);
  parsed = null;
  plaintext = null;

  const item = Office.context.mailbox && Office.context.mailbox.item;
  if (!item || !item.attachments) {
    setStatus('no message selected', 'wait');
    return;
  }
  const sealed = (item.attachments || []).filter(a => isSealedName(a.name));
  if (sealed.length === 0) {
    setStatus('no .sealed attachment on this message', 'wait');
    return;
  }
  setStatus(`${sealed.length} sealed attachment(s) found`, 'ok');
  populateAttachmentSelect(sealed);
  show('attachment-row', true);
}

document.getElementById('btn-load').addEventListener('click', () => {
  setError('');
  const sel = document.getElementById('attachment-select');
  const attId = sel.value;
  if (!attId) return;

  const item = Office.context.mailbox.item;
  item.getAttachmentContentAsync(attId, { asyncContext: null }, async (result) => {
    if (result.status !== Office.AsyncResultStatus.Succeeded) {
      setError('Outlook refused to provide the attachment: ' + (result.error && result.error.message));
      return;
    }
    const fmt = result.value && result.value.format;
    const data = result.value && result.value.content;
    if (fmt !== Office.MailboxEnums.AttachmentContentFormat.Base64 || !data) {
      setError('unexpected attachment format: ' + fmt);
      return;
    }
    let bytes;
    try {
      bytes = base64ToBytes(data);
    } catch (e) {
      setError('attachment was not valid base64: ' + e.message);
      return;
    }
    try {
      parsed = parseSealed(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
    } catch (e) {
      setError('not a valid Oversight sealed file: ' + e.message);
      return;
    }
    let sig;
    try {
      sig = await verifyManifestSignature(parsed.manifest);
    } catch (e) {
      setError('signature check failed to run: ' + e.message);
      return;
    }
    renderManifest(parsed.manifest, !!(sig && sig.ok));
    show('manifest-row', true);
    show('decrypt-row', true);
    setStatus(sig.ok ? `signature verified (${parsed.suiteName})` : 'SIGNATURE INVALID', sig.ok ? 'ok' : 'bad');
  });
});

document.getElementById('btn-decrypt').addEventListener('click', async () => {
  setError('');
  show('plaintext-out', false);
  if (!parsed) { setError('Load a sealed attachment first.'); return; }
  const raw = document.getElementById('identity-text').value.trim();
  if (!raw) { setError('Paste your identity JSON.'); return; }
  let identity;
  try { identity = JSON.parse(raw); }
  catch (e) { setError('identity JSON could not be parsed: ' + e.message); return; }

  try {
    plaintext = await decryptSealed(parsed, identity, xchacha20poly1305, ml_kem768);
  } catch (e) {
    setError('decrypt failed: ' + e.message);
    return;
  }
  const text = new TextDecoder('utf-8', { fatal: false }).decode(plaintext);
  // Show first 1 KiB as a preview; the full plaintext is downloadable below.
  document.getElementById('plaintext-preview').textContent = text.slice(0, 1024) + (text.length > 1024 ? '\n...' : '');
  show('plaintext-out', true);
});

document.getElementById('btn-download').addEventListener('click', () => {
  if (!plaintext) return;
  const blob = new Blob([plaintext], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const name = (parsed && parsed.manifest && parsed.manifest.filename) || 'plaintext.bin';
  a.download = name.replace(/\.sealed$|\.oversight$/i, '') || 'plaintext.bin';
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
});
