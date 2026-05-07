# Outlook add-in design

## Scope

The Outlook add-in is a thin wrapper around the same parse / verify / decrypt
pipeline that runs in the public browser inspector. It does not introduce a
second crypto stack, a second container parser, or a second canonicalization.
Where the inspector handles a `.sealed` file dropped onto a web page, the
add-in handles a `.sealed` attachment on an open Outlook message.

The MVP is read-only: a recipient who receives a sealed attachment by email
can verify the issuer signature, read the manifest, and (optionally) decrypt
the payload using their identity, all inside the Outlook task pane. Sealing
new files from inside Outlook is a follow-up milestone, gated on a separate
identity-key flow.

## Architecture

```
Outlook task pane (HTML/JS)
        |
        +-- Office.js: get current message, enumerate attachments,
        |              fetch the .sealed attachment as base64.
        |
        +-- import { parseSealed, verifyManifestSignature, decryptSealed }
        |     from '/viewer/viewer.js'
        +-- import { xchacha20poly1305 } from '/viewer/vendor/...'
        +-- import { ml_kem768 }         from '/viewer/vendor/...'
        |
        +-- Render the same kind of summary the inspector shows:
              suite, signature status, recipient id, content hash,
              decrypt panel for both classic and hybrid suites.
```

The task pane is a static HTML page hosted under the same origin as the
public inspector, so the imports above are relative-path imports against the
already-vendored modules. Nothing is duplicated.

## Manifest

`integrations/outlook/manifest.xml` is an Office add-in 1.1 manifest of type
`MailApp`. It declares:

- `Hosts`: `Mailbox`
- `Requirements`: `Mailbox >= 1.5` (modern enough for `getAttachmentContentAsync`)
- `Permissions`: `ReadItem`
- A read-mode form with `SourceLocation` pointing to the hosted task pane
  URL, currently `https://oversightprotocol.dev/integrations/outlook/taskpane.html`
- A `Rule` that activates the add-in on items that have any attachment

The `<Id>` GUID is `ee9beb3a-64a6-4656-b3f9-a8d0ad8c409c`. This is the
stable identity of the add-in across versions; do not change it without
also coordinating an AppSource update if the add-in ever ships there.

## Hosting

The task pane HTML, JS, and the existing viewer modules all live on
`gh-pages`, served at `oversightprotocol.dev`. The path layout is:

- `oversightprotocol.dev/integrations/outlook/taskpane.html`
- `oversightprotocol.dev/integrations/outlook/taskpane.js`
- `oversightprotocol.dev/viewer/viewer.js` (already deployed)
- `oversightprotocol.dev/viewer/vendor/...` (already deployed)

Same-origin imports keep the security model simple: the task pane is treated
as one site by the browser, and Office's add-in sandbox enforces the rest.

## Distribution

For a pilot the manifest is sideloaded:

- **Outlook on the web**: `Get Add-ins > My add-ins > Add a custom add-in
  from URL/file`, point at the hosted manifest.
- **Outlook desktop**: same dialog from the ribbon.
- **Tenant-wide**: an admin uploads the manifest in the Microsoft 365 admin
  centre and assigns it to a user group.

AppSource publication is out of scope for the MVP. It requires a Partner
Center account, validation submission, and review, none of which is on the
critical path for the first regulated-industry deployment.

## Identity model

The recipient pastes or uploads their `identity.json` into the task pane,
exactly the same shape the public inspector accepts. Hybrid identities
include `mlkem_priv` and `mlkem_pub` alongside `x25519_priv` and
`x25519_pub`. The identity stays in task-pane memory only; nothing is
persisted to Outlook storage and nothing is sent to a server.

This is deliberately the same UX as the public inspector. Recipients who
have already used the inspector will recognize the flow.

## What is intentionally not in the MVP

- **Sealing from Outlook**: requires an issuer key on the user's machine
  and a separate key-management story. Treat as v2.
- **Auto-attribution on leak**: the attribute pipeline runs server-side
  against the registry; not appropriate for an end-user task pane.
- **Compose-mode rules**: would let the add-in inject metadata into
  outgoing mail. Out of scope until a customer asks.
- **Persistent identity storage**: until a hardware-key path is wired up
  (see `docs/HARDWARE_KEYS.md`), persisting private keys in Office storage
  is a regression versus the inspector's "memory only" guarantee.

## Security caveats

The add-in inherits the inspector's caveats. In particular:

- The browser's WebCrypto + the vendored noble libraries are the only
  crypto. Office.js is not used for any cryptographic operation.
- The add-in trusts the page's same-origin scripts. Anyone who can ship
  a malicious update to the task pane HTML/JS can subvert decryption.
  The mitigation is the same as for the public inspector: vendor pinning
  with SHA-256 fingerprints in `viewer/vendor/README.md`.
- Outlook's message body and attachment metadata pass through Microsoft's
  servers as a normal part of email transport. The sealed bundle is
  end-to-end encrypted to the recipient's keys, but envelope metadata
  (sender, subject line, attachment filenames) is visible to the email
  provider as for any other message.
