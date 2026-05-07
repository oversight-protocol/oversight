# Oversight Inspector for Outlook

Read-mode Outlook task pane that verifies and decrypts `.sealed` attachments
using the same parse/verify/decrypt pipeline as the public web inspector at
<https://oversightprotocol.dev/viewer/>. No second crypto stack, no second
container parser, no telemetry.

Status: **scaffold**. The manifest, task pane HTML, and JS are wired up but
nothing has been load-tested inside an Outlook tenant yet. The architecture
decisions are recorded in [`docs/OUTLOOK.md`](../../docs/OUTLOOK.md).

## Files

| File | Purpose |
|---|---|
| `manifest.xml` | Office add-in 1.1 manifest, `MailApp` type, read-mode task pane |
| `taskpane.html` | UI shell: status badge, attachment picker, manifest summary, decrypt panel |
| `taskpane.js` | Office.js + viewer-module integration; reuses `parseSealed`, `verifyManifestSignature`, `decryptSealed` |
| `assets/` | Icons referenced by `manifest.xml` (64 px, 128 px). Placeholders pending design. |

## Hosting

The task pane and its imports must be served over HTTPS from the URL declared
in `manifest.xml` (`SourceLocation`). Production target is
`https://oversightprotocol.dev/integrations/outlook/`, which lives under
`gh-pages` next to `viewer/`.

To deploy: copy this directory's contents into `P:\Oversight\site\integrations\outlook\`
and push `gh-pages` (the standard site deploy step). Same-origin imports of
`/viewer/viewer.js` and the vendored noble bundles work automatically once
both paths are on the same host.

## Sideload (developer)

1. Build a local manifest with `SourceLocation` pointing at your dev URL
   (e.g., `https://localhost:3000/integrations/outlook/taskpane.html` if you
   are serving locally). Outlook requires HTTPS even for localhost; use
   `office-addin-dev-certs` or your own self-signed pair.
2. **Outlook on the web**: open any message > the More (`...`) menu >
   `Get Add-ins` > `My add-ins` > `Add a custom add-in` > `Add from file...`
   and pick your local `manifest.xml`.
3. **Outlook desktop**: Home tab > `Get Add-ins` > same path.
4. Open a message that has a `.sealed` or `.oversight` attachment. The task
   pane will offer to load and verify it.

## Tenant install

For a pilot deployment a Microsoft 365 admin uploads `manifest.xml` in the
admin centre under `Integrated apps > Upload custom apps > Office Add-in >
Provide link to the manifest file` (or by uploading the XML directly). The
admin assigns the add-in to a user group and Outlook surfaces it on the
ribbon for those users.

## Permissions

`ReadItem` is the only requested scope. The add-in does not modify the
message, send anything from the user's mailbox, or access any folders other
than the open message. Decryption keys come from the user's pasted
`identity.json` and stay in task-pane memory for the lifetime of that
message view.

## What's missing for a real pilot

- [ ] Icons in `assets/` (64 px and 128 px PNG, transparent background).
- [ ] A short demo video or screenshots for the AppSource listing once we
      decide AppSource is in scope.
- [ ] End-to-end test inside an Outlook dev tenant against a hybrid `.sealed`
      attachment.
- [ ] Decision: do we accept the `.oversight` extension Codex is shipping on
      the mobile side as a synonym for `.sealed`? The activation rule already
      covers any attachment, so this only affects the task pane's filename
      filter.
- [ ] Localization beyond `en-US` once a customer asks.

Sealing-from-Outlook (compose mode) is intentionally out of scope for v1; see
`docs/OUTLOOK.md` for the rationale.
