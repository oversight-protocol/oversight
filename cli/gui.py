"""Small Tkinter GUI for non-technical Oversight users."""

from __future__ import annotations

import json
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os

from oversight_core import (
    ClassicIdentity,
    Manifest,
    Recipient,
    WatermarkRef,
    beacon,
    content_hash,
    l3_policy,
    open_sealed,
    seal,
    watermark,
)
from oversight_core.fingerprint import ContentFingerprint


class OversightGui(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Oversight Protocol")
        self.geometry("760x540")
        self._build()

    def _build(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12, pady=12)
        self._build_keygen(notebook)
        self._build_seal(notebook)
        self._build_open(notebook)

    def _row(self, parent, label: str, row: int, browse: bool = False):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        var = tk.StringVar()
        ent = ttk.Entry(parent, textvariable=var, width=72)
        ent.grid(row=row, column=1, sticky="ew", pady=4)
        if browse:
            ttk.Button(parent, text="Browse", command=lambda: self._browse(var)).grid(row=row, column=2, padx=4)
        parent.columnconfigure(1, weight=1)
        return var

    def _browse(self, var: tk.StringVar, save: bool = False) -> None:
        path = filedialog.asksaveasfilename() if save else filedialog.askopenfilename()
        if path:
            var.set(path)

    def _build_keygen(self, notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Generate Keys")
        identity_id = self._row(frame, "Identity name", 0)
        identity_id.set("alice")
        out = self._row(frame, "Private key output", 1)
        ttk.Button(frame, text="Choose Output", command=lambda: self._browse(out, save=True)).grid(row=1, column=2, padx=4)
        ttk.Button(frame, text="Generate Keypair", command=lambda: self._keygen(identity_id.get(), out.get())).grid(row=2, column=1, sticky="e", pady=12)

    def _build_seal(self, notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Seal File")
        self.seal_input = self._row(frame, "Input file", 0, True)
        self.seal_issuer = self._row(frame, "Issuer private key", 1, True)
        self.seal_recipient = self._row(frame, "Recipient public key", 2, True)
        self.seal_out = self._row(frame, "Sealed output", 3)
        ttk.Button(frame, text="Choose Output", command=lambda: self._browse(self.seal_out, save=True)).grid(row=3, column=2, padx=4)
        self.registry_url = self._row(frame, "Registry URL", 4)
        self.registry_url.set("https://registry.oversightprotocol.dev")
        self.content_type = self._row(frame, "Content type", 5)
        self.content_type.set("text/plain")
        self.l3_mode = tk.StringVar(value="auto")
        ttk.Label(frame, text="L3 mode").grid(row=6, column=0, sticky="w", pady=4)
        ttk.Combobox(frame, textvariable=self.l3_mode, values=["auto", "off", "boilerplate", "full"], state="readonly").grid(row=6, column=1, sticky="w")
        self.watermark_enabled = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Embed L1/L2 watermarks", variable=self.watermark_enabled).grid(row=7, column=1, sticky="w")
        ttk.Button(frame, text="Seal", command=self._seal_file).grid(row=8, column=1, sticky="e", pady=12)

    def _build_open(self, notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Open File")
        self.open_input = self._row(frame, "Sealed file", 0, True)
        self.open_identity = self._row(frame, "Recipient private key", 1, True)
        self.open_out = self._row(frame, "Plaintext output", 2)
        ttk.Button(frame, text="Choose Output", command=lambda: self._browse(self.open_out, save=True)).grid(row=2, column=2, padx=4)
        ttk.Button(frame, text="Open", command=self._open_file).grid(row=3, column=1, sticky="e", pady=12)

    def _keygen(self, identity_id: str, out_path: str) -> None:
        try:
            ident = ClassicIdentity.generate()
            out = {
                "id": identity_id or "identity",
                "x25519_priv": ident.x25519_priv.hex(),
                "x25519_pub": ident.x25519_pub.hex(),
                "ed25519_priv": ident.ed25519_priv.hex(),
                "ed25519_pub": ident.ed25519_pub.hex(),
            }
            path = Path(out_path)
            _write_private_json(path, out)
            path.with_suffix(".pub.json").write_text(json.dumps({
                "id": out["id"],
                "x25519_pub": out["x25519_pub"],
                "ed25519_pub": out["ed25519_pub"],
            }, indent=2))
            messagebox.showinfo("Oversight", "Keypair generated.")
        except Exception as exc:
            messagebox.showerror("Oversight", str(exc))

    def _seal_file(self) -> None:
        try:
            input_path = Path(self.seal_input.get())
            plaintext = input_path.read_bytes()
            canonical_plaintext = plaintext
            issuer = json.loads(Path(self.seal_issuer.get()).read_text())
            rec_pub = json.loads(Path(self.seal_recipient.get()).read_text())
            watermarks: list[WatermarkRef] = []
            decision = None

            if self.watermark_enabled.get():
                text = plaintext.decode("utf-8")
                mark_id = watermark.new_mark_id()
                decision = l3_policy.decide_l3(
                    filename=str(input_path),
                    content_type=self.content_type.get(),
                    text=text,
                    requested_mode=self.l3_mode.get(),
                )
                if decision.enabled:
                    if not messagebox.askyesno(
                        "L3 disclosure",
                        "L3 semantic watermarking changes visible prose. Continue?",
                    ):
                        return
                    text = l3_policy.apply_l3_safe(text, mark_id, mode=decision.mode)
                    watermarks.append(WatermarkRef(f"L3_semantic_{decision.mode}", mark_id.hex()))
                text = watermark.embed_ws(text, mark_id)
                text = watermark.embed_zw(text, mark_id)
                plaintext = text.encode("utf-8")
                watermarks.extend([
                    WatermarkRef("L1_zero_width", mark_id.hex()),
                    WatermarkRef("L2_whitespace", mark_id.hex()),
                ])

            recipient = Recipient(rec_pub["id"], rec_pub["x25519_pub"], rec_pub.get("ed25519_pub"))
            manifest = Manifest.new(
                input_path.name,
                content_hash(plaintext),
                len(plaintext),
                issuer.get("id", "issuer"),
                issuer["ed25519_pub"],
                recipient,
                self.registry_url.get(),
                self.content_type.get(),
            )
            manifest.canonical_content_hash = content_hash(canonical_plaintext)
            manifest.watermarks = watermarks
            manifest.l3_policy = decision.to_dict() if decision else {}
            manifest.beacons = [
                b.to_dict() for b in beacon.gen_beacons("oversightprotocol.dev", "pending", rec_pub["id"])
            ]
            out_path = Path(self.seal_out.get() or f"{input_path}.sealed")
            blob = seal(plaintext, manifest, bytes.fromhex(issuer["ed25519_priv"]), bytes.fromhex(rec_pub["x25519_pub"]))
            out_path.write_bytes(blob)
            if watermarks:
                fp = ContentFingerprint.from_text(plaintext.decode("utf-8", errors="replace"))
                out_path.with_suffix(".fingerprint.json").write_text(json.dumps({
                    "file_id": manifest.file_id,
                    "recipient_id": rec_pub["id"],
                    "canonical_content_hash": manifest.canonical_content_hash,
                    "l3_policy": manifest.l3_policy,
                    "fingerprint": fp.to_dict(),
                }, indent=2))
            messagebox.showinfo("Oversight", f"Sealed file written.\nfile_id={manifest.file_id}")
        except Exception as exc:
            messagebox.showerror("Oversight", str(exc))

    def _open_file(self) -> None:
        try:
            ident = json.loads(Path(self.open_identity.get()).read_text())
            plaintext, _manifest = open_sealed(
                Path(self.open_input.get()).read_bytes(),
                bytes.fromhex(ident["x25519_priv"]),
            )
            Path(self.open_out.get()).write_bytes(plaintext)
            messagebox.showinfo("Oversight", "File opened.")
        except Exception as exc:
            messagebox.showerror("Oversight", str(exc))


def main() -> None:
    app = OversightGui()
    app.mainloop()


def _write_private_json(path: Path, data: dict) -> None:
    """Write private key material with restrictive permissions where supported."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2)
    if os.name == "posix":
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
    else:
        path.write_text(payload, encoding="utf-8")


if __name__ == "__main__":
    main()
