"""Small Tkinter GUI for non-technical Oversight users."""

from __future__ import annotations

import json
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlparse

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
from oversight_core.safe_io import (
    atomic_write_bytes,
    atomic_write_private_json,
    atomic_write_text,
    is_private_key_file,
    is_windows_reserved_path,
    validate_output_path,
)


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
            identity_id = (identity_id or "identity").strip()
            if not identity_id:
                raise ValueError("Please enter an identity name.")
            if len(identity_id) > 256:
                raise ValueError("Identity name must be 256 characters or fewer.")
            if not out_path:
                raise ValueError("Please choose a private key output path.")
            path = Path(out_path)
            pub_path = _public_key_path(path)
            self._prepare_output(path)
            self._prepare_output(pub_path, input_paths=[path])
            ident = ClassicIdentity.generate()
            out = {
                "id": identity_id,
                "x25519_priv": ident.x25519_priv.hex(),
                "x25519_pub": ident.x25519_pub.hex(),
                "ed25519_priv": ident.ed25519_priv.hex(),
                "ed25519_pub": ident.ed25519_pub.hex(),
            }
            _write_private_json(path, out)
            atomic_write_text(pub_path, json.dumps({
                "id": out["id"],
                "x25519_pub": out["x25519_pub"],
                "ed25519_pub": out["ed25519_pub"],
            }, indent=2))
            messagebox.showinfo("Oversight", "Keypair generated.")
        except Exception as exc:
            messagebox.showerror("Oversight", str(exc))

    def _seal_file(self) -> None:
        try:
            input_path = _require_file(self.seal_input.get(), "input file")
            issuer_path = _require_file(self.seal_issuer.get(), "issuer private key")
            recipient_path = _require_file(self.seal_recipient.get(), "recipient public key")
            raw_out = self.seal_out.get().strip()
            out_path = Path(raw_out) if raw_out else _default_sealed_path(input_path)
            self._prepare_output(out_path, input_paths=[input_path, issuer_path, recipient_path])
            plaintext = input_path.read_bytes()
            canonical_plaintext = plaintext
            issuer = _read_private_identity(issuer_path, "Issuer file")
            rec_pub = _read_public_identity(recipient_path, "Recipient file")
            watermarks: list[WatermarkRef] = []
            decision = None

            if self.watermark_enabled.get():
                try:
                    text = plaintext.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ValueError(
                        "File is not UTF-8 text. Uncheck 'Embed L1/L2 watermarks' "
                        "to seal binary data."
                    ) from exc
                mark_id = watermark.new_mark_id()
                decision = l3_policy.decide_l3(
                    filename=str(input_path),
                    content_type=_validate_content_type(self.content_type.get()),
                    text=text,
                    requested_mode=self.l3_mode.get(),
                )
                if decision.enabled:
                    if not messagebox.askyesno(
                        "L3 disclosure",
                        "L3 semantic watermarking changes visible prose.\n\n"
                        f"Detected document class: {decision.document_class}\n"
                        f"Mode: {decision.mode}\n"
                        f"Reason: {decision.reason}\n\n"
                        "Continue?",
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

            registry_url = _validate_registry_url(self.registry_url.get())
            content_type = _validate_content_type(self.content_type.get())
            recipient = Recipient(rec_pub["id"], rec_pub["x25519_pub"], rec_pub.get("ed25519_pub"))
            manifest = Manifest.new(
                input_path.name,
                content_hash(plaintext),
                len(plaintext),
                issuer.get("id", "issuer"),
                issuer["ed25519_pub"],
                recipient,
                registry_url,
                content_type,
            )
            manifest.canonical_content_hash = content_hash(canonical_plaintext)
            manifest.watermarks = watermarks
            manifest.l3_policy = decision.to_dict() if decision else {}
            beacon_domain = _registry_domain(registry_url)
            manifest.beacons = [
                b.to_dict() for b in beacon.gen_beacons(beacon_domain, manifest.file_id, rec_pub["id"])
            ]
            blob = seal(plaintext, manifest, bytes.fromhex(issuer["ed25519_priv"]), bytes.fromhex(rec_pub["x25519_pub"]))
            atomic_write_bytes(out_path, blob)
            if watermarks:
                fp = ContentFingerprint.from_text(plaintext.decode("utf-8", errors="replace"))
                atomic_write_text(out_path.with_suffix(".fingerprint.json"), json.dumps({
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
            input_path = _require_file(self.open_input.get(), "sealed file")
            identity_path = _require_file(self.open_identity.get(), "recipient private key")
            out_path_raw = self.open_out.get().strip()
            if not out_path_raw:
                raise ValueError("Please choose a plaintext output path.")
            out_path = Path(out_path_raw)
            self._prepare_output(out_path, input_paths=[input_path, identity_path])
            ident = _read_private_identity(identity_path, "Recipient identity file")
            plaintext, _manifest = open_sealed(
                input_path.read_bytes(),
                bytes.fromhex(ident["x25519_priv"]),
            )
            atomic_write_bytes(out_path, plaintext)
            messagebox.showinfo("Oversight", "File opened.")
        except Exception as exc:
            messagebox.showerror("Oversight", str(exc))

    def _prepare_output(self, path: Path, input_paths: list[Path] | None = None) -> None:
        input_paths = input_paths or []
        if is_private_key_file(path):
            raise ValueError("Refusing to overwrite an Oversight private key file.")
        try:
            validate_output_path(path, input_paths=input_paths)
            return
        except FileExistsError:
            if not messagebox.askyesno("Overwrite file?", f"{path} already exists. Overwrite it?"):
                raise ValueError("Write cancelled; output file already exists.")
            validate_output_path(path, input_paths=input_paths, allow_existing=True)


def main() -> None:
    app = OversightGui()
    app.mainloop()


def _write_private_json(path: Path, data: dict) -> None:
    """Write private key material with restrictive permissions where supported."""
    atomic_write_private_json(path, data)


def _require_file(raw_path: str, label: str) -> Path:
    if not raw_path.strip():
        raise ValueError(f"Please choose a {label}.")
    path = Path(raw_path)
    if is_windows_reserved_path(path):
        raise ValueError(f"{label.capitalize()} uses a Windows reserved device name: {path.name}")
    if not path.exists() or not path.is_file():
        raise ValueError(f"{label.capitalize()} not found: {path}")
    return path


def _read_json(path: Path, label: str) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON.") from exc
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not UTF-8 JSON.") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{label} must contain a JSON object.")
    return data


def _read_private_identity(path: Path, label: str) -> dict:
    data = _read_json(path, label)
    for key in ("x25519_priv", "x25519_pub", "ed25519_priv", "ed25519_pub"):
        if key not in data:
            raise ValueError(f"{label} does not contain `{key}`; did you select a public key by mistake?")
        _validate_hex_field(data[key], key, 32)
    if "id" not in data:
        raise ValueError(f"{label} does not contain `id`.")
    return data


def _read_public_identity(path: Path, label: str) -> dict:
    data = _read_json(path, label)
    for key in ("id", "x25519_pub"):
        if key not in data:
            raise ValueError(f"{label} does not contain `{key}`.")
    _validate_hex_field(data["x25519_pub"], "x25519_pub", 32)
    if "ed25519_pub" in data:
        _validate_hex_field(data["ed25519_pub"], "ed25519_pub", 32)
    return data


def _validate_hex_field(value: object, key: str, expected_len: int) -> None:
    if not isinstance(value, str):
        raise ValueError(f"`{key}` must be hex text.")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"`{key}` is not valid hex.") from exc
    if len(raw) != expected_len:
        raise ValueError(f"`{key}` must decode to {expected_len} bytes.")


def _validate_registry_url(raw_url: str) -> str:
    url = (raw_url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Registry URL must be an http(s) URL with a host.")
    return url


def _registry_domain(registry_url: str) -> str:
    return urlparse(registry_url).netloc or "oversightprotocol.dev"


def _validate_content_type(raw_content_type: str) -> str:
    content_type = (raw_content_type or "application/octet-stream").strip()
    if any(ch in content_type for ch in "\r\n\"'<>"):
        raise ValueError("Content type contains unsafe characters.")
    if "/" not in content_type:
        raise ValueError("Content type must look like a MIME type, such as text/plain.")
    return content_type


def _public_key_path(private_path: Path) -> Path:
    name = private_path.name
    if name.lower().endswith(".pub.json"):
        raise ValueError("Private key output should not end with .pub.json.")
    if name.lower().endswith(".priv.json"):
        return private_path.with_name(name[:-10] + ".pub.json")
    return private_path.with_suffix(".pub.json")


def _default_sealed_path(input_path: Path) -> Path:
    if input_path.name.lower().endswith(".sealed"):
        return input_path.with_name(input_path.name + ".out.sealed")
    return Path(f"{input_path}.sealed")


if __name__ == "__main__":
    main()
