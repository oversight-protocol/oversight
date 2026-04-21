"""Filesystem safety helpers for key and sealed-file writes."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Iterable


WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def is_windows_reserved_path(path: Path) -> bool:
    """Return True if the final path component targets a Windows device name."""
    name = path.name.rstrip(" .")
    if not name:
        return False
    return name.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES


def is_private_key_file(path: Path) -> bool:
    """Best-effort detection for Oversight private identity JSON files."""
    if not path.exists() or not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return is_private_key_dict(data)


def is_private_key_dict(data: object) -> bool:
    return (
        isinstance(data, dict)
        and isinstance(data.get("x25519_priv"), str)
        and isinstance(data.get("ed25519_priv"), str)
    )


def same_path(a: Path, b: Path) -> bool:
    try:
        return a.resolve(strict=False) == b.resolve(strict=False)
    except OSError:
        return os.path.abspath(a) == os.path.abspath(b)


def validate_output_path(
    path: Path,
    *,
    input_paths: Iterable[Path] = (),
    allow_existing: bool = False,
    block_private_keys: bool = True,
) -> None:
    """Reject destructive or confusing output paths before writing."""
    if not str(path) or not path.name:
        raise ValueError("Please choose an output path.")
    if is_windows_reserved_path(path):
        raise ValueError(f"Refusing to write to Windows reserved device name: {path.name}")
    for input_path in input_paths:
        if input_path and same_path(path, input_path):
            raise ValueError("Output path must be different from every input path.")
    if block_private_keys and is_private_key_file(path):
        raise ValueError("Refusing to overwrite an Oversight private key file.")
    if path.exists() and not allow_existing:
        raise FileExistsError(f"Refusing to overwrite existing file: {path}")


def atomic_write_bytes(path: Path, data: bytes, *, mode: int | None = None) -> None:
    """Write bytes via temp file + fsync + atomic replace in the same directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        if mode is not None and os.name == "posix":
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def atomic_write_text(path: Path, text: str, *, mode: int | None = None) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def atomic_write_private_json(path: Path, data: dict) -> None:
    payload = json.dumps(data, indent=2)
    atomic_write_text(path, payload, mode=0o600)
    if os.name == "nt":
        harden_windows_private_file_acl(path)


def harden_windows_private_file_acl(path: Path) -> None:
    """Best-effort Windows ACL narrowing for private key files."""
    user = os.environ.get("USERNAME")
    if not user:
        return
    domain = os.environ.get("USERDOMAIN")
    principal = f"{domain}\\{user}" if domain else user
    subprocess.run(
        [
            "icacls",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"{principal}:(R,W)",
            "SYSTEM:(F)",
            "Administrators:(F)",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
