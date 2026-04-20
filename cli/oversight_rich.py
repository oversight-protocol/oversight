#!/usr/bin/env python3
"""
OVERSIGHT Rich CLI -- Interactive command-line interface with rich output.

Provides the `oversight` command with colorful, structured output for all
Oversight Protocol operations: key management, sealing, opening, inspection,
attribution, and registry interaction.

Entry point: main()
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

# Make oversight_core importable when running from repo root
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich import box

import httpx

from oversight_core import (
    ClassicIdentity,
    Manifest,
    Recipient,
    WatermarkRef,
    content_hash,
    seal,
    open_sealed,
    beacon,
    watermark,
    l3_policy,
    __version__ as core_version,
)
from oversight_core.container import SealedFile
from oversight_core.fingerprint import ContentFingerprint

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CLI_VERSION = "0.4.5"
CONFIG_FILENAME = "config.json"
CONFIG_DIR_NAME = ".oversight"

console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def print_banner():
    """Display the startup banner with version info."""
    banner_text = Text()
    banner_text.append("OVERSIGHT", style="bold bright_white")
    banner_text.append(" PROTOCOL", style="bold cyan")

    version_line = Text()
    version_line.append(f"cli v{CLI_VERSION}", style="dim")
    version_line.append("  |  ", style="dim")
    version_line.append(f"core v{core_version}", style="dim")
    version_line.append("  |  ", style="dim")
    version_line.append("Sealed Entity, Notarized Trust", style="dim italic")

    combined = Text()
    combined.append(banner_text)
    combined.append("\n")
    combined.append(version_line)

    console.print(Panel(
        combined,
        border_style="cyan",
        padding=(0, 2),
    ))


# ---------------------------------------------------------------------------
# Config discovery and management
# ---------------------------------------------------------------------------

def find_config_dir() -> Optional[Path]:
    """
    Search for .oversight/ directory. Order:
      1. Current working directory
      2. Parent directories (up to root)
      3. ~/.oversight/
    Returns the path if found, None otherwise.
    """
    # Check current and parents
    check = Path.cwd()
    while True:
        candidate = check / CONFIG_DIR_NAME
        if candidate.is_dir():
            return candidate
        parent = check.parent
        if parent == check:
            break
        check = parent

    # Check home directory
    home_config = Path.home() / CONFIG_DIR_NAME
    if home_config.is_dir():
        return home_config

    return None


def load_config() -> dict:
    """Load config from discovered .oversight/ directory. Returns empty dict if not found."""
    config_dir = find_config_dir()
    if config_dir is None:
        return {}
    config_file = config_dir / CONFIG_FILENAME
    if not config_file.exists():
        return {"_config_dir": str(config_dir)}
    try:
        cfg = json.loads(config_file.read_text())
        cfg["_config_dir"] = str(config_dir)
        return cfg
    except (json.JSONDecodeError, OSError) as e:
        err_console.print(f"[yellow]Warning: failed to read config: {e}[/]")
        return {"_config_dir": str(config_dir)}


def save_config(config_dir: Path, config: dict) -> None:
    """Write config to the given .oversight/ directory."""
    clean = {k: v for k, v in config.items() if not k.startswith("_")}
    config_file = config_dir / CONFIG_FILENAME
    config_file.write_text(json.dumps(clean, indent=2))


def config_dir_from_cfg(cfg: dict) -> Optional[Path]:
    """Extract the config directory path from a loaded config dict."""
    raw = cfg.get("_config_dir")
    if raw:
        return Path(raw)
    return None


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def error_panel(message: str, suggestion: str = "") -> None:
    """Print a red error panel with optional suggestion."""
    body = Text(message, style="bold red")
    if suggestion:
        body.append(f"\n\nSuggestion: {suggestion}", style="yellow")
    console.print(Panel(body, title="[red]Error[/]", border_style="red", padding=(0, 2)))


def success(message: str) -> None:
    console.print(f"[green][+][/] {message}")


def warn(message: str) -> None:
    console.print(f"[yellow][!][/] {message}")


def info(message: str) -> None:
    console.print(f"[cyan][*][/] {message}")


def format_hex_short(hex_str: str, length: int = 16) -> str:
    """Shorten a hex string for display."""
    if len(hex_str) <= length:
        return hex_str
    return hex_str[:length] + "..."


# ---------------------------------------------------------------------------
# Command: init
# ---------------------------------------------------------------------------

def cmd_init(args):
    """Initialize a .oversight/ directory with config."""
    target = Path(args.path) if args.path else Path.cwd()
    config_dir = target / CONFIG_DIR_NAME

    if config_dir.exists() and not args.force:
        error_panel(
            f"Directory already exists: {config_dir}",
            "Use --force to reinitialize."
        )
        sys.exit(1)

    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "recipients").mkdir(exist_ok=True)
    (config_dir / "fingerprints").mkdir(exist_ok=True)

    config = {
        "issuer_identity": "",
        "registry_url": args.registry_url or "http://localhost:8000",
        "registry_domain": args.registry_domain or "oversightprotocol.dev",
        "default_watermark": True,
        "content_type": "application/octet-stream",
    }

    save_config(config_dir, config)

    console.print(Panel(
        Text.assemble(
            ("Initialized .oversight/ directory\n\n", "bold green"),
            ("Location: ", ""),
            (str(config_dir), "cyan"),
            ("\n\nCreated:\n", ""),
            ("  config.json       ", "white"),
            ("- project configuration\n", "dim"),
            ("  recipients/       ", "white"),
            ("- recipient public keys\n", "dim"),
            ("  fingerprints/     ", "white"),
            ("- content fingerprints", "dim"),
        ),
        title="[green]Init Complete[/]",
        border_style="green",
        padding=(0, 2),
    ))

    if not config["issuer_identity"]:
        warn("No issuer identity set. Run: oversight keys generate")


# ---------------------------------------------------------------------------
# Command: keys generate
# ---------------------------------------------------------------------------

def cmd_keys_generate(args):
    """Generate a new identity keypair."""
    cfg = load_config()
    config_dir = config_dir_from_cfg(cfg)

    # Determine output paths
    identity_name = args.name or "identity"

    if args.out:
        out_path = Path(args.out)
    elif config_dir:
        out_path = config_dir / f"{identity_name}.json"
    else:
        out_path = Path(f"{identity_name}.json")

    if out_path.exists() and not args.force:
        error_panel(
            f"Identity file already exists: {out_path}",
            "Use --force to overwrite."
        )
        sys.exit(1)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Generating X25519 + Ed25519 keypair...", total=None)
        ident = ClassicIdentity.generate()

    priv_data = {
        "id": identity_name,
        "x25519_priv": ident.x25519_priv.hex(),
        "x25519_pub": ident.x25519_pub.hex(),
        "ed25519_priv": ident.ed25519_priv.hex(),
        "ed25519_pub": ident.ed25519_pub.hex(),
    }

    pub_path = out_path.with_suffix(".pub.json")
    pub_data = {
        "id": identity_name,
        "x25519_pub": ident.x25519_pub.hex(),
        "ed25519_pub": ident.ed25519_pub.hex(),
    }

    out_path.write_text(json.dumps(priv_data, indent=2))
    pub_path.write_text(json.dumps(pub_data, indent=2))

    # Update config if we have one
    if config_dir and not args.out:
        cfg["issuer_identity"] = str(out_path)
        save_config(config_dir, cfg)

    table = Table(title="Generated Identity", box=box.ROUNDED, border_style="green")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Name", identity_name)
    table.add_row("Private key", str(out_path))
    table.add_row("Public key", str(pub_path))
    table.add_row("X25519 pub", format_hex_short(ident.x25519_pub.hex(), 32))
    table.add_row("Ed25519 pub", format_hex_short(ident.ed25519_pub.hex(), 32))
    table.add_row("Suite", "OSGT-CLASSIC-v1 (X25519 + Ed25519)")
    console.print(table)
    success("Identity generated. Share the .pub.json file with senders.")


# ---------------------------------------------------------------------------
# Command: keys list
# ---------------------------------------------------------------------------

def cmd_keys_list(args):
    """List all known identities and recipients."""
    cfg = load_config()
    config_dir = config_dir_from_cfg(cfg)

    if not config_dir:
        error_panel(
            "No .oversight/ directory found.",
            "Run: oversight init"
        )
        sys.exit(1)

    # List identities (*.json but not *.pub.json in config root)
    identity_files = [
        f for f in config_dir.glob("*.json")
        if not f.name.endswith(".pub.json") and f.name != CONFIG_FILENAME
    ]

    table = Table(title="Identities", box=box.ROUNDED, border_style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Ed25519 Public Key", style="white")
    table.add_column("X25519 Public Key", style="white")
    table.add_column("File", style="dim")

    for f in identity_files:
        try:
            data = json.loads(f.read_text())
            is_active = str(f) == cfg.get("issuer_identity", "")
            name = data.get("id", f.stem)
            if is_active:
                name = f"[green]{name} (active)[/green]"
            table.add_row(
                name,
                format_hex_short(data.get("ed25519_pub", ""), 24),
                format_hex_short(data.get("x25519_pub", ""), 24),
                f.name,
            )
        except (json.JSONDecodeError, OSError):
            table.add_row(f.stem, "[red]error reading[/]", "", f.name)

    console.print(table)

    # List recipients
    recipients_dir = config_dir / "recipients"
    recipient_files = list(recipients_dir.glob("*.json")) if recipients_dir.exists() else []

    if recipient_files:
        rtable = Table(title="Recipients", box=box.ROUNDED, border_style="yellow")
        rtable.add_column("ID", style="bold")
        rtable.add_column("Ed25519 Public Key", style="white")
        rtable.add_column("X25519 Public Key", style="white")
        rtable.add_column("File", style="dim")

        for f in recipient_files:
            try:
                data = json.loads(f.read_text())
                rtable.add_row(
                    data.get("id", f.stem),
                    format_hex_short(data.get("ed25519_pub", ""), 24),
                    format_hex_short(data.get("x25519_pub", ""), 24),
                    f.name,
                )
            except (json.JSONDecodeError, OSError):
                rtable.add_row(f.stem, "[red]error reading[/]", "", f.name)

        console.print(rtable)
    else:
        info("No recipients imported. Use: oversight keys import <file>")


# ---------------------------------------------------------------------------
# Command: keys import
# ---------------------------------------------------------------------------

def cmd_keys_import(args):
    """Import a recipient's public key."""
    cfg = load_config()
    config_dir = config_dir_from_cfg(cfg)

    if not config_dir:
        error_panel(
            "No .oversight/ directory found.",
            "Run: oversight init"
        )
        sys.exit(1)

    source = Path(args.file)
    if not source.exists():
        error_panel(f"File not found: {source}")
        sys.exit(1)

    try:
        data = json.loads(source.read_text())
    except (json.JSONDecodeError, OSError) as e:
        error_panel(f"Failed to parse key file: {e}")
        sys.exit(1)

    # Validate it has the needed fields
    if "x25519_pub" not in data:
        error_panel(
            "Key file missing x25519_pub field.",
            "Ensure this is a valid Oversight public key (.pub.json)."
        )
        sys.exit(1)

    recipients_dir = config_dir / "recipients"
    recipients_dir.mkdir(exist_ok=True)

    name = data.get("id", source.stem)
    dest = recipients_dir / f"{name}.pub.json"

    if dest.exists() and not args.force:
        error_panel(
            f"Recipient already exists: {dest}",
            "Use --force to overwrite."
        )
        sys.exit(1)

    dest.write_text(json.dumps(data, indent=2))
    success(f"Imported recipient '{name}' to {dest}")


# ---------------------------------------------------------------------------
# Command: seal
# ---------------------------------------------------------------------------

def cmd_seal(args):
    """Seal a file for a recipient with full rich output."""
    cfg = load_config()
    config_dir = config_dir_from_cfg(cfg)

    input_path = Path(args.input)
    if not input_path.exists():
        error_panel(f"Input file not found: {input_path}")
        sys.exit(1)

    # Resolve issuer identity
    issuer_key_path = args.issuer_key
    if not issuer_key_path and cfg.get("issuer_identity"):
        issuer_key_path = cfg["issuer_identity"]
    if not issuer_key_path:
        error_panel(
            "No issuer identity specified.",
            "Use --issuer-key or set issuer_identity in config. Run: oversight keys generate"
        )
        sys.exit(1)

    issuer_key_path = Path(issuer_key_path)
    if not issuer_key_path.exists():
        error_panel(f"Issuer key file not found: {issuer_key_path}")
        sys.exit(1)

    # Resolve recipient public key
    recipient_pub_path = args.to
    if not recipient_pub_path and config_dir:
        # Check recipients dir for a single recipient
        rdir = config_dir / "recipients"
        if rdir.exists():
            rfiles = list(rdir.glob("*.json"))
            if len(rfiles) == 1:
                recipient_pub_path = str(rfiles[0])

    if not recipient_pub_path:
        error_panel(
            "No recipient specified.",
            "Use --to <recipient.pub.json> or place a single key in .oversight/recipients/"
        )
        sys.exit(1)

    recipient_pub_path = Path(recipient_pub_path)
    if not recipient_pub_path.exists():
        # Try looking in recipients dir
        if config_dir:
            candidate = config_dir / "recipients" / f"{recipient_pub_path}.pub.json"
            if candidate.exists():
                recipient_pub_path = candidate
            else:
                candidate = config_dir / "recipients" / str(recipient_pub_path)
                if candidate.exists():
                    recipient_pub_path = candidate
        if not recipient_pub_path.exists():
            error_panel(f"Recipient key file not found: {recipient_pub_path}")
            sys.exit(1)

    # Load keys
    issuer = json.loads(issuer_key_path.read_text())
    rec_pub = json.loads(recipient_pub_path.read_text())
    plaintext = input_path.read_bytes()

    # Determine output path
    out_path = Path(args.out) if args.out else input_path.with_suffix(".sealed")

    # Resolve settings
    registry_url = args.registry_url or cfg.get("registry_url", "http://localhost:8000")
    registry_domain = args.registry_domain or cfg.get("registry_domain", "oversightprotocol.dev")
    issuer_id = args.issuer_id or issuer.get("id", "issuer")
    do_watermark = args.watermark if args.watermark is not None else cfg.get("default_watermark", True)
    content_type_val = args.content_type or cfg.get("content_type", "application/octet-stream")

    canonical_plaintext = plaintext
    watermarks_for_manifest: list[WatermarkRef] = []
    fingerprint = None
    mark_id = None
    l3_decision = None

    # Run the seal pipeline with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        total_steps = 7 if do_watermark else 4
        task = progress.add_task("Sealing...", total=total_steps)

        # Step 1-3: Watermarking (if enabled)
        if do_watermark:
            try:
                text = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                warn("Input is not UTF-8 text; skipping watermarks.")
                text = None
                progress.advance(task, 3)

            if text is not None:
                mark_id = watermark.new_mark_id()
                l3_decision = l3_policy.decide_l3(
                    filename=str(input_path),
                    content_type=content_type_val,
                    text=text,
                    declared_class=args.document_class,
                    requested_mode=args.l3_mode,
                )

                progress.update(task, description="Evaluating L3 safety policy...")
                if l3_decision.enabled:
                    progress.stop()
                    if not args.l3_ack:
                        console.print(Panel(
                            "L3 semantic watermarking changes visible prose. "
                            f"Class: [bold]{l3_decision.document_class}[/], "
                            f"mode: [bold]{l3_decision.mode}[/].\n\n"
                            "Enable only when you accept that the recipient copy "
                            "is textually non-identical to the canonical source.",
                            title="[yellow]L3 Disclosure[/]",
                            border_style="yellow",
                        ))
                        if not Confirm.ask("Acknowledge and apply L3?", default=False):
                            error_panel("L3 not acknowledged. Re-run with --l3-mode off or --l3-ack.")
                            sys.exit(1)
                    progress.start()
                    progress.update(task, description=f"Watermarking L3 ({l3_decision.mode})...")
                    text = l3_policy.apply_l3_safe(text, mark_id, mode=l3_decision.mode)
                else:
                    progress.update(task, description=f"Skipping L3: {l3_decision.document_class}")
                progress.advance(task)

                progress.update(task, description="Watermarking L2 (whitespace)...")
                text = watermark.embed_ws(text, mark_id)
                progress.advance(task)

                progress.update(task, description="Watermarking L1 (zero-width)...")
                text = watermark.embed_zw(text, mark_id)
                plaintext = text.encode("utf-8")
                progress.advance(task)

                watermarks_for_manifest = [
                    WatermarkRef(layer="L1_zero_width", mark_id=mark_id.hex()),
                    WatermarkRef(layer="L2_whitespace", mark_id=mark_id.hex()),
                ]
                if l3_decision and l3_decision.enabled:
                    watermarks_for_manifest.append(
                        WatermarkRef(layer=f"L3_semantic_{l3_decision.mode}", mark_id=mark_id.hex())
                    )

        # Step 4: Build manifest
        progress.update(task, description="Building manifest...")
        recipient_obj = Recipient(
            recipient_id=rec_pub["id"],
            x25519_pub=rec_pub["x25519_pub"],
            ed25519_pub=rec_pub.get("ed25519_pub"),
        )

        beacons = beacon.gen_beacons(
            registry_domain=registry_domain,
            file_id="pending",
            recipient_id=rec_pub["id"],
        )

        manifest = Manifest.new(
            original_filename=input_path.name,
            content_hash=content_hash(plaintext),
            size_bytes=len(plaintext),
            issuer_id=issuer_id,
            issuer_ed25519_pub_hex=issuer["ed25519_pub"],
            recipient=recipient_obj,
            registry_url=registry_url,
            content_type=content_type_val,
        )
        manifest.canonical_content_hash = content_hash(canonical_plaintext)
        if l3_decision:
            manifest.l3_policy = l3_decision.to_dict()
        manifest.watermarks = watermarks_for_manifest
        manifest.beacons = [b.to_dict() for b in beacons]
        progress.advance(task)

        # Step 5: Compute fingerprint
        progress.update(task, description="Computing content fingerprint...")
        try:
            fp_text = plaintext.decode("utf-8")
            fingerprint = ContentFingerprint.from_text(fp_text)
        except UnicodeDecodeError:
            pass
        progress.advance(task)

        # Step 6: Encrypt and seal
        progress.update(task, description="Encrypting (XChaCha20-Poly1305)...")
        blob = seal(
            plaintext=plaintext,
            manifest=manifest,
            issuer_ed25519_priv=bytes.fromhex(issuer["ed25519_priv"]),
            recipient_x25519_pub=bytes.fromhex(rec_pub["x25519_pub"]),
        )
        progress.advance(task)

        # Step 7: Write output
        progress.update(task, description="Writing sealed file...")
        out_path.write_bytes(blob)

        if fingerprint:
            fp_path = out_path.with_suffix(".fingerprint.json")
            fp_path.write_text(json.dumps({
                "file_id": manifest.file_id,
                "recipient_id": rec_pub["id"],
                "mark_id": mark_id.hex() if mark_id else None,
                "canonical_content_hash": manifest.canonical_content_hash,
                "l3_policy": manifest.l3_policy,
                "fingerprint": fingerprint.to_dict(),
            }, indent=2))

        progress.advance(task)

    # Summary panel
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Output", str(out_path))
    table.add_row("Size", f"{len(blob):,} bytes")
    table.add_row("File ID", manifest.file_id)
    table.add_row("Issuer", issuer_id)
    table.add_row("Recipient", rec_pub["id"])
    table.add_row("Watermarks", str(len(watermarks_for_manifest)))
    if l3_decision:
        table.add_row("L3 policy", f"{l3_decision.mode} ({l3_decision.document_class})")
    table.add_row("Beacons", str(len(beacons)))
    table.add_row("Suite", "OSGT-CLASSIC-v1")
    if mark_id:
        table.add_row("Mark ID", mark_id.hex())
    if fingerprint:
        table.add_row("Fingerprint", f"{len(fingerprint.winnowing_fp)} winnow, {len(fingerprint.sentence_fp)} sentence hashes")

    console.print(Panel(table, title="[green]Sealed[/]", border_style="green", padding=(0, 1)))

    # Register if requested
    register_url = args.register or cfg.get("auto_register")
    if register_url:
        _do_register(register_url, manifest, beacons, watermarks_for_manifest, fingerprint)


def _do_register(register_url: str, manifest, beacons, watermarks_for_manifest, fingerprint):
    """Register with the registry server."""
    reg_payload = {
        "manifest": manifest.to_dict(),
        "beacons": [b.to_dict() for b in beacons],
        "watermarks": [w.__dict__ for w in watermarks_for_manifest],
    }
    if fingerprint:
        reg_payload["fingerprint"] = fingerprint.to_dict()
    try:
        resp = httpx.post(
            f"{register_url.rstrip('/')}/register",
            json=reg_payload,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        success(f"Registered with {register_url}: tlog_index={data.get('tlog_index')}")
    except Exception as e:
        warn(f"Registry registration failed: {e}")


# ---------------------------------------------------------------------------
# Command: open
# ---------------------------------------------------------------------------

def cmd_open(args):
    """Open (decrypt) a sealed file."""
    cfg = load_config()

    input_path = Path(args.input)
    if not input_path.exists():
        error_panel(f"Sealed file not found: {input_path}")
        sys.exit(1)

    # Resolve identity
    identity_path = args.identity
    if not identity_path and cfg.get("issuer_identity"):
        identity_path = cfg["issuer_identity"]
    if not identity_path:
        error_panel(
            "No identity specified.",
            "Use --identity <file> or set issuer_identity in config."
        )
        sys.exit(1)

    identity_path = Path(identity_path)
    if not identity_path.exists():
        error_panel(f"Identity file not found: {identity_path}")
        sys.exit(1)

    out_path = Path(args.out) if args.out else input_path.with_suffix("")

    ident = json.loads(identity_path.read_text())

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Decrypting...", total=None)

        try:
            blob = input_path.read_bytes()
            plaintext, manifest = open_sealed(
                blob,
                recipient_x25519_priv=bytes.fromhex(ident["x25519_priv"]),
            )
            out_path.write_bytes(plaintext)
        except ValueError as e:
            error_panel(
                f"Decryption failed: {e}",
                "Verify you are using the correct recipient identity."
            )
            sys.exit(1)

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Output", str(out_path))
    table.add_row("Size", f"{len(plaintext):,} bytes")
    table.add_row("File ID", manifest.file_id)
    table.add_row("Issuer", manifest.issuer_id)
    table.add_row("Recipient", manifest.recipient.recipient_id if manifest.recipient else "unknown")
    table.add_row("Watermarks", str(len(manifest.watermarks)))
    table.add_row("Beacons", str(len(manifest.beacons)))

    console.print(Panel(table, title="[green]Decrypted[/]", border_style="green", padding=(0, 1)))


# ---------------------------------------------------------------------------
# Command: inspect
# ---------------------------------------------------------------------------

def cmd_inspect(args):
    """Display the manifest from a sealed file without decrypting."""
    input_path = Path(args.input)
    if not input_path.exists():
        error_panel(f"Sealed file not found: {input_path}")
        sys.exit(1)

    try:
        blob = input_path.read_bytes()
        sf = SealedFile.from_bytes(blob)
    except ValueError as e:
        error_panel(f"Failed to parse sealed file: {e}")
        sys.exit(1)

    m = sf.manifest
    sig_valid = m.verify()

    # Header info
    header = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    header.add_column("Key", style="cyan")
    header.add_column("Value", style="white")
    header.add_row("File", str(input_path))
    header.add_row("Version", m.version)
    header.add_row("Suite", m.suite)
    header.add_row("File ID", m.file_id)
    header.add_row("Issued At", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(m.issued_at)))

    sig_style = "bold green" if sig_valid else "bold red"
    sig_text = "VALID" if sig_valid else "INVALID"
    header.add_row("Signature", f"[{sig_style}]{sig_text}[/]")

    console.print(Panel(header, title="[cyan]Manifest[/]", border_style="cyan", padding=(0, 1)))

    # Content info
    content = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    content.add_column("Key", style="cyan")
    content.add_column("Value", style="white")
    content.add_row("Filename", m.original_filename)
    content.add_row("Content Type", m.content_type)
    content.add_row("Size", f"{m.size_bytes:,} bytes")
    content.add_row("Content Hash", format_hex_short(m.content_hash, 32))

    console.print(Panel(content, title="[cyan]Content[/]", border_style="cyan", padding=(0, 1)))

    # Identity info
    ident_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    ident_table.add_column("Key", style="cyan")
    ident_table.add_column("Value", style="white")
    ident_table.add_row("Issuer ID", m.issuer_id)
    ident_table.add_row("Issuer Ed25519", format_hex_short(m.issuer_ed25519_pub, 32))
    if m.recipient:
        ident_table.add_row("Recipient ID", m.recipient.recipient_id)
        ident_table.add_row("Recipient X25519", format_hex_short(m.recipient.x25519_pub, 32))

    console.print(Panel(ident_table, title="[cyan]Identities[/]", border_style="cyan", padding=(0, 1)))

    # Watermarks
    if m.watermarks:
        wm_table = Table(box=box.ROUNDED, border_style="yellow")
        wm_table.add_column("Layer", style="bold")
        wm_table.add_column("Mark ID", style="white")
        for w in m.watermarks:
            wm_table.add_row(w.layer, w.mark_id)
        console.print(wm_table)

    # Beacons
    if m.beacons:
        b_table = Table(box=box.ROUNDED, border_style="magenta")
        b_table.add_column("Kind", style="bold")
        b_table.add_column("Token ID", style="white")
        b_table.add_column("URL", style="dim")
        for b in m.beacons:
            b_table.add_row(
                b.get("kind", ""),
                format_hex_short(b.get("token_id", ""), 20),
                b.get("url", ""),
            )
        console.print(b_table)

    # Policy
    if m.policy:
        p_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        p_table.add_column("Key", style="cyan")
        p_table.add_column("Value", style="white")
        for k, v in m.policy.items():
            p_table.add_row(k, str(v))
        console.print(Panel(p_table, title="[cyan]Policy[/]", border_style="cyan", padding=(0, 1)))

    # Raw JSON option
    if args.json:
        console.print(Rule("Raw Manifest JSON"))
        console.print_json(json.dumps(m.to_dict(), default=str))


# ---------------------------------------------------------------------------
# Command: attribute
# ---------------------------------------------------------------------------

def cmd_attribute(args):
    """Run full 5-phase attribution on a leaked file."""
    cfg = load_config()

    leak_path = Path(args.leak)
    if not leak_path.exists():
        error_panel(f"Leak file not found: {leak_path}")
        sys.exit(1)

    text = leak_path.read_text(encoding="utf-8", errors="replace")
    registry_url = args.registry or cfg.get("registry_url", "http://localhost:8000")

    # Resolve fingerprints path
    fingerprints_path = args.fingerprints
    if not fingerprints_path and cfg.get("_config_dir"):
        fp_dir = Path(cfg["_config_dir"]) / "fingerprints"
        if fp_dir.exists() and any(fp_dir.glob("*.fingerprint.json")):
            fingerprints_path = str(fp_dir)

    console.print(Rule("[bold]Attribution Analysis[/]", style="red"))
    console.print()

    # ===== Phase 1: Direct extraction =====
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task("Phase 1: Extracting L1 + L2 marks...", total=None)
        l1_marks = watermark.extract_zw(text)
        l2_candidate, l2_conf, l2_bits, l2_needed = watermark.extract_ws_partial(text)

    l1_unique = list(set(l1_marks))
    direct_candidates: list[bytes] = list(l1_unique)
    if l2_candidate and l2_conf >= 0.5:
        if l2_candidate not in direct_candidates:
            direct_candidates.append(l2_candidate)

    p1_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    p1_table.add_column("Layer", style="cyan", width=8)
    p1_table.add_column("Result", style="white")

    if l1_unique:
        for m_id in l1_unique:
            p1_table.add_row("L1", f"[green]{m_id.hex()}[/] ({len(l1_marks)} frames, {len(l1_unique)} unique)")
    else:
        p1_table.add_row("L1", "[red]No zero-width frames found (stripped?)[/]")

    if l2_conf >= 1.0:
        p1_table.add_row("L2", f"[green]{l2_candidate.hex()}[/] ({l2_bits}/{l2_needed} bits, 100%)")
    elif l2_conf > 0:
        p1_table.add_row("L2", f"[yellow]{l2_candidate.hex()}[/] ({l2_bits}/{l2_needed} bits, {l2_conf:.0%} partial)")
    else:
        p1_table.add_row("L2", "[red]No trailing whitespace marks found (stripped?)[/]")

    console.print(Panel(p1_table, title="[bold]Phase 1: Direct Extraction[/]", border_style="cyan", padding=(0, 1)))

    # ===== Phase 2: Registry query =====
    registry_candidates: list[bytes] = []
    p2_results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(f"Phase 2: Querying registry at {registry_url}...", total=None)

        if direct_candidates:
            for m_id in direct_candidates:
                try:
                    resp = httpx.post(
                        f"{registry_url.rstrip('/')}/attribute",
                        json={"mark_id": m_id.hex(), "layer": "L1_zero_width"},
                        timeout=10,
                    )
                    data = resp.json()
                    if data.get("found"):
                        p2_results.append((m_id.hex(), data.get("recipient_id"), data.get("file_id")))
                except Exception as e:
                    p2_results.append((m_id.hex(), f"query failed: {e}", None))

        try:
            resp = httpx.get(f"{registry_url.rstrip('/')}/marks", timeout=10)
            if resp.status_code == 200:
                registry_data = resp.json()
                for entry in registry_data.get("marks", []):
                    mid_bytes = bytes.fromhex(entry["mark_id"])
                    if mid_bytes not in registry_candidates:
                        registry_candidates.append(mid_bytes)
        except Exception:
            pass

    p2_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    p2_table.add_column("Field", style="cyan")
    p2_table.add_column("Value", style="white")

    if p2_results:
        for mark_hex, recipient, file_id in p2_results:
            if file_id:
                p2_table.add_row("Match", f"[green]{mark_hex}[/] -> recipient={recipient}, file={file_id}")
            else:
                p2_table.add_row("Query", f"{mark_hex}: {recipient}")
    else:
        p2_table.add_row("Result", "No direct candidates to query" if not direct_candidates else "No matches found")

    if registry_candidates:
        p2_table.add_row("Registry", f"Fetched {len(registry_candidates)} candidate mark_id(s)")

    console.print(Panel(p2_table, title="[bold]Phase 2: Registry Query[/]", border_style="cyan", padding=(0, 1)))

    # ===== Phase 3: L3 semantic verification =====
    all_candidates = direct_candidates + [
        m_id for m_id in registry_candidates if m_id not in direct_candidates
    ]

    p3_hits = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(f"Phase 3: L3 semantic verification ({len(all_candidates)} candidates)...", total=None)
        if all_candidates:
            p3_hits = watermark.verify_l3(text, all_candidates)

    p3_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    p3_table.add_column("Field", style="cyan")
    p3_table.add_column("Value", style="white")

    if p3_hits:
        for mid, score, detail in p3_hits:
            p3_table.add_row(
                "L3 Match",
                f"[green]{mid.hex()}[/] score={score:.2f} "
                f"(synonyms={detail['synonyms_score']:.2f}, "
                f"punct={detail['punctuation_hits']}, dict={detail['dict_version']})"
            )
    elif not all_candidates:
        p3_table.add_row("Result", "[yellow]No candidates available (L1/L2 stripped, registry unreachable?)[/]")
    else:
        p3_table.add_row("Result", f"[yellow]No candidates matched above threshold ({len(all_candidates)} tested)[/]")

    console.print(Panel(p3_table, title="[bold]Phase 3: Semantic Verification[/]", border_style="cyan", padding=(0, 1)))

    # ===== Phase 4: Multi-layer fusion =====
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task("Phase 4: Multi-layer Bayesian fusion...", total=None)
        result = watermark.recover_marks_v2(text, all_candidates if all_candidates else None)

    if result["candidates"]:
        fusion_table = Table(box=box.ROUNDED, border_style="green")
        fusion_table.add_column("Mark ID", style="bold white")
        fusion_table.add_column("Score", style="bold")
        fusion_table.add_column("Layers", style="cyan")

        for mark_id_val, score, layers in result["candidates"]:
            score_style = "green" if score >= 0.8 else "yellow" if score >= 0.5 else "red"
            fusion_table.add_row(
                mark_id_val.hex(),
                f"[{score_style}]{score:.1%}[/]",
                layers,
            )

        console.print(Panel(fusion_table, title="[bold]Phase 4: Fusion Results[/]", border_style="green", padding=(0, 1)))

        best = result["candidates"][0]
        attribution_body = Text()
        attribution_body.append(f"Mark ID:    {best[0].hex()}\n", style="bold white")
        attribution_body.append(f"Confidence: {best[1]:.1%}\n", style="bold green" if best[1] >= 0.8 else "bold yellow")
        attribution_body.append(f"Evidence:   {best[2]}\n", style="cyan")

        # Final registry lookup
        try:
            resp = httpx.post(
                f"{registry_url.rstrip('/')}/attribute",
                json={"mark_id": best[0].hex(), "layer": "fused"},
                timeout=10,
            )
            data = resp.json()
            if data.get("found"):
                attribution_body.append(f"File ID:    {data['file_id']}\n", style="white")
                attribution_body.append(f"Recipient:  {data['recipient_id']}\n", style="bold white")
                attribution_body.append(f"Issuer:     {data['issuer_id']}\n", style="white")
        except Exception:
            pass

        console.print(Panel(
            attribution_body,
            title="[bold red]ATTRIBUTION[/]",
            border_style="red",
            padding=(0, 2),
        ))
    else:
        console.print(Panel(
            "[red]No marks recovered from any layer.[/]",
            title="[bold]Phase 4: Fusion[/]",
            border_style="red",
            padding=(0, 2),
        ))
        if result["diagnostics"]:
            for d in result["diagnostics"]:
                info(d)

    # ===== Phase 5: Content fingerprint comparison =====
    if fingerprints_path:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task("Phase 5: Content fingerprint comparison...", total=None)
            leak_fp = ContentFingerprint.from_text(text)

        fp_dir = Path(fingerprints_path)
        if fp_dir.is_dir():
            fp_files = list(fp_dir.glob("*.fingerprint.json"))
        elif fp_dir.is_file():
            fp_files = [fp_dir]
        else:
            fp_files = []

        if fp_files:
            fp_table = Table(box=box.ROUNDED, border_style="magenta")
            fp_table.add_column("File", style="dim")
            fp_table.add_column("Recipient", style="bold")
            fp_table.add_column("Winnow", style="white")
            fp_table.add_column("Sentence", style="white")
            fp_table.add_column("Combined", style="bold")
            fp_table.add_column("Verdict", style="bold")

            best_fp_match = None
            best_fp_score = 0.0

            for fp_file in fp_files:
                try:
                    fp_data = json.loads(fp_file.read_text())
                    stored_fp = ContentFingerprint.from_dict(fp_data["fingerprint"])
                    sim = leak_fp.similarity(stored_fp)
                    recipient_id = fp_data.get("recipient_id", "unknown")
                    fp_mark_id = fp_data.get("mark_id", "unknown")

                    if sim["combined"] >= 0.1:
                        verdict_style = (
                            "green" if sim["verdict"] == "MATCH"
                            else "yellow" if sim["verdict"] == "LIKELY"
                            else "red"
                        )
                        fp_table.add_row(
                            fp_file.name,
                            recipient_id,
                            f"{sim['winnowing']:.2f}",
                            f"{sim['sentence']:.2f}",
                            f"{sim['combined']:.2f}",
                            f"[{verdict_style}]{sim['verdict']}[/]",
                        )

                    if sim["combined"] > best_fp_score:
                        best_fp_score = sim["combined"]
                        best_fp_match = {
                            "file": fp_file.name,
                            "recipient_id": recipient_id,
                            "mark_id": fp_mark_id,
                            "similarity": sim,
                        }
                except Exception as e:
                    warn(f"Error reading {fp_file.name}: {e}")

            console.print(Panel(fp_table, title="[bold]Phase 5: Fingerprint Comparison[/]", border_style="magenta", padding=(0, 1)))

            if best_fp_match and best_fp_score >= 0.3:
                fp_body = Text()
                fp_body.append(f"Verdict:    {best_fp_match['similarity']['verdict']}\n", style="bold")
                fp_body.append(f"Recipient:  {best_fp_match['recipient_id']}\n", style="bold white")
                fp_body.append(f"Mark ID:    {best_fp_match['mark_id']}\n", style="white")
                fp_body.append(f"Confidence: {best_fp_score:.1%}\n", style="green")
                fp_body.append(f"Winnowing:  {best_fp_match['similarity']['winnowing']:.1%}\n", style="dim")
                fp_body.append(f"Sentence:   {best_fp_match['similarity']['sentence']:.1%}", style="dim")

                console.print(Panel(
                    fp_body,
                    title="[bold magenta]FINGERPRINT ATTRIBUTION[/]",
                    border_style="magenta",
                    padding=(0, 2),
                ))
        else:
            info("No fingerprint files found to compare against.")


# ---------------------------------------------------------------------------
# Command: status
# ---------------------------------------------------------------------------

def cmd_status(args):
    """Show config, identity, registry health, version info."""
    cfg = load_config()
    config_dir = config_dir_from_cfg(cfg)

    # Version and config panel
    status_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    status_table.add_column("Key", style="cyan")
    status_table.add_column("Value", style="white")
    status_table.add_row("CLI version", CLI_VERSION)
    status_table.add_row("Core version", core_version)

    if config_dir:
        status_table.add_row("Config dir", str(config_dir))
    else:
        status_table.add_row("Config dir", "[yellow]not found (run: oversight init)[/]")

    # Config values
    if cfg.get("issuer_identity"):
        ident_path = Path(cfg["issuer_identity"])
        if ident_path.exists():
            try:
                ident_data = json.loads(ident_path.read_text())
                status_table.add_row("Issuer ID", ident_data.get("id", "unknown"))
                status_table.add_row("Ed25519 pub", format_hex_short(ident_data.get("ed25519_pub", ""), 32))
            except (json.JSONDecodeError, OSError):
                status_table.add_row("Issuer identity", f"[red]error reading {ident_path}[/]")
        else:
            status_table.add_row("Issuer identity", f"[yellow]file not found: {ident_path}[/]")
    else:
        status_table.add_row("Issuer identity", "[yellow]not configured[/]")

    registry_url = cfg.get("registry_url", "not configured")
    status_table.add_row("Registry URL", registry_url)
    status_table.add_row("Default watermark", str(cfg.get("default_watermark", "not set")))

    # Recipients count
    if config_dir:
        rdir = config_dir / "recipients"
        rcount = len(list(rdir.glob("*.json"))) if rdir.exists() else 0
        status_table.add_row("Recipients", str(rcount))

        fdir = config_dir / "fingerprints"
        fcount = len(list(fdir.glob("*.fingerprint.json"))) if fdir.exists() else 0
        status_table.add_row("Fingerprints", str(fcount))

    console.print(Panel(status_table, title="[cyan]Oversight Status[/]", border_style="cyan", padding=(0, 1)))

    # Registry health check
    if registry_url and registry_url != "not configured":
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(f"Checking registry at {registry_url}...", total=None)
            try:
                resp = httpx.get(f"{registry_url.rstrip('/')}/health", timeout=5)
                if resp.status_code == 200:
                    health_data = resp.json()
                    htable = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
                    htable.add_column("Key", style="cyan")
                    htable.add_column("Value", style="white")
                    htable.add_row("Status", f"[green]{health_data.get('status', 'ok')}[/]")
                    htable.add_row("Service", health_data.get("service", "unknown"))
                    htable.add_row("Version", health_data.get("version", "unknown"))
                    htable.add_row("TLog size", str(health_data.get("tlog_size", 0)))
                    console.print(Panel(htable, title="[green]Registry Health[/]", border_style="green", padding=(0, 1)))
                else:
                    warn(f"Registry returned HTTP {resp.status_code}")
            except httpx.ConnectError:
                warn(f"Registry unreachable at {registry_url}")
            except Exception as e:
                warn(f"Registry check failed: {e}")


# ---------------------------------------------------------------------------
# Command: registry start
# ---------------------------------------------------------------------------

def cmd_registry_start(args):
    """Start the local registry server."""
    import subprocess

    host = args.host or "0.0.0.0"
    port = args.port or 8000

    registry_script = ROOT / "registry" / "server.py"
    if not registry_script.exists():
        error_panel(
            f"Registry server not found at {registry_script}",
            "Verify the Oversight installation is complete."
        )
        sys.exit(1)

    info(f"Starting registry server on {host}:{port}")
    info(f"Server module: {registry_script}")
    console.print(Rule("Registry Server", style="cyan"))

    try:
        subprocess.run(
            [
                sys.executable, "-m", "uvicorn",
                "registry.server:app",
                "--host", host,
                "--port", str(port),
            ],
            cwd=str(ROOT),
        )
    except KeyboardInterrupt:
        info("Registry server stopped.")


# ---------------------------------------------------------------------------
# Argparse setup
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="oversight",
        description="Oversight Protocol CLI -- data provenance, attribution, and leak detection.",
    )
    p.add_argument("--no-banner", action="store_true", help="suppress startup banner")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("gui", help="launch the graphical desktop app")

    # init
    init_p = sub.add_parser("init", help="initialize .oversight/ directory")
    init_p.add_argument("--path", default=None, help="target directory (default: cwd)")
    init_p.add_argument("--registry-url", default=None, help="registry server URL")
    init_p.add_argument("--registry-domain", default=None, help="registry domain for beacons")
    init_p.add_argument("--force", action="store_true", help="overwrite existing config")

    # keys
    keys_p = sub.add_parser("keys", help="key management")
    keys_sub = keys_p.add_subparsers(dest="keys_cmd")

    kg = keys_sub.add_parser("generate", help="generate a new identity keypair")
    kg.add_argument("--name", default=None, help="identity name (default: identity)")
    kg.add_argument("--out", default=None, help="output file path")
    kg.add_argument("--force", action="store_true", help="overwrite existing identity")

    kl = keys_sub.add_parser("list", help="list identities and recipients")

    ki = keys_sub.add_parser("import", help="import a recipient public key")
    ki.add_argument("file", help="path to recipient .pub.json file")
    ki.add_argument("--force", action="store_true", help="overwrite existing recipient")

    # seal
    seal_p = sub.add_parser("seal", help="seal a file for a recipient")
    seal_p.add_argument("input", help="input file to seal")
    seal_p.add_argument("--to", default=None, help="recipient public key file or name")
    seal_p.add_argument("--issuer-key", default=None, help="issuer private key file")
    seal_p.add_argument("--issuer-id", default=None, help="issuer identifier")
    seal_p.add_argument("--registry-url", default=None, help="registry URL")
    seal_p.add_argument("--registry-domain", default=None, help="registry domain for beacons")
    seal_p.add_argument("--out", default=None, help="output file (default: <input>.sealed)")
    seal_p.add_argument("--content-type", default=None, help="MIME content type")
    seal_p.add_argument("--watermark", default=None, action="store_true", help="embed watermarks (default from config)")
    seal_p.add_argument("--no-watermark", dest="watermark", action="store_false", help="skip watermarks")
    seal_p.add_argument("--l3-mode", choices=("auto", "off", "full", "boilerplate"), default="auto",
                        help="semantic L3 mode; auto disables L3 for wording-sensitive documents")
    seal_p.add_argument("--l3-ack", action="store_true",
                        help="acknowledge enabled L3 makes recipient text non-identical")
    seal_p.add_argument("--document-class",
                        choices=("auto", "prose", "legal", "regulatory", "technical_spec",
                                 "source_code", "sql", "log", "structured_data"),
                        default="auto",
                        help="declare document class for L3 safety decisions")
    seal_p.add_argument("--register", default=None, help="POST manifest to this registry URL")

    # open
    open_p = sub.add_parser("open", help="decrypt a sealed file")
    open_p.add_argument("input", help="sealed file to open")
    open_p.add_argument("--identity", default=None, help="recipient identity file")
    open_p.add_argument("--out", default=None, help="output file (default: strip .sealed)")

    # inspect
    inspect_p = sub.add_parser("inspect", help="show manifest without decrypting")
    inspect_p.add_argument("input", help="sealed file to inspect")
    inspect_p.add_argument("--json", action="store_true", help="also print raw JSON")

    # attribute
    attr_p = sub.add_parser("attribute", help="attribute a leaked file")
    attr_p.add_argument("leak", nargs="?", default=None, help="leaked text file")
    attr_p.add_argument("--leak", dest="leak_flag", default=None, help="leaked text file (alternative flag)")
    attr_p.add_argument("--registry", default=None, help="registry URL for lookups")
    attr_p.add_argument("--fingerprints", default=None, help="fingerprint file or directory")

    # status
    sub.add_parser("status", help="show config, identity, and registry health")

    # registry
    reg_p = sub.add_parser("registry", help="registry server management")
    reg_sub = reg_p.add_subparsers(dest="registry_cmd")
    rs = reg_sub.add_parser("start", help="start the local registry server")
    rs.add_argument("--host", default=None, help="bind host (default: 0.0.0.0)")
    rs.add_argument("--port", type=int, default=None, help="bind port (default: 8000)")

    return p


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    # Handle --no-banner before argparse so it works in any position
    show_banner = "--no-banner" not in sys.argv
    argv = [a for a in sys.argv[1:] if a != "--no-banner"]

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.cmd:
        if show_banner:
            print_banner()
        parser.print_help()
        sys.exit(0)

    if args.cmd == "gui":
        from cli.gui import main as gui_main
        gui_main()
        return

    if show_banner:
        print_banner()

    if args.cmd == "init":
        cmd_init(args)

    elif args.cmd == "keys":
        if not args.keys_cmd:
            err_console.print("[red]Specify a keys subcommand: generate, list, import[/]")
            sys.exit(1)
        if args.keys_cmd == "generate":
            cmd_keys_generate(args)
        elif args.keys_cmd == "list":
            cmd_keys_list(args)
        elif args.keys_cmd == "import":
            cmd_keys_import(args)

    elif args.cmd == "seal":
        cmd_seal(args)

    elif args.cmd == "open":
        cmd_open(args)

    elif args.cmd == "inspect":
        cmd_inspect(args)

    elif args.cmd == "attribute":
        # Support both positional and --leak flag
        leak_file = args.leak or args.leak_flag
        if not leak_file:
            error_panel(
                "No leak file specified.",
                "Usage: oversight attribute <leak-file> or oversight attribute --leak <file>"
            )
            sys.exit(1)
        args.leak = leak_file
        cmd_attribute(args)

    elif args.cmd == "status":
        cmd_status(args)

    elif args.cmd == "registry":
        if not args.registry_cmd:
            err_console.print("[red]Specify a registry subcommand: start[/]")
            sys.exit(1)
        if args.registry_cmd == "start":
            cmd_registry_start(args)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
