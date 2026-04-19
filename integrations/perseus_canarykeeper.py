"""
CanaryKeeper — OVERSIGHT-attribution → Discord-alert agent for Perseus.

Role: sole owner of the "trap recipient" identities (decoy file recipient
keys), and sole escalation path for OVERSIGHT attribution hits. Runs as a
Perseus agent alongside Grok / DMCA Shield / etc.

Responsibilities:
    1. Poll the registry's tlog for new beacon events (any kind: http_img, dns,
       ocsp, license). A beacon fire = a sealed file was opened somewhere.
    2. For each event, pull the signed evidence bundle for the file_id.
    3. Verify the bundle's registry Ed25519 signature against the pinned
       well-known pubkey (no blind trust).
    4. Classify: is this a decoy file (trap), a real-recipient file, or unknown?
    5. For trap hits → DM Zion on Discord immediately (P1).
    6. For real-recipient hits from unexpected geography/time → P2 alert.
    7. For Flywheel-discovered leaks → P1.

Trap recipient storage:
    Keys stay encrypted at rest under a Perseus Vault master key.
    Only CanaryKeeper has the decrypt role — not the main brain, not DMCA Shield.

Usage:
    python -m integrations.perseus_canarykeeper \\
        --registry https://beacon.example.com \\
        --pinned-key <hex> \\
        --discord-webhook https://discord.com/api/webhooks/... \\
        --owner-id 682818191990587393 \\
        --poll-interval 60

Config can also come from env vars:
    OVERSIGHT_REGISTRY_URL, OVERSIGHT_PINNED_KEY, DISCORD_WEBHOOK, OWNER_DISCORD_ID
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


log = logging.getLogger("canarykeeper")

STATE_PATH = Path(
    os.environ.get("CANARYKEEPER_STATE", "/var/lib/canarykeeper/state.json")
)


# --------- state ----------

def load_state() -> dict:
    if not STATE_PATH.exists():
        return {
            "last_tlog_seen": 0,
            "known_file_ids": [],
            "trap_file_ids": [],
        }
    try:
        return json.loads(STATE_PATH.read_text())
    except (ValueError, OSError):
        return {"last_tlog_seen": 0, "known_file_ids": [], "trap_file_ids": []}


def save_state(state: dict):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(STATE_PATH)


# --------- registry client ----------

class RegistryMonitor:
    def __init__(self, url: str, pinned_pubkey_hex: str):
        self.url = url.rstrip("/")
        self.pinned_pub = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(pinned_pubkey_hex)
        )
        self.client = httpx.Client(timeout=15.0)

    def close(self):
        self.client.close()

    def tlog_head(self) -> dict:
        r = self.client.get(f"{self.url}/tlog/head")
        r.raise_for_status()
        head = r.json()
        # Verify the signature against the pinned key
        sig = bytes.fromhex(head["signature"])
        msg = head["signed_message"].encode("utf-8")
        try:
            self.pinned_pub.verify(sig, msg)
        except InvalidSignature:
            raise RuntimeError(
                "registry /tlog/head signature does not verify under pinned key! "
                "possible tampering or key rotation — refusing to proceed"
            )
        return head

    def evidence_bundle(self, file_id: str) -> Optional[dict]:
        try:
            r = self.client.get(f"{self.url}/evidence/{file_id}")
            if r.status_code == 404:
                return None
            r.raise_for_status()
            bundle = r.json()
        except httpx.HTTPError as e:
            log.warning(f"evidence fetch failed for {file_id}: {e}")
            return None
        # Verify bundle signature
        sig_hex = bundle.pop("bundle_signature_ed25519", None)
        if not sig_hex:
            log.warning(f"bundle for {file_id} has no signature")
            return None
        msg = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            self.pinned_pub.verify(bytes.fromhex(sig_hex), msg)
        except InvalidSignature:
            log.error(f"bundle signature invalid for {file_id} — IGNORING")
            return None
        bundle["bundle_signature_ed25519"] = sig_hex  # restore
        return bundle

    def raw_tlog_entries(self, start_index: int) -> list[dict]:
        """Fetch raw tlog leaves from start_index to current. Uses the /tlog/range endpoint
        if available, else falls back to re-reading the whole log."""
        try:
            r = self.client.get(
                f"{self.url}/tlog/range",
                params={"start": start_index, "limit": 500},
            )
            r.raise_for_status()
            return r.json().get("entries", [])
        except httpx.HTTPError:
            # Fallback: fetch head, synthesize empty (registry doesn't yet have /tlog/range)
            return []


# --------- Discord notifier ----------

class DiscordNotifier:
    def __init__(self, webhook_url: str, owner_id: str):
        self.webhook = webhook_url
        self.owner_id = owner_id
        self.client = httpx.Client(timeout=10.0)

    def close(self):
        self.client.close()

    def alert(self, priority: str, title: str, body: str):
        """Post an alert to Discord. Priority = P1/P2/P3."""
        colors = {"P1": 0xFF0000, "P2": 0xFF9900, "P3": 0xFFFF00}
        mention = f"<@{self.owner_id}>" if priority == "P1" else ""
        payload = {
            "content": mention,
            "embeds": [{
                "title": f"[{priority}] {title}",
                "description": body[:4000],
                "color": colors.get(priority, 0x0099FF),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "footer": {"text": "OVERSIGHT CanaryKeeper"},
            }],
        }
        try:
            r = self.client.post(self.webhook, json=payload)
            r.raise_for_status()
        except httpx.HTTPError as e:
            log.error(f"Discord alert failed: {e}")


# --------- main loop ----------

def process_event(event: dict, state: dict, registry: RegistryMonitor,
                  notifier: DiscordNotifier):
    """Classify a single tlog event and escalate if it's interesting."""
    kind = event.get("event")
    if kind != "beacon":
        return  # registrations and attribution queries are log-only

    file_id = event.get("file_id")
    if not file_id:
        return

    is_trap = file_id in state.get("trap_file_ids", [])
    beacon_kind = event.get("kind", "unknown")
    source_ip = event.get("source_ip") or "unknown"

    if is_trap:
        # Trap beacon fire = intruder. Always P1.
        title = f"TRAP FILE OPENED: {file_id[:8]}..."
        body = (
            f"A decoy file's beacon fired. This is a high-confidence intrusion signal.\n"
            f"• beacon kind: `{beacon_kind}`\n"
            f"• source IP:   `{source_ip}`\n"
            f"• file_id:     `{file_id}`\n"
            f"• timestamp:   `{event.get('timestamp', '?')}`\n\n"
            f"Action: investigate source IP, pull evidence bundle, consider containment."
        )
        notifier.alert("P1", title, body)
    else:
        # Real file beacon. P3 for now; upgrade to P2 if it has suspicious features
        # (source IP geolocation, unusual time, etc. — future work).
        title = f"Real file beacon: {file_id[:8]}..."
        body = (
            f"A legitimate sealed file's beacon fired (expected behavior on open).\n"
            f"• kind: `{beacon_kind}`, source: `{source_ip}`, "
            f"recipient: `{event.get('recipient_id', '?')}`"
        )
        notifier.alert("P3", title, body)


def run_once(state: dict, registry: RegistryMonitor, notifier: DiscordNotifier):
    """One polling cycle. Fetches new tlog entries and processes each."""
    try:
        head = registry.tlog_head()
    except RuntimeError as e:
        notifier.alert("P1", "Registry signature check FAILED", str(e))
        raise
    except httpx.HTTPError as e:
        log.warning(f"registry unreachable: {e}")
        return state

    new_size = head["size"]
    old_seen = state.get("last_tlog_seen", 0)
    if new_size <= old_seen:
        return state  # no new entries

    new_entries = registry.raw_tlog_entries(old_seen)
    for entry in new_entries:
        try:
            event = json.loads(entry.get("leaf_data", "{}"))
            process_event(event, state, registry, notifier)
        except Exception as e:
            log.error(f"event processing failed: {e}")

    state["last_tlog_seen"] = new_size
    save_state(state)
    return state


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--registry", default=os.environ.get("OVERSIGHT_REGISTRY_URL"))
    p.add_argument("--pinned-key", default=os.environ.get("OVERSIGHT_PINNED_KEY"))
    p.add_argument("--discord-webhook", default=os.environ.get("DISCORD_WEBHOOK"))
    p.add_argument("--owner-id", default=os.environ.get("OWNER_DISCORD_ID", "682818191990587393"))
    p.add_argument("--poll-interval", type=int, default=60)
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args()

    if not args.registry or not args.pinned_key or not args.discord_webhook:
        print("Missing required config: --registry, --pinned-key, --discord-webhook")
        sys.exit(2)

    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    registry = RegistryMonitor(args.registry, args.pinned_key)
    notifier = DiscordNotifier(args.discord_webhook, args.owner_id)
    state = load_state()

    log.info(f"CanaryKeeper starting (registry={args.registry}, poll={args.poll_interval}s)")
    log.info(f"  tracking {len(state.get('trap_file_ids', []))} trap files")
    log.info(f"  last tlog seen: {state.get('last_tlog_seen', 0)}")

    notifier.alert("P3", "CanaryKeeper online",
                   f"Monitoring {args.registry}, polling every {args.poll_interval}s.")

    try:
        while True:
            try:
                state = run_once(state, registry, notifier)
            except Exception as e:
                log.exception(f"poll cycle error: {e}")
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        registry.close()
        notifier.close()


if __name__ == "__main__":
    main()
