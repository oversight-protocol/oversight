"""SIEM export formatters for Oversight registry events.

Oversight records beacon callbacks (DNS, HTTP pixel, OCSP, license) in the
registry's ``events`` table. Security teams need those events in whichever
incident pipeline they already run: Splunk, Microsoft Sentinel, or an
Elastic stack following the Elastic Common Schema. This module provides
schema-stable formatters for each of the three, a normalized event model,
and minimal file/HTTP sinks so operators can stream live or stage to a
forwarder.

Formatters are pure. They do not perform network I/O and they do not
access the database. Transport lives in the sink classes and is
optional. The default workflow is to emit JSON lines and let an existing
site forwarder (Splunk Universal Forwarder, Azure Monitor Agent,
Filebeat) deliver them, so Oversight does not need to carry SIEM
credentials in the default deployment.

Event semantics match the registry ``events`` table exactly. See
``docs/SIEM.md`` for the field dictionary, the Sentinel HMAC signing
recipe, and example Splunk / Elastic dashboards.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Mapping, Optional


ECS_VERSION = "8.11.0"
SCHEMA_VERSION = "oversight-siem-1"

BEACON_KINDS = {"dns", "http_img", "ocsp", "license"}
ACTION_BY_KIND = {
    "dns": "beacon-dns-callback",
    "http_img": "beacon-http-pixel",
    "ocsp": "beacon-ocsp-callback",
    "license": "beacon-license-check",
}


def iso8601(unix_ts: int | float) -> str:
    """RFC 3339 UTC timestamp to second precision, suitable for ECS ``@timestamp``."""
    return datetime.fromtimestamp(float(unix_ts), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


@dataclass
class OversightEvent:
    """Normalized Oversight event, one row of the registry ``events`` table.

    ``registry_id`` is the registry's ed25519 public key hex (or a short
    fingerprint thereof), not an operator-chosen hostname. SIEM consumers
    use it to tell federated registries apart.
    """

    event_id: str
    event_kind: str
    occurred_unix: int
    occurred_at: str
    registry_id: str
    token_id: Optional[str] = None
    file_id: Optional[str] = None
    recipient_id: Optional[str] = None
    issuer_id: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    qualified_timestamp: Optional[str] = None
    tlog_index: Optional[int] = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def from_registry_row(
    row: Mapping[str, Any] | sqlite3.Row,
    *,
    registry_id: str,
) -> OversightEvent:
    """Map a ``SELECT * FROM events`` row into an :class:`OversightEvent`."""
    if isinstance(row, sqlite3.Row):
        d = {k: row[k] for k in row.keys()}
    else:
        d = dict(row)

    extra_raw = d.get("extra") or ""
    try:
        extra = json.loads(extra_raw) if extra_raw else {}
    except (TypeError, json.JSONDecodeError):
        extra = {"raw": extra_raw}

    occurred_unix = int(d.get("timestamp") or 0)
    return OversightEvent(
        event_id=str(d.get("id", "")),
        event_kind=str(d.get("kind") or ""),
        occurred_unix=occurred_unix,
        occurred_at=iso8601(occurred_unix) if occurred_unix else "",
        registry_id=registry_id,
        token_id=d.get("token_id"),
        file_id=d.get("file_id"),
        recipient_id=d.get("recipient_id"),
        issuer_id=d.get("issuer_id"),
        source_ip=d.get("source_ip"),
        user_agent=d.get("user_agent") or None,
        qualified_timestamp=d.get("qualified_timestamp"),
        tlog_index=d.get("tlog_index") if d.get("tlog_index") is not None else None,
        extra=extra if isinstance(extra, dict) else {"raw": extra},
    )


def _clean(d: dict) -> dict:
    """Drop keys whose values are ``None`` or empty string."""
    return {k: v for k, v in d.items() if v not in (None, "")}


def to_splunk_hec(
    evt: OversightEvent,
    *,
    source: str = "oversight:registry",
    sourcetype: str = "oversight:beacon",
    index: Optional[str] = None,
    host: Optional[str] = None,
) -> dict:
    """Format an event as a Splunk HTTP Event Collector envelope.

    Posted one-per-line (JSONL) or one-per-request against
    ``/services/collector/event``. ``time`` is epoch seconds as a float,
    which Splunk accepts natively.
    """
    envelope: dict = {
        "time": float(evt.occurred_unix),
        "host": host or evt.registry_id,
        "source": source,
        "sourcetype": sourcetype,
        "event": _clean({
            "schema": SCHEMA_VERSION,
            "kind": evt.event_kind,
            "action": ACTION_BY_KIND.get(evt.event_kind, f"beacon-{evt.event_kind}"),
            "event_id": evt.event_id,
            "occurred_at": evt.occurred_at,
            "token_id": evt.token_id,
            "file_id": evt.file_id,
            "recipient_id": evt.recipient_id,
            "issuer_id": evt.issuer_id,
            "source_ip": evt.source_ip,
            "user_agent": evt.user_agent,
            "qualified_timestamp": evt.qualified_timestamp,
            "tlog_index": evt.tlog_index,
            "registry_id": evt.registry_id,
            "extra": evt.extra or None,
        }),
        "fields": _clean({
            "file_id": evt.file_id,
            "recipient_id": evt.recipient_id,
            "issuer_id": evt.issuer_id,
            "beacon_kind": evt.event_kind,
        }),
    }
    if index:
        envelope["index"] = index
    return envelope


def to_ecs(evt: OversightEvent) -> dict:
    """Format an event as Elastic Common Schema 8.x.

    The custom ``oversight.*`` namespace carries protocol-native fields
    that do not have a canonical ECS home. ECS reserves top-level
    ``event.*``, ``source.*``, ``user_agent.*``, and ``labels.*`` for
    the common cases so dashboards built on the Elastic Security app
    light up without extra mapping work.
    """
    ecs_event = _clean({
        "@timestamp": evt.occurred_at,
        "ecs": {"version": ECS_VERSION},
        "event": _clean({
            "kind": "event",
            "category": ["network"],
            "type": ["access", "info"],
            "dataset": "oversight.beacon",
            "module": "oversight",
            "provider": "oversight-registry",
            "action": ACTION_BY_KIND.get(evt.event_kind, f"beacon-{evt.event_kind}"),
            "id": evt.event_id,
            "outcome": "success",
        }),
        "source": _clean({"ip": evt.source_ip}) or None,
        "user_agent": _clean({"original": evt.user_agent}) or None,
        "labels": _clean({
            "oversight_token_id": evt.token_id,
            "oversight_file_id": evt.file_id,
            "oversight_recipient_id": evt.recipient_id,
            "oversight_issuer_id": evt.issuer_id,
            "oversight_beacon_kind": evt.event_kind,
        }),
        "oversight": _clean({
            "schema": SCHEMA_VERSION,
            "registry_id": evt.registry_id,
            "token_id": evt.token_id,
            "file_id": evt.file_id,
            "recipient_id": evt.recipient_id,
            "issuer_id": evt.issuer_id,
            "beacon_kind": evt.event_kind,
            "tlog_index": evt.tlog_index,
            "qualified_timestamp": evt.qualified_timestamp,
            "extra": evt.extra or None,
        }),
    })
    return ecs_event


def to_sentinel(evt: OversightEvent) -> dict:
    """Format an event for Microsoft Sentinel's Log Analytics custom logs.

    Sentinel's Data Collector API accepts flat JSON objects. Nested
    structures are allowed but become dynamic columns that are harder
    to KQL against, so the flat shape is the operator-friendly default.
    """
    return _clean({
        "TimeGenerated": evt.occurred_at,
        "Schema": SCHEMA_VERSION,
        "RegistryId": evt.registry_id,
        "EventId": evt.event_id,
        "BeaconKind": evt.event_kind,
        "Action": ACTION_BY_KIND.get(evt.event_kind, f"beacon-{evt.event_kind}"),
        "TokenId": evt.token_id,
        "FileId": evt.file_id,
        "RecipientId": evt.recipient_id,
        "IssuerId": evt.issuer_id,
        "SourceIp": evt.source_ip,
        "UserAgent": evt.user_agent,
        "QualifiedTimestamp": evt.qualified_timestamp,
        "TlogIndex": evt.tlog_index,
        "ExtraJson": json.dumps(evt.extra, separators=(",", ":")) if evt.extra else None,
    })


FORMATTERS = {
    "splunk": to_splunk_hec,
    "ecs": to_ecs,
    "sentinel": to_sentinel,
}


def format_event(evt: OversightEvent, fmt: str, **kwargs) -> dict:
    if fmt not in FORMATTERS:
        raise ValueError(f"unknown SIEM format: {fmt!r} (choices: {sorted(FORMATTERS)})")
    return FORMATTERS[fmt](evt, **kwargs) if fmt == "splunk" else FORMATTERS[fmt](evt)


# ---- Microsoft Sentinel HMAC signing ----------------------------------------


def sentinel_authorization(
    *,
    workspace_id: str,
    shared_key_b64: str,
    content_length: int,
    date_rfc1123: str,
    method: str = "POST",
    content_type: str = "application/json",
    resource: str = "/api/logs",
) -> str:
    """Build the ``Authorization`` header for the Sentinel Data Collector API.

    The signing recipe follows Microsoft's current documentation for the
    Log Analytics HTTP Data Collector API. Callers supply an RFC 1123
    ``x-ms-date`` value and Content-Length; this helper hashes the
    canonical string and returns ``SharedKey {workspace_id}:{base64_hmac}``
    ready to drop into ``Authorization``.
    """
    string_to_hash = (
        f"{method}\n{content_length}\n{content_type}\nx-ms-date:{date_rfc1123}\n{resource}"
    )
    decoded_key = base64.b64decode(shared_key_b64)
    digest = hmac.new(
        decoded_key, string_to_hash.encode("utf-8"), hashlib.sha256
    ).digest()
    encoded_hash = base64.b64encode(digest).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"


# ---- Sinks -------------------------------------------------------------------


class Sink:
    """Interface: ``send(records: Iterable[dict]) -> int`` returns emitted count."""

    def send(self, records: Iterable[dict]) -> int:  # pragma: no cover - abstract
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - default no-op
        pass


class FileSink(Sink):
    """Append JSON lines to a file. Safe for log-rotation forwarders."""

    def __init__(self, path: str, *, mode: str = "a"):
        if mode not in ("a", "w"):
            raise ValueError("FileSink mode must be 'a' or 'w'")
        self.path = path
        self._fh = open(path, mode, encoding="utf-8")

    def send(self, records: Iterable[dict]) -> int:
        n = 0
        for rec in records:
            self._fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            n += 1
        self._fh.flush()
        return n

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


class StdoutSink(Sink):
    """JSON lines to stdout. Useful for piping into a forwarder."""

    def __init__(self):
        import sys
        self._out = sys.stdout

    def send(self, records: Iterable[dict]) -> int:
        n = 0
        for rec in records:
            self._out.write(json.dumps(rec, separators=(",", ":")) + "\n")
            n += 1
        self._out.flush()
        return n


class HTTPJSONSink(Sink):
    """POST records as a JSON array to a generic HTTP endpoint.

    Covers Splunk HEC (``Authorization: Splunk <token>``), Elastic
    ``_bulk`` when callers pre-format the payload, and any in-house
    HTTP collector. This sink does not retry; callers retry.
    """

    def __init__(
        self,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        timeout: float = 10.0,
        verify: bool = True,
    ):
        import httpx
        self._client = httpx.Client(timeout=timeout, verify=verify)
        self.url = url
        self._headers = dict(headers or {})

    def send(self, records: Iterable[dict]) -> int:
        batch = list(records)
        if not batch:
            return 0
        resp = self._client.post(self.url, json=batch, headers=self._headers)
        resp.raise_for_status()
        return len(batch)

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass


# ---- DB iteration ------------------------------------------------------------


def iter_registry_events(
    db_path: str,
    *,
    since_unix: Optional[int] = None,
    limit: Optional[int] = None,
    registry_id: str,
) -> Iterator[OversightEvent]:
    """Yield :class:`OversightEvent` records from a registry SQLite database.

    Read-only; opens the DB with ``PRAGMA query_only=ON`` so an operator
    can safely run this against a live registry. The caller is responsible
    for passing the registry's own public identifier (typically
    ``IDENTITY['ed25519_pub']``).
    """
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA query_only=ON")
        sql = "SELECT * FROM events"
        params: list = []
        if since_unix is not None:
            sql += " WHERE timestamp >= ?"
            params.append(int(since_unix))
        sql += " ORDER BY timestamp ASC, id ASC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        for row in con.execute(sql, params):
            yield from_registry_row(row, registry_id=registry_id)
    finally:
        con.close()


def export_events(
    *,
    events: Iterable[OversightEvent],
    fmt: str,
    sink: Sink,
    splunk_kwargs: Optional[dict] = None,
) -> int:
    """Format and push events through a sink. Returns emitted count."""
    if fmt not in FORMATTERS:
        raise ValueError(f"unknown SIEM format: {fmt!r}")
    splunk_kwargs = splunk_kwargs or {}
    def _gen():
        for evt in events:
            if fmt == "splunk":
                yield to_splunk_hec(evt, **splunk_kwargs)
            else:
                yield FORMATTERS[fmt](evt)
    return sink.send(_gen())
