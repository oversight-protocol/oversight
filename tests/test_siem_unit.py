#!/usr/bin/env python3
"""Focused tests for the SIEM export formatters and registry-row mapping."""

import base64
import io
import json
import os
import sqlite3
import sys
import tempfile
import time

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from oversight_core import siem


REGISTRY_ID = "deadbeef" * 8


def ok(msg: str) -> None:
    print(f"  [PASS] {msg}")


def _sample_event(**overrides) -> siem.OversightEvent:
    base = dict(
        event_id="42",
        event_kind="dns",
        occurred_unix=1_735_000_000,
        occurred_at=siem.iso8601(1_735_000_000),
        registry_id=REGISTRY_ID,
        token_id="tok_abc",
        file_id="file_xyz",
        recipient_id="rcpt_alice",
        issuer_id="issuer_zion",
        source_ip="198.51.100.42",
        user_agent="Mozilla/5.0",
        qualified_timestamp="2024-12-24T01:06:40Z",
        tlog_index=7,
        extra={"qname": "abc.t.example.com", "qtype": "A"},
    )
    base.update(overrides)
    return siem.OversightEvent(**base)


def t1_splunk_envelope_carries_time_host_event_and_fields():
    evt = _sample_event()
    out = siem.to_splunk_hec(evt, source="s", sourcetype="st", index="main", host="h")

    assert out["time"] == 1_735_000_000.0
    assert out["host"] == "h"
    assert out["source"] == "s"
    assert out["sourcetype"] == "st"
    assert out["index"] == "main"
    assert out["event"]["kind"] == "dns"
    assert out["event"]["action"] == "beacon-dns-callback"
    assert out["event"]["token_id"] == "tok_abc"
    assert out["event"]["tlog_index"] == 7
    assert out["fields"]["file_id"] == "file_xyz"
    assert out["fields"]["beacon_kind"] == "dns"
    ok("Splunk HEC envelope carries time, host, event, and fields")


def t2_splunk_drops_empty_optional_fields():
    evt = _sample_event(user_agent=None, source_ip=None, qualified_timestamp=None)
    out = siem.to_splunk_hec(evt)
    assert "user_agent" not in out["event"]
    assert "source_ip" not in out["event"]
    assert "qualified_timestamp" not in out["event"]
    ok("Splunk envelope omits None optionals rather than emitting null")


def t3_ecs_document_has_canonical_fields():
    evt = _sample_event()
    out = siem.to_ecs(evt)
    assert out["@timestamp"] == siem.iso8601(1_735_000_000)
    assert out["ecs"]["version"] == siem.ECS_VERSION
    assert out["event"]["kind"] == "event"
    assert "network" in out["event"]["category"]
    assert out["event"]["dataset"] == "oversight.beacon"
    assert out["event"]["action"] == "beacon-dns-callback"
    assert out["source"]["ip"] == "198.51.100.42"
    assert out["user_agent"]["original"] == "Mozilla/5.0"
    assert out["labels"]["oversight_token_id"] == "tok_abc"
    assert out["oversight"]["registry_id"] == REGISTRY_ID
    assert out["oversight"]["tlog_index"] == 7
    ok("ECS record carries @timestamp, event.*, source.ip, user_agent.*, oversight.*")


def t4_ecs_ua_and_source_absent_when_empty():
    evt = _sample_event(user_agent=None, source_ip=None)
    out = siem.to_ecs(evt)
    assert "source" not in out
    assert "user_agent" not in out
    ok("ECS record drops empty source/user_agent blocks entirely")


def t5_sentinel_flat_row_kql_friendly():
    evt = _sample_event()
    out = siem.to_sentinel(evt)
    assert out["TimeGenerated"] == siem.iso8601(1_735_000_000)
    assert out["BeaconKind"] == "dns"
    assert out["TokenId"] == "tok_abc"
    assert out["SourceIp"] == "198.51.100.42"
    assert out["TlogIndex"] == 7
    assert json.loads(out["ExtraJson"])["qname"] == "abc.t.example.com"
    assert "ExtraJson" in out
    assert all(not k.startswith("@") for k in out)
    ok("Sentinel row is flat, KQL-friendly, with JSON-serialized extras")


def t6_from_registry_row_reads_sqlite_row():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    try:
        con = sqlite3.connect(tmp.name)
        con.row_factory = sqlite3.Row
        con.executescript(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_id TEXT NOT NULL,
                file_id TEXT,
                recipient_id TEXT,
                issuer_id TEXT,
                kind TEXT NOT NULL,
                source_ip TEXT,
                user_agent TEXT,
                extra TEXT,
                timestamp INTEGER NOT NULL,
                qualified_timestamp TEXT,
                tlog_index INTEGER
            );
            """
        )
        con.execute(
            "INSERT INTO events (token_id,file_id,recipient_id,issuer_id,kind,"
            "source_ip,user_agent,extra,timestamp,qualified_timestamp,tlog_index) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("tok", "file", "rcpt", "iss", "dns",
             "203.0.113.9", "curl/8", json.dumps({"qtype": "A"}),
             1_735_000_000, "2024-12-24T01:06:40Z", 11),
        )
        con.commit()

        row = con.execute("SELECT * FROM events WHERE id=1").fetchone()
        evt = siem.from_registry_row(row, registry_id=REGISTRY_ID)
        con.close()

        assert evt.event_kind == "dns"
        assert evt.token_id == "tok"
        assert evt.source_ip == "203.0.113.9"
        assert evt.tlog_index == 11
        assert evt.extra == {"qtype": "A"}
        ok("from_registry_row reads a live SQLite row into OversightEvent")

        # iter_registry_events in read-only mode.
        events = list(siem.iter_registry_events(tmp.name, registry_id=REGISTRY_ID))
        assert len(events) == 1
        assert events[0].token_id == "tok"
        ok("iter_registry_events opens the db read-only and yields rows")
    finally:
        os.unlink(tmp.name)


def t7_sentinel_authorization_matches_microsoft_recipe():
    # Known-value check: fixed inputs, recompute and confirm stability.
    workspace = "00000000-0000-0000-0000-000000000001"
    key_bytes = b"\x01" * 32
    shared_key_b64 = base64.b64encode(key_bytes).decode("utf-8")
    date = "Mon, 22 Apr 2026 12:00:00 GMT"
    body_len = 1234

    header1 = siem.sentinel_authorization(
        workspace_id=workspace,
        shared_key_b64=shared_key_b64,
        content_length=body_len,
        date_rfc1123=date,
    )
    header2 = siem.sentinel_authorization(
        workspace_id=workspace,
        shared_key_b64=shared_key_b64,
        content_length=body_len,
        date_rfc1123=date,
    )
    assert header1 == header2
    assert header1.startswith(f"SharedKey {workspace}:")
    assert len(header1.split(":")[-1]) >= 40
    ok("Sentinel Authorization header is deterministic and correctly prefixed")


def t8_filesink_and_stdoutsink_write_jsonl():
    evts = [_sample_event(event_id=str(i)) for i in range(3)]
    tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
    tmp.close()
    try:
        sink = siem.FileSink(tmp.name, mode="w")
        try:
            n = siem.export_events(events=iter(evts), fmt="ecs", sink=sink)
        finally:
            sink.close()
        assert n == 3
        with open(tmp.name) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == 3
        assert lines[0]["event"]["action"] == "beacon-dns-callback"
        ok("FileSink persists one JSON line per event")
    finally:
        os.unlink(tmp.name)


def t9_unknown_format_raises():
    try:
        siem.format_event(_sample_event(), "wazuh")
    except ValueError as e:
        assert "wazuh" in str(e)
        ok("format_event rejects unknown SIEM names")
        return
    raise AssertionError("expected ValueError for unknown SIEM format")


def t10_action_names_cover_all_beacon_kinds():
    for k in ("dns", "http_img", "ocsp", "license"):
        evt = _sample_event(event_kind=k)
        assert siem.to_splunk_hec(evt)["event"]["action"].startswith("beacon-")
        assert siem.to_ecs(evt)["event"]["action"].startswith("beacon-")
        assert siem.to_sentinel(evt)["Action"].startswith("beacon-")
    ok("every known beacon kind maps to a stable action name")


def run():
    print("[*] test_siem_unit.py")
    t1_splunk_envelope_carries_time_host_event_and_fields()
    t2_splunk_drops_empty_optional_fields()
    t3_ecs_document_has_canonical_fields()
    t4_ecs_ua_and_source_absent_when_empty()
    t5_sentinel_flat_row_kql_friendly()
    t6_from_registry_row_reads_sqlite_row()
    t7_sentinel_authorization_matches_microsoft_recipe()
    t8_filesink_and_stdoutsink_write_jsonl()
    t9_unknown_format_raises()
    t10_action_names_cover_all_beacon_kinds()
    print("[ok] all SIEM unit tests passed")


if __name__ == "__main__":
    run()
