# SIEM integration

Oversight registries record every beacon callback (DNS, HTTP pixel, OCSP,
license check) in the local SQLite `events` table and append a signed entry
to the transparency log. Security teams running Splunk, Microsoft Sentinel,
or an Elastic Common Schema stack want that data in the same pipeline as
the rest of their telemetry. The `oversight_core.siem` module and the
`oversight siem export` CLI handle the formatting and the minimal transport
that gets events from the registry to the SIEM.

The module is pure Python and stdlib-only for the formatters. HTTP
transport reuses the `httpx` client already in the dependency set. No SIEM
vendor SDK is required, and no vendor-specific credential lives in the
Oversight process unless the operator configures one.

## Event shape

One normalized record per row of the `events` table. The registry
identifier is typically the registry's own Ed25519 public key hex so
federated operators are distinguishable in SIEM dashboards.

| Field                 | Source column            |
|-----------------------|--------------------------|
| `event_id`            | `events.id`              |
| `event_kind`          | `events.kind` (`dns`, `http_img`, `ocsp`, `license`) |
| `occurred_unix`       | `events.timestamp`       |
| `occurred_at`         | derived RFC 3339 UTC     |
| `registry_id`         | caller-supplied          |
| `token_id`            | `events.token_id`        |
| `file_id`             | `events.file_id`         |
| `recipient_id`        | `events.recipient_id`    |
| `issuer_id`           | `events.issuer_id`       |
| `source_ip`           | `events.source_ip`       |
| `user_agent`          | `events.user_agent`      |
| `qualified_timestamp` | `events.qualified_timestamp` (RFC 3161) |
| `tlog_index`          | `events.tlog_index`      |
| `extra`               | `events.extra` (JSON)    |

## CLI

```
oversight siem export \
  --db /var/lib/oversight/registry.sqlite \
  --format splunk|ecs|sentinel \
  --registry-id <ed25519_pub hex or short id> \
  [--since <unix_ts>] \
  [--limit N] \
  [--output -|/path/to/file.jsonl|https://collector.example/endpoint] \
  [--header 'Authorization: Splunk <hec-token>']
```

The default output is `-` (stdout, JSON lines). Forwarders like the Splunk
Universal Forwarder, Azure Monitor Agent, or Filebeat can tail the file
output directly; no Oversight-side credential is required. When the
`--output` is an HTTP URL, the CLI POSTs a JSON array and fails loudly on
non-2xx so a backoff wrapper can retry.

### Splunk HTTP Event Collector

Deploy the events over HEC:

```
oversight siem export --db registry.sqlite --registry-id $REG \
  --format splunk \
  --output https://splunk.example:8088/services/collector/event \
  --header 'Authorization: Splunk 00000000-0000-0000-0000-000000000000'
```

`source` and `sourcetype` default to `oversight:registry` and
`oversight:beacon`. Override with `--splunk-source`, `--splunk-sourcetype`,
and `--splunk-index` to match your deployment's field extraction.

### Microsoft Sentinel (Log Analytics Data Collector API)

The Data Collector API requires an HMAC-SHA256 `Authorization` header.
`oversight_core.siem.sentinel_authorization` computes it; the CLI does not
yet sign requests on your behalf because the signing window depends on the
RFC 1123 `x-ms-date` header, which must match the body length exactly.
For production, write the records to a file and have Azure Monitor Agent
pick them up, or wrap the signing in a small adapter:

```python
from oversight_core.siem import (
    iter_registry_events, export_events, HTTPJSONSink, sentinel_authorization,
)
from datetime import datetime, timezone
import json

events = list(iter_registry_events("registry.sqlite", registry_id=REG))
# Pre-format so we know the content length.
batch = [e for e in events]  # ... format via to_sentinel
body = json.dumps([...]).encode("utf-8")
date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
auth = sentinel_authorization(
    workspace_id=WORKSPACE_ID,
    shared_key_b64=SHARED_KEY,
    content_length=len(body),
    date_rfc1123=date,
)
sink = HTTPJSONSink(
    f"https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
    headers={
        "Authorization": auth,
        "Log-Type": "Oversight",
        "x-ms-date": date,
        "time-generated-field": "TimeGenerated",
    },
)
```

The KQL-friendly custom log name is `Oversight_CL` after Sentinel ingests
the first batch. Each beacon kind surfaces as a value of the `BeaconKind`
column, so a single `Oversight_CL | where BeaconKind == "dns"` query pulls
every DNS callback. Joins against your existing identity tables key off
`RecipientId` or `IssuerId`.

### Elastic Common Schema

ECS 8.x-compatible records are ready to index into Elasticsearch or ship
through Filebeat. The schema sets `event.module = "oversight"` and
`event.dataset = "oversight.beacon"` so the Elastic Security app renders
the events without extra mapping work.

```
oversight siem export --db registry.sqlite --registry-id $REG \
  --format ecs \
  --output /var/log/oversight/events.ndjson
```

Point Filebeat at the file with the `ndjson` parser and a `fields_under_root: true`
processor that promotes the embedded `@timestamp`. The custom namespace at
`oversight.*` preserves the protocol-native fields for runtime fields or
Lens visualizations.

## Honest limits

Absence of a beacon is not evidence of no leak. Corporate egress filtering,
air-gapped readers, and sandboxed previews suppress beacon callbacks.
Oversight records what it sees; SIEM alerting on the absence of beacons
needs a baseline and an explicit policy, not just the event stream.
`docs/security.md` and the research threat model cover the details.

## Fields you may want to rename on your side

- `token_id` is the public beacon token, not an authentication token; renaming
  to `beacon_token` in your dashboards avoids confusion with OAuth scopes.
- `file_id` is the Oversight-internal content identifier, not a hash. Map to
  your DLP system's `document_id` or equivalent.
- `recipient_id` and `issuer_id` map to whatever identity scheme the Oversight
  deployment uses (email, SSO subject, Ed25519 fingerprint).
