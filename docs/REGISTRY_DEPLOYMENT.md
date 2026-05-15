# Registry Deployment

This is the public-safe live configuration for the reference Oversight
registry. It keeps secrets in `.env`, keeps the registry process off the public
host interface, and exposes TLS through Caddy. The Python FastAPI registry and
the Rust Axum registry both honor the write-side operator token described here.

## Layout

- `Dockerfile` builds the Python reference registry image.
- `docker-compose.yml` runs the registry on loopback and adds a `live` profile
  for Caddy.
- `Caddyfile` routes the registry, beacon, OCSP-style, and license-style
  hostnames to the registry container.
- `.env.example` lists every live setting without carrying secret values.

## First Run

```bash
cp .env.example .env
# Fill OVERSIGHT_DNS_EVENT_SECRET and OVERSIGHT_OPERATOR_TOKEN in .env.
# Use high-entropy random values; never commit .env.

docker compose up -d oversight-registry
curl http://127.0.0.1:8765/health
```

For public TLS, point DNS for the four configured hostnames at the host, then
start the live profile:

```bash
docker compose --profile live up -d
```

## Public Routes

`OVERSIGHT_REGISTRY_DOMAIN` serves the registry metadata, evidence, tlog, and
operator routes:

- `GET /health`
- `GET /.well-known/oversight-registry`
- `GET /evidence/{file_id}`
- `GET /tlog/head`
- `GET /tlog/proof/{index}`
- `GET /tlog/range`
- `GET /candidates/semantic`
- `POST /register`
- `POST /attribute`
- `POST /dns_event`

The beacon hostnames route only their beacon families:

- `OVERSIGHT_BEACON_DOMAIN`: `/p/{token}.png`
- `OVERSIGHT_OCSP_DOMAIN`: `/r/{token}` and `/ocsp/r/{token}`
- `OVERSIGHT_LICENSE_DOMAIN`: `/v/{token}` and `/lic/v/{token}`

Everything else returns `404`.

## Operator Authentication

If `OVERSIGHT_OPERATOR_TOKEN` is set, `POST /register` and `POST /attribute`
require either:

```http
Authorization: Bearer <token>
```

or:

```http
X-Oversight-Operator-Token: <token>
```

Leaving `OVERSIGHT_OPERATOR_TOKEN` empty keeps the v1 conformance harness and
local development behavior unchanged. Do not leave it empty on a public
operator deployment. Both reference registry implementations use the same
token contract, so live conformance commands work against either backend.

DNS bridge callbacks are separate. Set `OVERSIGHT_DNS_EVENT_SECRET`; the DNS
bridge must send either `Authorization: Bearer <secret>` or
`X-Oversight-DNS-Secret: <secret>` when posting `/dns_event`.

## Conformance

Local reference check:

```bash
python tests/test_registry_conformance.py
```

Live check against a token-protected registry:

```bash
OVERSIGHT_REGISTRY_URL=https://registry.example.org \
OVERSIGHT_OPERATOR_TOKEN=<token> \
python tests/test_registry_conformance.py
```

The token is read from the environment and sent as a bearer header. Do not put
real token values in shell history on shared machines.
