"""
OVERSIGHT attribution registry — v0.2 (security-hardened)

Upgrades over initial v0.2:
  - Registry identity private key written with 0600 permissions.
  - /register requires a valid Ed25519 signature from the issuer over the
    canonical manifest; INSERT OR REPLACE is only permitted when the new
    signature re-verifies for the SAME issuer pubkey already on file.
  - Rate limiter supports X-Forwarded-For when TRUSTED_PROXY env is set.
  - Rate limiter bounded with an LRU cap to prevent memory growth.
  - SQLite opens with journal_mode=WAL for concurrency.
  - FastAPI lifespan (not deprecated on_event).
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
import time
from collections import OrderedDict
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from oversight_core.tlog import TransparencyLog
from oversight_core.manifest import Manifest
from oversight_core import rekor as rekor_mod


DB_PATH = Path(os.environ.get("OVERSIGHT_DB", "/tmp/oversight-registry.sqlite"))
DATA_DIR = Path(os.environ.get("OVERSIGHT_DATA", "/tmp/oversight-data"))
TLOG_DIR = DATA_DIR / "tlog"
IDENTITY_PATH = DATA_DIR / "registry-identity.json"
TRUSTED_PROXY = bool(int(os.environ.get("TRUSTED_PROXY", "0")))
# When TRUSTED_PROXY=1, honor X-Forwarded-For for rate limiting.

# Rekor v2 wiring (v0.5 Session B). Off by default so existing tests do not
# generate live network traffic. Set OVERSIGHT_REKOR_ENABLED=1 to opt in.
# Failures are non-fatal: registry remains usable when Rekor is unreachable;
# the local SQLite tlog continues to be the authoritative event index.
REKOR_ENABLED = bool(int(os.environ.get("OVERSIGHT_REKOR_ENABLED", "0")))
REKOR_URL = os.environ.get("OVERSIGHT_REKOR_URL", rekor_mod.DEFAULT_REKOR_URL)


SCHEMA = """
CREATE TABLE IF NOT EXISTS beacons (
    token_id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    issuer_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    registered_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS watermarks (
    mark_id TEXT NOT NULL,
    layer TEXT NOT NULL,
    file_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    issuer_id TEXT NOT NULL,
    registered_at INTEGER NOT NULL,
    PRIMARY KEY (mark_id, layer)
);
CREATE TABLE IF NOT EXISTS manifests (
    file_id TEXT PRIMARY KEY,
    recipient_id TEXT NOT NULL,
    issuer_id TEXT NOT NULL,
    issuer_ed25519_pub TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    registered_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
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
CREATE TABLE IF NOT EXISTS corpus (
    file_id TEXT NOT NULL,
    hash_kind TEXT NOT NULL,
    hash_value TEXT NOT NULL,
    metadata TEXT,
    registered_at INTEGER NOT NULL,
    PRIMARY KEY (file_id, hash_kind, hash_value)
);
CREATE INDEX IF NOT EXISTS idx_events_token ON events(token_id);
CREATE INDEX IF NOT EXISTS idx_events_file ON events(file_id);
CREATE INDEX IF NOT EXISTS idx_corpus_hash ON corpus(hash_kind, hash_value);
"""


def load_or_create_identity() -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if IDENTITY_PATH.exists():
        return json.loads(IDENTITY_PATH.read_text())
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    ident = {
        "ed25519_priv": sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex(),
        "ed25519_pub": pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex(),
        "created_at": int(time.time()),
    }
    # Write private key file with 0600 permissions (owner-only read/write).
    fd = os.open(str(IDENTITY_PATH), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(ident, f, indent=2)
    return ident


IDENTITY: Optional[dict] = None
TLOG: Optional[TransparencyLog] = None


@contextmanager
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    # WAL for concurrent readers/writer. Safe to set every connection.
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db():
    with db() as con:
        con.executescript(SCHEMA)


def timestamp_stub() -> str:
    """Fallback: self-timestamp from registry clock when TSA is unreachable."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def qualified_timestamp_or_stub(data: bytes) -> tuple[str, Optional[dict]]:
    """
    Attempt a qualified RFC 3161 timestamp via the default TSA chain
    (FreeTSA, DigiCert — both free, no account). Falls back to a
    self-timestamp if all TSAs are unreachable.

    Returns (iso_string, qualified_details_dict_or_None).

    The registry persists the qualified_details dict (if present) in the
    events table so external auditors can independently verify the timestamp
    against the TSA's root cert, without trusting the registry operator.
    """
    try:
        from oversight_core.timestamp import qualified_timestamp
        ts = qualified_timestamp(data)
        if ts is not None:
            return ts.gen_time_iso, ts.to_dict()
    except ImportError:
        pass
    return timestamp_stub(), None


# ---- rate limiting with LRU bound ----

class TokenBucket:
    """Per-key token bucket with an LRU bound on state size."""

    def __init__(self, rate: float = 10.0, burst: int = 30, max_keys: int = 100_000):
        self.rate = rate
        self.burst = burst
        self.max_keys = max_keys
        self._state: "OrderedDict[str, tuple[float, float]]" = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if key in self._state:
                tokens, last = self._state.pop(key)
            else:
                tokens, last = (float(self.burst), now)
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1.0:
                self._state[key] = (tokens, now)
                self._evict_if_needed()
                return False
            self._state[key] = (tokens - 1.0, now)
            self._evict_if_needed()
            return True

    def _evict_if_needed(self):
        while len(self._state) > self.max_keys:
            self._state.popitem(last=False)


BUCKET = TokenBucket(rate=10.0, burst=30, max_keys=100_000)


def _client_key(request: Request) -> str:
    """Extract the client identifier used for rate limiting."""
    if TRUSTED_PROXY:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            # Last hop is the most recent proxy, first is the original client.
            # For rate limiting the original client IP is what we want.
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---- app + lifespan ----

@asynccontextmanager
async def lifespan(app: FastAPI):
    global IDENTITY, TLOG
    init_db()
    IDENTITY = load_or_create_identity()
    TLOG = TransparencyLog(TLOG_DIR, signing_key_hex=IDENTITY["ed25519_priv"])
    yield


app = FastAPI(title="OVERSIGHT Registry", version="0.2.1", lifespan=lifespan)


class RegistrationRequest(BaseModel):
    manifest: dict
    beacons: list[dict]
    watermarks: list[dict]
    corpus: Optional[dict] = None


class AttributionQuery(BaseModel):
    token_id: Optional[str] = None
    mark_id: Optional[str] = None
    layer: Optional[str] = None
    perceptual_hash: Optional[str] = None


def _append_tlog(event: dict) -> int:
    return TLOG.append(event) if TLOG else -1


def _attest_to_rekor(
    file_id: str,
    issuer_pub_hex: str,
    recipient_id: str,
    recipient_pubkey_hex: Optional[str],
    suite: str,
    content_hash_sha256_hex: str,
    mark_id_hex: str,
) -> Optional[dict]:
    """Sign a registration predicate with the registry's identity key and
    append it to a public Rekor v2 log.

    Returns a small JSON-serializable summary on success (log_url, log_index,
    log_id, integrated_time) so the response can carry it back to the client.
    Returns ``None`` when REKOR_ENABLED is false. Returns a dict with an
    ``error`` field (and no log_index) when the upload itself fails — the
    caller treats this as non-fatal.
    """
    if not REKOR_ENABLED or IDENTITY is None:
        return None
    try:
        recipient_hash = (
            rekor_mod.hash_recipient_pubkey(recipient_pubkey_hex)
            if recipient_pubkey_hex
            else "0" * 64
        )
        predicate = rekor_mod.OversightRegistrationPredicate(
            file_id=file_id,
            issuer_pubkey_ed25519=issuer_pub_hex,
            recipient_id=recipient_id,
            recipient_pubkey_sha256=recipient_hash,
            suite=suite,
            registered_at=timestamp_stub(),
        )
        statement = rekor_mod.build_statement(
            mark_id_hex=mark_id_hex,
            content_hash_sha256_hex=content_hash_sha256_hex,
            predicate=predicate,
        )
        envelope = rekor_mod.sign_dsse(
            statement=statement,
            issuer_ed25519_priv=bytes.fromhex(IDENTITY["ed25519_priv"]),
        )
        # Build a PEM for the registry's verifier key. Rekor v2 needs PEM.
        registry_pub = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(IDENTITY["ed25519_pub"])
        )
        pub_pem = registry_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        result = rekor_mod.upload_dsse(
            envelope=envelope,
            issuer_ed25519_pub_pem=pub_pem,
            log_url=REKOR_URL,
        )
        return {
            "log_url": result.log_url,
            "log_index": result.log_index,
            "log_id": result.log_id,
            "integrated_time": result.integrated_time,
            "tlog_kind": rekor_mod.TLOG_KIND,
            "bundle_schema": rekor_mod.BUNDLE_SCHEMA,
        }
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "tlog_kind": rekor_mod.TLOG_KIND}


def _rate_limit(request: Request):
    if not BUCKET.allow(_client_key(request)):
        raise HTTPException(429, "rate limit exceeded")


def _verify_manifest_signature(manifest_dict: dict) -> tuple[bool, str]:
    """
    Parse and verify the manifest's embedded Ed25519 signature.
    Returns (ok, issuer_pub_hex). issuer_pub_hex is the claimed issuer key.
    """
    try:
        m = Manifest.from_json(
            json.dumps(manifest_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
    except Exception as e:
        return False, ""
    return m.verify(), m.issuer_ed25519_pub


@app.post("/register")
def register(req: RegistrationRequest, request: Request):
    """
    Register a sealed file's beacons + watermarks.

    Security requirements:
      - The manifest's embedded Ed25519 signature MUST verify.
      - If the file_id already exists in our DB, the re-registration's issuer
        pubkey MUST match the original. This prevents hostile overwrites of
        another issuer's attribution record.
      - A per-client rate limit applies.
    """
    _rate_limit(request)

    m = req.manifest
    file_id = m.get("file_id")
    recipient = m.get("recipient") or {}
    recipient_id = recipient.get("recipient_id", "unknown")
    issuer_id = m.get("issuer_id", "unknown")

    if not file_id:
        raise HTTPException(400, "manifest missing file_id")

    sig_ok, issuer_pub = _verify_manifest_signature(m)
    if not sig_ok:
        raise HTTPException(400, "manifest signature invalid")
    if not issuer_pub:
        raise HTTPException(400, "manifest missing issuer_ed25519_pub")

    now = int(time.time())
    with db() as con:
        existing = con.execute(
            "SELECT issuer_ed25519_pub FROM manifests WHERE file_id=?",
            (file_id,),
        ).fetchone()
        if existing and existing["issuer_ed25519_pub"] != issuer_pub:
            raise HTTPException(
                409,
                f"file_id already registered under a different issuer pubkey "
                f"(claimed={issuer_pub[:16]}..., existing={existing['issuer_ed25519_pub'][:16]}...)",
            )

        con.execute(
            "INSERT OR REPLACE INTO manifests VALUES (?,?,?,?,?,?)",
            (file_id, recipient_id, issuer_id, issuer_pub, json.dumps(m), now),
        )
        for b in req.beacons:
            con.execute(
                "INSERT OR REPLACE INTO beacons VALUES (?,?,?,?,?,?)",
                (b["token_id"], file_id, recipient_id, issuer_id, b["kind"], now),
            )
        for w in req.watermarks:
            con.execute(
                "INSERT OR REPLACE INTO watermarks VALUES (?,?,?,?,?,?)",
                (w["mark_id"], w["layer"], file_id, recipient_id, issuer_id, now),
            )
        if req.corpus:
            for hash_kind, hash_value in req.corpus.items():
                if hash_value:
                    con.execute(
                        "INSERT OR REPLACE INTO corpus VALUES (?,?,?,?,?)",
                        (file_id, hash_kind, str(hash_value), None, now),
                    )

    tlog_idx = _append_tlog({
        "event": "register",
        "file_id": file_id,
        "recipient_id": recipient_id,
        "issuer_id": issuer_id,
        "issuer_pub": issuer_pub,
        "n_beacons": len(req.beacons),
        "n_watermarks": len(req.watermarks),
        "timestamp": timestamp_stub(),
    })

    rekor_result = _attest_to_rekor(
        file_id=file_id,
        issuer_pub_hex=issuer_pub,
        recipient_id=recipient_id,
        recipient_pubkey_hex=recipient.get("x25519_pub"),
        suite=m.get("suite", "classic"),
        content_hash_sha256_hex=(m.get("content") or {}).get("sha256", "0" * 64),
        mark_id_hex=file_id,
    )

    return {
        "ok": True,
        "file_id": file_id,
        "registered_beacons": len(req.beacons),
        "tlog_index": tlog_idx,
        "rekor": rekor_result,
    }


ONE_PX_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d49444154789c626000000000050001a5f645400000000049454e44ae426082"
)


def _record_event(request: Request, token_id: str, kind: str) -> int:
    with db() as con:
        row = con.execute(
            "SELECT file_id, recipient_id, issuer_id FROM beacons WHERE token_id=?",
            (token_id,),
        ).fetchone()
        file_id = row["file_id"] if row else None
        recipient_id = row["recipient_id"] if row else None
        issuer_id = row["issuer_id"] if row else None

        client_ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent", "")
        qts = timestamp_stub()

        tlog_idx = _append_tlog({
            "event": "beacon",
            "kind": kind,
            "token_id": token_id,
            "file_id": file_id,
            "recipient_id": recipient_id,
            "source_ip": client_ip,
            "user_agent": ua,
            "timestamp": qts,
        })

        con.execute(
            "INSERT INTO events (token_id,file_id,recipient_id,issuer_id,kind,"
            "source_ip,user_agent,extra,timestamp,qualified_timestamp,tlog_index) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (token_id, file_id, recipient_id, issuer_id, kind,
             client_ip, ua, "{}", int(time.time()), qts, tlog_idx),
        )
        return tlog_idx


@app.get("/p/{token_id}.png")
async def beacon_png(token_id: str, request: Request):
    _rate_limit(request)
    _record_event(request, token_id, "http_img")
    return Response(content=ONE_PX_PNG, media_type="image/png")


@app.api_route("/ocsp/r/{token_id}", methods=["GET", "POST"])
@app.api_route("/r/{token_id}", methods=["GET", "POST"])
async def beacon_ocsp(token_id: str, request: Request):
    _rate_limit(request)
    _record_event(request, token_id, "ocsp")
    return Response(status_code=200)


@app.get("/lic/v/{token_id}")
@app.get("/v/{token_id}")
async def beacon_license(token_id: str, request: Request):
    _rate_limit(request)
    _record_event(request, token_id, "license")
    return JSONResponse({"valid": True})


@app.post("/attribute")
def attribute(q: AttributionQuery):
    with db() as con:
        row = None
        if q.token_id:
            row = con.execute(
                "SELECT * FROM beacons WHERE token_id=?", (q.token_id,)
            ).fetchone()
        elif q.mark_id and q.layer:
            row = con.execute(
                "SELECT * FROM watermarks WHERE mark_id=? AND layer=?",
                (q.mark_id, q.layer),
            ).fetchone()
        elif q.mark_id:
            row = con.execute(
                "SELECT * FROM watermarks WHERE mark_id=?", (q.mark_id,)
            ).fetchone()
        elif q.perceptual_hash:
            row = con.execute(
                "SELECT c.file_id as file_id, b.recipient_id as recipient_id, "
                "b.issuer_id as issuer_id "
                "FROM corpus c LEFT JOIN beacons b ON c.file_id = b.file_id "
                "WHERE c.hash_kind='perceptual' AND c.hash_value=? LIMIT 1",
                (q.perceptual_hash,),
            ).fetchone()
        else:
            raise HTTPException(400, "provide token_id, mark_id, or perceptual_hash")

        if not row:
            return {"found": False}

        file_id = row["file_id"]
        manifest_row = con.execute(
            "SELECT manifest_json FROM manifests WHERE file_id=?", (file_id,)
        ).fetchone()
        manifest = json.loads(manifest_row["manifest_json"]) if manifest_row else None
        events = con.execute(
            "SELECT kind, source_ip, user_agent, timestamp, qualified_timestamp, tlog_index "
            "FROM events WHERE file_id=? ORDER BY timestamp DESC LIMIT 50",
            (file_id,),
        ).fetchall()

        return {
            "found": True,
            "file_id": file_id,
            "recipient_id": row["recipient_id"],
            "issuer_id": row["issuer_id"],
            "manifest": manifest,
            "recent_events": [dict(e) for e in events],
        }


@app.get("/evidence/{file_id}")
def evidence_bundle(file_id: str):
    with db() as con:
        m = con.execute(
            "SELECT manifest_json FROM manifests WHERE file_id=?", (file_id,)
        ).fetchone()
        if not m:
            raise HTTPException(404, "unknown file_id")
        events = con.execute(
            "SELECT * FROM events WHERE file_id=? ORDER BY timestamp ASC", (file_id,),
        ).fetchall()
        beacons = con.execute(
            "SELECT * FROM beacons WHERE file_id=?", (file_id,)
        ).fetchall()
        watermarks = con.execute(
            "SELECT * FROM watermarks WHERE file_id=?", (file_id,)
        ).fetchall()

    bundle = {
        "file_id": file_id,
        "bundle_generated_at": timestamp_stub(),
        "registry_pub": IDENTITY["ed25519_pub"],
        "manifest": json.loads(m["manifest_json"]),
        "beacons": [dict(b) for b in beacons],
        "watermarks": [dict(w) for w in watermarks],
        "events": [dict(e) for e in events],
        "tlog_head": TLOG.signed_head() if TLOG else None,
        "disclaimer": (
            "This bundle is a provenance record, not a legal finding. For court use, "
            "supplement with RFC 3161 qualified timestamps and ISO/IEC 27037 chain-of-custody."
        ),
    }
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(IDENTITY["ed25519_priv"]))
    msg = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    bundle["bundle_signature_ed25519"] = sk.sign(msg).hex()
    return bundle


@app.get("/tlog/head")
def tlog_head():
    if not TLOG:
        raise HTTPException(503, "tlog not initialized")
    return TLOG.signed_head()


@app.get("/tlog/proof/{index}")
def tlog_proof(index: int):
    if not TLOG:
        raise HTTPException(503, "tlog not initialized")
    proof = TLOG.inclusion_proof(index)
    if proof is None:
        raise HTTPException(404, "index out of range")
    return proof


@app.get("/tlog/range")
def tlog_range(start: int = 0, limit: int = 500):
    """Return tlog leaf entries in [start, start+limit). For CanaryKeeper polling."""
    if not TLOG:
        raise HTTPException(503, "tlog not initialized")
    limit = min(max(1, limit), 1000)
    leaves_path = TLOG.leaves_path
    if not leaves_path.exists():
        return {"start": start, "count": 0, "entries": []}
    entries = []
    with leaves_path.open("r") as f:
        for i, line in enumerate(f):
            if i < start:
                continue
            if len(entries) >= limit:
                break
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
    return {"start": start, "count": len(entries), "entries": entries}


class DnsEvent(BaseModel):
    token_id: str
    client_ip: Optional[str] = None
    qtype: Optional[str] = None
    qname: Optional[str] = None


@app.post("/dns_event")
def dns_event(evt: DnsEvent, request: Request):
    """Called by the oversight_dns server when a beacon DNS query arrives."""
    _rate_limit(request)
    with db() as con:
        row = con.execute(
            "SELECT file_id, recipient_id, issuer_id FROM beacons WHERE token_id=?",
            (evt.token_id,),
        ).fetchone()
        file_id = row["file_id"] if row else None
        recipient_id = row["recipient_id"] if row else None
        issuer_id = row["issuer_id"] if row else None

        qts = timestamp_stub()
        tlog_idx = _append_tlog({
            "event": "beacon",
            "kind": "dns",
            "token_id": evt.token_id,
            "file_id": file_id,
            "recipient_id": recipient_id,
            "source_ip": evt.client_ip,
            "qname": evt.qname,
            "qtype": evt.qtype,
            "timestamp": qts,
        })
        con.execute(
            "INSERT INTO events (token_id,file_id,recipient_id,issuer_id,kind,"
            "source_ip,user_agent,extra,timestamp,qualified_timestamp,tlog_index) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (evt.token_id, file_id, recipient_id, issuer_id, "dns",
             evt.client_ip, "", json.dumps({"qtype": evt.qtype, "qname": evt.qname}),
             int(time.time()), qts, tlog_idx),
        )
    return {"ok": True, "tlog_index": tlog_idx}


@app.get("/candidates/semantic")
def candidates_semantic(limit: int = 1000, since: Optional[int] = None):
    """
    Flywheel-friendly endpoint: returns recent L3 semantic mark_ids so the
    scraper can verify them against leaked text without shipping the whole
    watermark table over the wire repeatedly.
    """
    limit = min(max(1, limit), 10_000)
    with db() as con:
        if since:
            rows = con.execute(
                "SELECT mark_id, file_id, recipient_id, registered_at FROM watermarks "
                "WHERE layer='L3_semantic' AND registered_at>=? "
                "ORDER BY registered_at DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT mark_id, file_id, recipient_id, registered_at FROM watermarks "
                "WHERE layer='L3_semantic' ORDER BY registered_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return {
        "generated_at": timestamp_stub(),
        "count": len(rows),
        "candidates": [dict(r) for r in rows],
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "oversight-registry",
        "version": "0.2.1",
        "tlog_size": TLOG.size() if TLOG else 0,
    }


@app.get("/.well-known/oversight-registry")
def well_known():
    return {
        "ed25519_pub": IDENTITY["ed25519_pub"] if IDENTITY else None,
        "version": "0.2.1",
        "jurisdiction": os.environ.get("OVERSIGHT_JURISDICTION", "GLOBAL"),
        "tlog_size": TLOG.size() if TLOG else 0,
    }
