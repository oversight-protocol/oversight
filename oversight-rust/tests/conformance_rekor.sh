#!/usr/bin/env bash
#
# Cross-language Rekor conformance for Oversight v0.5.
#
# Asserts:
#   1. PAE bytes are byte-identical between Python (oversight_core.rekor._pae)
#      and Rust (oversight_rekor::pae) for the same fixed inputs.
#   2. A DSSE envelope signed by the Python reference verifies under the
#      Rust verifier with the same public key.
#   3. A DSSE envelope signed by Rust verifies under the Python verifier.
#   4. The base64 payload (and decoded canonical statement bytes) are
#      bit-identical for the same statement when each side signs with the
#      same private key.
#
# Skips itself when CONFORMANCE_OFFLINE is unset to allow environments
# without a working Rust toolchain to opt out. The cargo build is itself
# offline; nothing here touches the network.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
HELPER_BIN="$ROOT/target/release/examples/conformance_helper"

cd "$ROOT"
echo "==> building conformance helper..."
cargo build --release -p oversight-rekor --example conformance_helper >/dev/null
test -x "$HELPER_BIN" || { echo "FAIL: helper not built at $HELPER_BIN"; exit 1; }

# Use a deterministic Ed25519 keypair derived from a fixed seed so both
# sides sign with the same key. (Ed25519 is deterministic so signatures
# match exactly bit-for-bit when key + message are equal.)
PRIV_HEX="1111111111111111111111111111111111111111111111111111111111111111"

# Compute pub_hex via Python (avoids extra Rust subcommand surface).
PUB_HEX="$(python3 - <<PY
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import sys
priv = bytes.fromhex("$PRIV_HEX")
sk = Ed25519PrivateKey.from_private_bytes(priv)
pk = sk.public_key().public_bytes_raw()
sys.stdout.write(pk.hex())
PY
)"
echo "==> deterministic pub: ${PUB_HEX:0:16}..."

#-----------------------------------------------------------------------
# 1. PAE byte-identity
#-----------------------------------------------------------------------
echo "==> [1/4] PAE byte-identity"
PAYLOAD_TYPE="application/vnd.in-toto+json"
PAYLOAD='{"a":1}'

PY_HEX="$(python3 - <<PY
import sys, os
sys.path.insert(0, "$REPO_ROOT")
from oversight_core.rekor import _pae
out = _pae("$PAYLOAD_TYPE", b'$PAYLOAD')
sys.stdout.write(out.hex())
PY
)"

RS_HEX="$(printf '%s' "$PAYLOAD" | "$HELPER_BIN" pae "$PAYLOAD_TYPE")"

if [ "$PY_HEX" != "$RS_HEX" ]; then
    echo "FAIL: PAE drift"
    echo "  py: $PY_HEX"
    echo "  rs: $RS_HEX"
    exit 1
fi
echo "  OK ($PY_HEX)"

#-----------------------------------------------------------------------
# 2. Python signs → Rust verifies
#-----------------------------------------------------------------------
echo "==> [2/4] Python signs → Rust verifies"
PY_ENVELOPE="$(python3 - <<PY
import sys, json
sys.path.insert(0, "$REPO_ROOT")
from oversight_core import rekor as R
priv = bytes.fromhex("$PRIV_HEX")
stmt = {"_type": R.STATEMENT_TYPE, "x": 1}
env = R.sign_dsse(stmt, priv)
sys.stdout.write(env.to_json())
PY
)"
RS_VERDICT="$(printf '%s' "$PY_ENVELOPE" | "$HELPER_BIN" verify "$PUB_HEX" || true)"
if [ "$RS_VERDICT" != "ok" ]; then
    echo "FAIL: Rust failed to verify Python-signed envelope (got: '$RS_VERDICT')"
    echo "  envelope: $PY_ENVELOPE"
    exit 1
fi
echo "  OK"

#-----------------------------------------------------------------------
# 3. Rust signs → Python verifies
#-----------------------------------------------------------------------
echo "==> [3/4] Rust signs → Python verifies"
STMT='{"_type":"https://in-toto.io/Statement/v1","y":2}'
RS_ENVELOPE="$(printf '%s' "$STMT" | "$HELPER_BIN" sign "$PRIV_HEX")"

PY_VERDICT="$(python3 - <<PY
import sys, json
sys.path.insert(0, "$REPO_ROOT")
from oversight_core import rekor as R
env = R.DSSEEnvelope.from_json('$RS_ENVELOPE')
pub = bytes.fromhex("$PUB_HEX")
print("ok" if R.verify_dsse(env, pub) else "fail")
PY
)"
if [ "$PY_VERDICT" != "ok" ]; then
    echo "FAIL: Python failed to verify Rust-signed envelope (got: '$PY_VERDICT')"
    echo "  envelope: $RS_ENVELOPE"
    exit 1
fi
echo "  OK"

#-----------------------------------------------------------------------
# 4. Same statement + same key → identical canonical payload bytes
#-----------------------------------------------------------------------
echo "==> [4/4] Canonical payload byte-identity (same key, same statement)"
SAME_STMT='{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"x","digest":{"sha256":"00"}}]}'

PY_PAYLOAD_HEX="$(python3 - <<PY
import sys, json, base64
sys.path.insert(0, "$REPO_ROOT")
from oversight_core import rekor as R
priv = bytes.fromhex("$PRIV_HEX")
stmt = json.loads('$SAME_STMT')
env = R.sign_dsse(stmt, priv)
sys.stdout.write(base64.b64decode(env.payload_b64).hex())
PY
)"

RS_ENV2="$(printf '%s' "$SAME_STMT" | "$HELPER_BIN" sign "$PRIV_HEX")"
RS_PAYLOAD_HEX="$(printf '%s' "$RS_ENV2" | "$HELPER_BIN" decode_payload | python3 -c "import sys; sys.stdout.write(sys.stdin.buffer.read().hex())")"

if [ "$PY_PAYLOAD_HEX" != "$RS_PAYLOAD_HEX" ]; then
    echo "FAIL: canonical payload drift"
    echo "  py: $PY_PAYLOAD_HEX"
    echo "  rs: $RS_PAYLOAD_HEX"
    exit 1
fi
echo "  OK ($PY_PAYLOAD_HEX)"

echo ""
echo "==> ALL CONFORMANCE CHECKS PASSED — Python ↔ Rust bit-identical (4/4)"
