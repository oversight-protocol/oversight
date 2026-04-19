# OVERSIGHT — Proxmox Deployment Runbook

Walkthrough for standing up OVERSIGHT on your existing Proxmox cluster, integrating with Flywheel (bug bounty automation), Forge (execution node), Perseus (CumpsterMedia orchestration), and PBS (backups), and setting up the public beacon domain.

Target environment:
- `pve` node at 192.168.1.50
- `pve-gpu` node at 192.168.1.107 (RTX 3060)
- WireGuard on CT 200 (192.168.1.51)
- PBS on CT 203 (192.168.1.54)
- Perseus on CT 120 (192.168.1.113)
- Flywheel + Forge + Desktop Claude + Mullvad VPN + GPU inference across the cluster

Proposed OVERSIGHT layout:
- **CT 220** — `oversight-registry` (primary registry service; tlog + signed bundles + rate-limited beacons)
- **CT 221** — `oversight-tsa` (RFC 3161 qualified timestamping — phase 2)
- **CT 222** — `oversight-tlog-mirror` (external read-only mirror for audit — phase 3)
- **CT 223** — `oversight-scraper` (Flywheel-integrated breach-forum scraper — phase 2)

## Phase 1 — Stand up the registry (today, ~30 minutes)

### 1.1 Create the container

```bash
pct create 220 local:vztmpl/debian-12-standard_12.2-1_amd64.tar.zst \
    --hostname oversight-registry \
    --cores 2 --memory 2048 --swap 512 \
    --rootfs local-lvm:20 \
    --net0 name=eth0,bridge=vmbr0,ip=192.168.1.60/24,gw=192.168.1.1 \
    --nameserver 192.168.1.201 \
    --features nesting=1 \
    --unprivileged 1 \
    --onboot 1 \
    --start 1
```

### 1.2 Install Docker inside the container

```bash
pct exec 220 -- bash -c '
    apt-get update
    apt-get install -y curl ca-certificates
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
'
```

### 1.3 Deploy the registry

```bash
scp oversight-0.2.0.tar.gz root@pve:/root/
pct push 220 /root/oversight-0.2.0.tar.gz /root/oversight.tar.gz

pct exec 220 -- bash -c '
    mkdir -p /opt/oversight
    cd /opt/oversight
    tar xzf /root/oversight.tar.gz --strip-components=1
    docker compose up -d --build
    sleep 5
    curl -s http://127.0.0.1:8765/health
'
```

### 1.4 Verify

```bash
pct exec 220 -- curl -s http://127.0.0.1:8765/health
# -> {"status":"ok","service":"oversight-registry","version":"0.2.0","tlog_size":0}

pct exec 220 -- curl -s http://127.0.0.1:8765/.well-known/oversight-registry
# -> {"ed25519_pub":"...","version":"0.2.0","jurisdiction":"GLOBAL","tlog_size":0}
```

Save the `ed25519_pub` value — it's your registry's identity, and every evidence bundle will be signed under it. Anyone validating bundles needs this public key.

### 1.5 Add to PBS backup rotation

```bash
# Match your existing CT 120 (Perseus) backup schedule
pvesh set /nodes/pve/lxc/220/config --onboot 1
```

Losing CT 220 means losing attribution for every file ever sealed. Replicate the PBS backup to an off-site target if you can.

## Phase 2 — Public beacon domain (~2 hours)

### 2.1 DNS setup

Pick a short, memorable beacon domain. It gets baked into every sealed file's beacon URLs — this is effectively permanent for any file you ship, so choose with care.

Examples: `sntl.<yourdomain>`, `beacon.<yourdomain>`, or a dedicated TLD like `sntl.pw`.

Required records (example for `beacon.example.com`):

```
A     beacon.example.com.           <public IP of oversight-registry>
A     *.beacon.example.com.         <public IP of oversight-registry>
```

The wildcard is needed for DNS beacons like `abc123.t.beacon.example.com`.

**IMPORTANT — keep this separate from Flywheel's infrastructure.** Beacon traffic is public-facing by design. Flywheel's C2 and scraper infrastructure has a different adversary profile; don't collapse them.

### 2.2 Port-forward 80 + 443

On your edge router, forward 80 and 443 to CT 220's IP. Do NOT route beacon traffic through Mullvad — the beacons MUST be reachable from the public internet, and routing through a VPN defeats the point.

### 2.3 Update Caddyfile

Edit `Caddyfile`, replace `oversight.example.com` with your chosen beacon domain. Uncomment the Caddy service in `docker-compose.yml`.

```bash
pct exec 220 -- bash -c '
    cd /opt/oversight
    vi Caddyfile
    vi docker-compose.yml
    docker compose up -d
'
```

### 2.4 Test from outside

```bash
curl -s https://beacon.example.com/health
# -> {"status":"ok",...}

# Mint a beacon-addressed URL via the registry API, then:
curl -o /dev/null -s -w "%{http_code}\n" https://beacon.example.com/p/abc123.png
# -> 200 (and an event appended to the tlog)
```

## Phase 3 — Integrate with Flywheel (scraper side)

Flywheel already monitors breach forums, paste sites, and Telegram for bug bounty research. Pointing it at your OVERSIGHT corpus turns it into the attribution pipeline that's the commercial thesis of the project.

### 3.1 Add a Flywheel job kind

Extend Flywheel with a `oversight_match` job. Inputs: a scraped text blob (plus any image/pdf/docx bytes if caught). Flow:

1. Try all text watermark extractors (`oversight_core.formats.text.recover`):
   - L1 zero-width → `mark_id` direct
   - L2 whitespace → `mark_id` direct
   - L3 semantic → needs candidate list from registry, calls `verify_semantic` for each
2. If text is a PDF/DOCX: call `formats.pdf.extract` / `formats.docx.extract` first for fast metadata hits, then `extract_text_for_watermark_recovery` for body-level L1/L2/L3.
3. If text is an image (phash all images attached to the scraped post): `formats.image.verify` against candidate marks, AND `formats.image.perceptual_hash` for fuzzy match.
4. Any hit → POST to `/attribute` → raise a priority-1 alert.

### 3.2 Candidate-list API

For L3 semantic, Flywheel needs the current candidate mark_ids. Add a registry endpoint:

```python
@app.get("/candidates/semantic")
def candidates_semantic(limit: int = 1000):
    with db() as con:
        rows = con.execute(
            "SELECT mark_id, file_id, recipient_id FROM watermarks "
            "WHERE layer='L3_semantic' ORDER BY registered_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return {"candidates": [dict(r) for r in rows]}
```

Flywheel polls this periodically (hourly is fine) and caches locally.

### 3.3 Alerting path

Route OVERSIGHT hits through the Perseus Discord bot but to a dedicated channel (`#oversight-hits`). Don't drown them in Flywheel's normal finding stream — a OVERSIGHT attribution is "document X leaked, attributed to recipient Y" which has a different urgency.

### 3.4 Forge integration

If Flywheel runs its scraping jobs on Forge, you just need outbound HTTP from Forge to the registry for the `/attribute` call. No inbound traffic needed. A single allow-list entry covers it.

## Phase 4 — Legal evidence pipeline (weeks)

### 4.1 RFC 3161 TSA integration

Options:
- **FreeTSA** — free, internal-POC-grade, NOT court-admissible.
- **DigiCert qualified TSA** — commercial, court-grade, ~$1K/yr.
- **Your own TSA on CT 221** — only worth it if you're operating a registry for other parties.

Replace `timestamp_stub()` in `registry/server.py` with actual TSA round-trips. Store the raw `TimeStampToken` bytes in the events table (new column), not the decoded string.

### 4.2 External tlog mirror

Deploy a read-only tlog mirror on CT 222 that polls `/tlog/head` from the primary every minute and stores signed heads with timestamps. If the primary ever "forgets" or reorders an entry, the mirror catches it.

For real production-grade auditability, consider delegating to [Sigstore Rekor](https://github.com/sigstore/rekor) instead of operating your own.

### 4.3 ISO/IEC 27037 alignment

Document:
- Who operates the registry (named role, not just "CumpsterMedia LLC")
- Who has access to the signing keys (HSM-protected for court-grade)
- Chain-of-custody procedure from event ingress to evidence bundle
- Examiner qualifications required to author a final forensic report

## Phase 5 — Hardware attestation (months)

The legitimate "tracker in the engine": gate DEK release through a TEE. The flow:

1. Recipient runs the decryption client inside an attested enclave (Intel TDX, AMD SEV-SNP, AWS Nitro Enclaves, or Azure Confidential VMs).
2. Enclave produces a remote attestation quote proving its identity and software hash.
3. Registry verifies the quote and releases the DEK only if attestation passes and policy is satisfied.
4. Plaintext never leaves the enclave in the clear.

This is the only configuration where a stolen ciphertext + stolen recipient key can still be denied.

Easiest entry point: AWS Nitro Enclaves. Intel Trust Authority (for TDX-based workloads) and AMD SEV-SNP via Azure/GCP are the other reasonable targets.

## Phase 6 — LLM decoy layer (parallel track)

`oversight_core/decoy.py` is already wired for your GPU node's Ollama. Default config hits `http://192.168.1.111:11434` with `dolphin-mistral:7b-v2.8`, which is what's running on CT 205.

Deployment pattern for each protected folder:

```python
from oversight_core.decoy import generate_decoy_set
from oversight_core import (ClassicIdentity, Manifest, Recipient, WatermarkRef, content_hash, seal, beacon, watermark)

# Fixed "trap recipient" identity — same across all decoys
trap = ClassicIdentity.generate()  # generate once, store private key in Perseus

# Generate N decoys
decoys = generate_decoy_set(n=5, context="financial services startup, Delaware LLC")
for filename, body in decoys:
    # Apply watermark to give it a registry-matchable mark
    mark = watermark.new_mark_id()
    body_wm = watermark.embed_zw(body, mark)
    # Seal for trap recipient
    # ... rest of seal flow ...
```

Any beacon firing from a decoy file means an intruder. No legitimate user touches them — the filenames are engineered bait.

Recommendation: host the trap-recipient identity keys in a separate Perseus agent called `CanaryKeeper`. Its only job is: receive OVERSIGHT alerts, check if the callback came from a decoy, escalate to `#oversight-hits` immediately.

## Phase 7 — Post-quantum activation

The PQ primitives are fully implemented in `oversight_core/crypto.py`. To activate for new files:

```bash
pct exec 220 -- bash -c '
    apt install -y libssl-dev cmake ninja-build
    cd /tmp && git clone https://github.com/open-quantum-safe/liboqs
    cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON -GNinja
    cmake --build liboqs/build --parallel 4
    cmake --build liboqs/build --target install
    ldconfig
    docker exec oversight-registry pip install liboqs-python
    docker compose restart oversight-registry
'
```

Then start minting new files with `suite=OSGT-HYBRID-v1`. Existing `OSGT-CLASSIC-v1` files continue to work — the suite is declared in the manifest so the protocol is crypto-agile.

## Monitoring

Add to Perseus's Infra Monitor agent (Phase 4+ queue):

- **Liveness:** `/health` endpoint reachable from public internet (synthetic probe every 5 min from a Mullvad exit)
- **Resource:** CT 220 CPU/mem/disk
- **Tlog growth:** alert on sudden spikes (could indicate beacon flood attack or a real leak)
- **Beacon rate per source IP:** new anomaly detector — high rate from one IP could be an attacker sweeping for leaked files
- **Certificate expiry:** Caddy auto-renews, but monitor anyway
- **Registry identity key age:** alert at 6 months, force rotation at 12

## Security notes specific to your stack

- **Keep issuer signing keys OUT of CT 220.** Generate them on Desktop Claude or on Perseus (CT 120). The registry never needs the issuer's private key — only the public key, which is in every manifest.
- **Beacon domain must be public.** Not Mullvad-fronted, not WireGuard-only. Public by design.
- **Flywheel scraper talks to registry over internal network.** No need to route that traffic over the public beacon domain; Flywheel can hit `192.168.1.60:8765` directly.
- **Do not let Forge or Flywheel's offensive tools share infrastructure with the registry.** If Forge gets flagged/rate-limited/blacklisted, you don't want OVERSIGHT's public face to go with it.
- **The registry's Ed25519 private key is the most sensitive secret in the system.** Losing it means losing the signing chain for all future evidence bundles. Back it up encrypted to PBS and to an off-site target. Consider storing in Perseus Vault (if you build one) rather than on the registry CT disk.

## Day-2 operations checklist

- [ ] `/health` returns 200 from an external probe
- [ ] `/.well-known/oversight-registry` returns the correct public key
- [ ] Seal + register + beacon fires + attribute round-trip works
- [ ] `/tlog/head` signature verifies
- [ ] Evidence bundle signature verifies
- [ ] PBS has a recent backup of CT 220
- [ ] Registry identity private key is backed up separately from the CT
- [ ] Caddy TLS certs are current
- [ ] Flywheel has pulled the latest candidate mark list in the past 24h
- [ ] `#oversight-hits` has been quiet (or the hits are explained)
