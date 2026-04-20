"""
OVERSIGHT DNS beacon server.

Runs as an authoritative nameserver for the beacon domain (e.g. `beacon.example.com`).
Every DNS lookup against `<token_id>.t.<beacon_domain>` is logged as an event in
the registry, then answered with a generic A record so the resolver is satisfied.

Why DNS beacons?
    - They fire on document preview in tools that do hostname resolution for
      linked images even when the HTTP fetch is blocked (many security sandboxes).
    - They fire before any HTTP request, giving us earlier detection.
    - They work through DNS-over-HTTPS resolvers, which are often allowed in
      airgapped / restricted environments while direct HTTP is blocked.

Deployment:
    - Run on a public IP (same host as the registry is fine).
    - Configure DNS glue: your beacon domain's parent zone NS records point
      here on UDP port 53.
    - The registry must publish an HTTP endpoint `POST /dns_event` that this
      server calls for every incoming query.

Startup:
    sudo python -m oversight_dns.server \\
        --beacon-domain beacon.example.com \\
        --registry-url http://localhost:8765 \\
        --answer-ip 203.0.113.10

Run as root to bind :53, or use authbind/setcap to avoid root.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path

try:
    from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A
    from dnslib.server import DNSServer, BaseResolver
except ImportError:
    print("dnslib not installed. pip install dnslib")
    sys.exit(1)

import httpx


log = logging.getLogger("oversight_dns")


class OversightResolver(BaseResolver):
    """Resolves queries matching <token_id>.t.<beacon_domain> and logs them."""

    def __init__(
        self,
        beacon_domain: str,
        registry_url: str,
        answer_ip: str,
        registry_secret: str = "",
    ):
        self.beacon_domain = beacon_domain.rstrip(".").lower()
        self.registry_url = registry_url.rstrip("/")
        self.answer_ip = answer_ip
        self.registry_secret = registry_secret
        self.token_suffix = f".t.{self.beacon_domain}"

    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE[request.q.qtype]

        client_ip = handler.client_address[0] if handler.client_address else "unknown"

        # Extract token_id if the query matches our beacon pattern
        token_id = None
        if qname.endswith(self.token_suffix):
            prefix = qname[: -len(self.token_suffix)]
            # The prefix should be the token_id (128-bit hex = 32 chars)
            if all(c in "0123456789abcdef" for c in prefix) and len(prefix) == 32:
                token_id = prefix

        if token_id:
            log.info(f"DNS beacon fired: token={token_id[:16]}... client={client_ip} qtype={qtype}")
            # Report to registry asynchronously (best-effort — we still answer the query)
            try:
                headers = {}
                if self.registry_secret:
                    headers["X-Oversight-DNS-Secret"] = self.registry_secret
                httpx.post(
                    f"{self.registry_url}/dns_event",
                    json={
                        "token_id": token_id,
                        "client_ip": client_ip,
                        "qtype": qtype,
                        "qname": qname,
                    },
                    headers=headers,
                    timeout=2.0,
                )
            except Exception as e:
                log.warning(f"registry report failed: {e}")

        # Always answer with our public IP so the resolver is satisfied
        # (regardless of whether it was a beacon or not — unmatched queries
        # get a generic response and aren't logged).
        if request.q.qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.answer_ip), ttl=60))
        return reply


def main():
    p = argparse.ArgumentParser(description="OVERSIGHT DNS beacon server")
    p.add_argument("--beacon-domain", required=True,
                   help="your beacon domain, e.g. beacon.example.com")
    p.add_argument("--registry-url", required=True,
                   help="URL of the OVERSIGHT registry, e.g. http://localhost:8765")
    p.add_argument("--answer-ip", required=True,
                   help="A-record answer IP (usually this server's public IP)")
    p.add_argument("--registry-secret", default=os.environ.get("OVERSIGHT_DNS_EVENT_SECRET", ""),
                   help="shared secret sent to registry /dns_event")
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--address", default="0.0.0.0")
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args()

    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    if not args.registry_secret and "localhost" not in args.registry_url and "127.0.0.1" not in args.registry_url:
        log.warning("no registry secret configured; public registry callbacks may be rejected")

    resolver = OversightResolver(
        args.beacon_domain,
        args.registry_url,
        args.answer_ip,
        registry_secret=args.registry_secret,
    )
    server = DNSServer(resolver, port=args.port, address=args.address,
                       tcp=False)
    tcp_server = DNSServer(resolver, port=args.port, address=args.address,
                           tcp=True)

    log.info(f"OVERSIGHT DNS beacon server starting on {args.address}:{args.port}")
    log.info(f"  beacon domain: {args.beacon_domain}")
    log.info(f"  token pattern: <token>.t.{args.beacon_domain}")
    log.info(f"  registry:      {args.registry_url}")
    log.info(f"  answer IP:     {args.answer_ip}")

    server.start_thread()
    tcp_server.start_thread()

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        log.info("shutting down")
        server.stop()
        tcp_server.stop()


if __name__ == "__main__":
    main()
