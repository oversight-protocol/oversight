# Oversight Security Notes

This document is the honest threat-model companion to the protocol spec. It
uses RFC 2119 / BCP 14 language for requirements; those terms are interpreted
only when written in all capitals.

## Watermark Layer Limits

| Layer | Screenshot | Reformat | Manual retype | Motivated adversary with vocab |
|-------|------------|----------|---------------|--------------------------------|
| L1 zero-width | No | Often no | No | No |
| L2 whitespace | No | No | No | No |
| L3 semantic | Yes | Yes | Often yes | No; canonicalization can defeat it |

L1 and L2 are steganographic convenience layers. They are useful forensic
signals but fragile against normalization. L3 is stronger because it encodes
choices in visible prose, but that means it changes the recipient copy.

## L3 Semantic Watermark Safety

L3 is opt-in for wording-sensitive documents. The seal path defaults L3 off
for legal documents, regulatory filings, technical specifications, source
code, SQL, logs, and structured data. When L3 is enabled, users must
acknowledge that the recipient copy is textually non-identical to the
canonical source. The manifest records `canonical_content_hash` so a dispute
can compare the recipient copy against the original source bytes.

Safe L3 application skips conservative protected regions:

- RFC 2119 / BCP 14 requirement keywords such as `MUST`, `SHOULD`, and `MAY`
- numerical values with units or percentages
- quoted text, inline code, code blocks, and indented code
- ALL-CAPS defined terms
- likely source-code, SQL, log, and structured-data inputs

`boilerplate` L3 mode marks only header/footer/cover-page style regions and is
the preferred mode when a user wants a semantic signal for contracts or
filings without changing the body text.

## Collusion Threat Model

L3 synonym choices are deterministic per mark ID. If multiple recipients
collude and compare their copies, they can identify controlled vocabulary
positions and may canonicalize those positions before leaking. That can defeat
L3 attribution silently. Mitigations under evaluation:

- per-recipient vocabulary randomization
- stronger candidate scoring that models collusion edits
- warnings or thresholds for large recipient sets before L3 is enabled

Until those mitigations land, issuers should treat L3 as attribution evidence
against ordinary leaks and low-to-medium effort stripping, not as a perfect
collusion-resistant watermark.

## Passive Beacons

Passive beacons are forensic telemetry, not a detection guarantee. Absence of
a beacon does not prove absence of a leak. Corporate egress filtering,
air-gapped readers, privacy tools, sandboxed previews, and offline workflows
can suppress callbacks.

## Jurisdiction Policy

Jurisdiction-by-IP is a soft policy control. It is useful for honest clients,
audit trails, and routing decisions, but it is not a cryptographic security
boundary. VPNs, proxies, and corporate NATs can defeat or blur IP geolocation.

## RFC 3161 Timestamps

RFC 3161 timestamps prove a datum existed at or before the TSA signing time.
They do not prove authorship. The TSA remains a trust anchor. Rekor / DSSE
transparency reduces reliance on a single private timestamping service, but it
does not eliminate timestamp trust entirely.
