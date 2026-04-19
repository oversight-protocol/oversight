# Hardware Security Keys for Oversight

Vendor-neutral guide for storing Oversight recipient private keys on a hardware
device (YubiKey, OnlyKey, Nitrokey) rather than a disk file.

## Why

When a recipient's `.key` file lives on disk, full compromise of that
recipient's laptop gives an attacker the private key forever. That attacker
can decrypt every sealed file addressed to that recipient, past and future,
with no way to tell the issuer it happened.

A hardware-backed key eliminates this. The private key is generated inside
the device's secure element and never leaves it. All ECDH (X25519) and
signing (Ed25519) operations happen on-device. The host OS gets ECDH
outputs, never the raw key. To decrypt, an adversary needs physical
possession of the device — and typically a touch, PIN, or biometric.

This doesn't give you enclave-grade guarantees (a compromised client
running while the YubiKey is plugged in can still open files via the device).
What it does give you:

- **Vendor-neutral** — any FIDO2 / PIV device works.
- **Theft is discrete** — physical device loss is noticeable; disk theft may not be.
- **Revocation is simple** — deauthorize the device's pubkey in the registry.
- **Works offline** — no cloud service.
- **No recurring cost** — $50–$80 once.

## Supported devices

Any device exposing **PIV** (Personal Identity Verification, PKCS#11-compatible)
slots works. Tested:

| Device | Cost (USD) | PIV slots | Notes |
|---|---|---|---|
| YubiKey 5C NFC | ~$75 | yes | Most tested; widely available |
| YubiKey 5 NFC | ~$55 | yes | USB-A version |
| YubiKey Security Key NFC | ~$29 | FIDO2 only | Cheapest but limited |
| Nitrokey 3 NFC | ~$80 | yes | Fully open-source firmware |
| OnlyKey | ~$50 | yes | Open hardware + firmware |

Recommendation: **YubiKey 5C NFC** for most users (best tooling), **Nitrokey
3** if firmware openness matters more than ecosystem support.

## First-time setup

### 1. Install the tooling

```bash
# Debian / Ubuntu
sudo apt install yubikey-manager pcscd opensc
sudo systemctl enable --now pcscd

# macOS
brew install yubikey-manager opensc

# Arch
sudo pacman -S yubikey-manager opensc ccid
```

### 2. Verify the device is seen

```bash
ykman info
# Should print serial, firmware version, and enabled applications.

pkcs11-tool --list-slots --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
# Should list the YubiKey as slot 0.
```

### 3. Set a PIN and management key

**Do not skip this.** The factory defaults (PIN 123456, PUK 12345678) are
publicly known. Change both now.

```bash
# PIV PIN (6-8 digits)
ykman piv access change-pin

# PIV PUK (used to unblock if you lock yourself out)
ykman piv access change-puk

# Management key (used for admin ops; 24-byte hex)
ykman piv access change-management-key --generate --protect
# --protect stashes the new key in PIV slot so you don't need to manage it
```

### 4. Generate an Oversight recipient key on-device

PIV has four main slots. Use **slot 9d (Key Management)** for Oversight — it's
meant for decryption operations and doesn't require PIN on every use (only
first use per session, via cached auth).

```bash
# Generate an ECC P-256 key in slot 9d
ykman piv keys generate 9d --algorithm ECCP256 -
# Note: P-256, not Curve25519. See "Curve choice" below.

# Self-sign a cert so PIV treats the slot as initialized
ykman piv certificates generate 9d \
    --subject "CN=oversight-recipient" \
    --valid-days 3650 -
```

### 5. Export the public key in Oversight format

Oversight identities are JSON. We need to convert the PIV slot's public key
to the format Oversight uses.

```bash
# Export the cert, extract the pubkey
ykman piv certificates export 9d - | \
    openssl x509 -pubkey -noout -in - | \
    openssl ec -pubin -text -noout
```

Write the resulting pubkey hex into an Oversight identity file with a
`hardware: true` marker:

```json
{
  "hardware": true,
  "provider": "piv",
  "piv_slot": "9d",
  "x25519_pub_equivalent": "<hex>",
  "ed25519_pub": null,
  "device_serial": "<yubikey-serial>"
}
```

The `x25519_pub_equivalent` is the P-256 pubkey. Oversight's hardware mode
uses **P-256 ECDH** instead of X25519 for this recipient, because P-256 is
what PIV supports natively (Curve25519 PIV support exists but is limited —
see below).

## Curve choice: why P-256 for hardware-backed recipients

The default Oversight suite uses X25519 for key agreement. PIV-compatible
hardware devices historically only supported P-256 and P-384 for PIV slots.
YubiKey 5.7+ firmware does support Curve25519 via a dedicated OpenPGP
applet, but PIV itself does not.

To stay compatible with the broadest set of devices (Nitrokey, OnlyKey,
older YubiKeys), Oversight uses **P-256 ECDH** for hardware-backed
recipients. The suite identifier in the manifest becomes `OSGT-HW-P256-v1`
instead of `OSGT-CLASSIC-v1`. The crypto is just as strong — P-256 ECDH
is NIST-standardized, FIPS 140-3 compliant, and battle-tested.

Open clients that want to decrypt for hardware-backed recipients must
support both suites. The default file-backed provider stays on X25519.

## Opening a sealed file with a hardware-backed key (CLI)

```bash
# Insert YubiKey. You may be prompted for PIN.
oversight open --input secret.sealed --output secret.txt \
    --recipient-hw piv:9d

# First op prompts for PIN; subsequent ops within the session don't.
```

Under the hood, this calls PKCS#11 `C_DeriveKey` to run ECDH against the
on-device private key, then runs the standard Oversight HKDF + AEAD decrypt
on the host. The raw private key never leaves the device.

## Revocation

If a device is lost, stolen, or retired:

1. POST to the registry:
   ```
   POST /recipients/{recipient_id}/revoke
   Authorization: Bearer <issuer_token>
   {"reason": "device_lost", "replaced_by": "<new_pubkey_hex>"}
   ```
2. The registry appends a revocation event to the tlog with a qualified
   RFC 3161 timestamp. Anyone verifying future sealed files addressed to
   the old pubkey will see the revocation in the event history and reject
   the file.
3. Issue new sealed files to the recipient's new pubkey.

Note: the revocation does NOT un-seal already-delivered ciphertext. Any file
the lost device opened before it was lost is already out. Revocation
protects against *future* misuse of the device.

## Threat model for hardware-backed keys

**What hardware keys defend against:**
- Recipient laptop fully compromised, attacker has root, keylogger running:
  attacker cannot exfiltrate the private key. Can only ECDH while device is
  plugged in. Discrete events.
- Recipient's encrypted laptop is stolen while powered off. Attacker brute-
  forces disk. Gets nothing useful because the PIV key is on the YubiKey.
- Malware on recipient's machine installs a background decryption job.
  Hardware-backed means each ECDH requires the device to be plugged in and
  (optionally) a touch. Attacker can't do it passively.

**What hardware keys do NOT defend against:**
- Recipient's laptop compromised WHILE YubiKey is plugged in. Attacker can
  call PKCS#11 to do ECDH against any file the legitimate client could.
  Mitigation: require touch-to-decrypt (YubiKey PIV policy `always-require`).
- Physical theft of both laptop + YubiKey. Attacker has everything needed.
  Mitigation: strong PIN; device auto-locks after N wrong PINs.
- A supply-chain-compromised YubiKey. Vendor-independence is the only
  mitigation — and is why Oversight supports Nitrokey / OnlyKey alongside.

## Known hardware caveats

- **PIV key operations count against the device's attempt counter.** YubiKey
  PIV defaults to 3 attempts before locking. Set a reasonable limit and
  keep a PUK to recover.
- **Touch policy trade-off.** `always-require-touch` is more secure but
  requires user interaction on every open. `cached` touches (one per
  session) is the usual compromise.
- **No post-quantum yet.** Current hardware keys don't support ML-KEM /
  ML-DSA. Hardware-backed recipients are CLASSIC-only for now. For PQ
  protection, use a file-backed recipient with a PQ suite, or wait for
  hardware-native ML-KEM support (YubiKey and Nitrokey have hinted at
  late-2026 / 2027 firmware).

## Checklist before deploying to real recipients

- [ ] PIN and PUK changed from factory defaults.
- [ ] Management key rotated.
- [ ] Touch policy decided (always vs cached vs never).
- [ ] Device serial recorded in a separate, encrypted inventory.
- [ ] Recovery procedure documented (if device lost, who is notified and how).
- [ ] Backup strategy: issue each recipient TWO devices (primary + backup),
      register BOTH pubkeys, seal to both, store backup in a safe.
- [ ] Revocation playbook tested end-to-end on a test recipient.

## Further reading

- YubiKey PIV documentation: https://developers.yubico.com/PIV/
- NIST SP 800-73-4 (PIV Interfaces): https://csrc.nist.gov/pubs/sp/800/73/4
- Nitrokey 3 PIV: https://docs.nitrokey.com/nitrokey3/
