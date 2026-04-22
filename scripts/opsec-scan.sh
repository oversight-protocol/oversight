#!/usr/bin/env bash
#
# opsec-scan: fail fast if about-to-commit content carries internal
# infrastructure details. Designed to run as a pre-commit hook and in CI.
#
# Usage:
#   scripts/opsec-scan.sh              # scan the whole working tree
#   scripts/opsec-scan.sh --staged     # scan staged diff only (pre-commit)
#
# Exit code is non-zero on any finding.

set -euo pipefail

MODE="tree"
if [[ "${1:-}" == "--staged" ]]; then
    MODE="staged"
fi

# Patterns that should never land in a public commit. Extend carefully.
# Each entry is a (label, ERE regex) pair.
PATTERNS=(
    "rfc1918-192-168:\\b192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3}\\b"
    "rfc1918-10-dot:\\b10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\b"
    "rfc1918-172-16:\\b172\\.(1[6-9]|2[0-9]|3[0-1])\\.[0-9]{1,3}\\.[0-9]{1,3}\\b"
    "workspace-path:/shared/projects(/|\\b)"
    "container-id:\\bCT [0-9]{3}\\b"
    "homelab-node:\\bpve-gpu\\b"
    "windows-desktop-path:\\bP:[/\\\\]"
    "github-pat:\\bghp_[A-Za-z0-9]{30,}\\b"
    "openai-key:\\bsk-[A-Za-z0-9]{20,}\\b"
    "slack-bot-token:\\bxoxb-[A-Za-z0-9-]{20,}\\b"
    "private-ssh-pem:-----BEGIN (OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY-----"
)

# Files we deliberately exempt. The allowlist is short, reviewed, and public.
EXEMPT_PATHS=(
    "scripts/opsec-scan.sh"
    ".github/workflows/opsec.yml"
    "CHANGELOG.md"
    "docs/SIEM.md"
)

is_exempt() {
    local p="$1"
    for e in "${EXEMPT_PATHS[@]}"; do
        [[ "$p" == "$e" ]] && return 0
    done
    return 1
}

scan_blob() {
    local path="$1"
    local content="$2"
    local fail=0
    for entry in "${PATTERNS[@]}"; do
        local label="${entry%%:*}"
        local rx="${entry#*:}"
        local hits
        hits=$(printf '%s' "$content" | grep -nE -e "$rx" 2>/dev/null || true)
        if [[ -n "$hits" ]]; then
            echo "[opsec] $path: $label"
            echo "$hits" | sed 's/^/  /'
            fail=1
        fi
    done
    return $fail
}

overall=0

if [[ "$MODE" == "staged" ]]; then
    # Scan only lines being added in the staged diff.
    while IFS= read -r -d '' path; do
        is_exempt "$path" && continue
        [[ -f "$path" ]] || continue
        # Added lines only
        added=$(git diff --cached -U0 -- "$path" | grep -E '^\+' | grep -vE '^\+\+\+' || true)
        [[ -z "$added" ]] && continue
        if ! scan_blob "$path" "$added"; then overall=1; fi
    done < <(git diff --cached --name-only -z --diff-filter=AM)
else
    # Whole-tree scan.
    while IFS= read -r -d '' path; do
        is_exempt "$path" && continue
        # Skip binary blobs; grep -Iq returns 1 on binary.
        if ! grep -Iq . "$path" 2>/dev/null; then continue; fi
        if ! scan_blob "$path" "$(cat "$path")"; then overall=1; fi
    done < <(git ls-files -z)
fi

if [[ $overall -ne 0 ]]; then
    echo ""
    echo "[opsec] one or more patterns matched. Redact and re-run."
    exit 1
fi

echo "[opsec] clean."
