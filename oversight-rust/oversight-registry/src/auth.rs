//! Ed25519 signature verification for /register.
//!
//! Uses the workspace `oversight-manifest` crate to parse and verify manifests
//! in canonical JSON form. The issuer's Ed25519 public key is embedded in the
//! manifest itself — verification proves the issuer signed the exact bytes.

use oversight_manifest::Manifest;

/// Parse a manifest JSON value, canonicalize it, and verify the embedded
/// Ed25519 signature.
///
/// Returns `(signature_valid, issuer_ed25519_pub_hex)`.
/// If parsing fails, returns `(false, "")`.
pub fn verify_manifest_signature(manifest_value: &serde_json::Value) -> (bool, String) {
    // Serialize to canonical JSON bytes (sorted keys, no whitespace) the same
    // way the Python server does: json.dumps(m, sort_keys=True, separators=(",",":"))
    let canonical = match serde_jcs::to_vec(manifest_value) {
        Ok(b) => b,
        Err(_) => return (false, String::new()),
    };

    let manifest: Manifest = match serde_json::from_slice(&canonical) {
        Ok(m) => m,
        Err(_) => return (false, String::new()),
    };

    let issuer_pub = manifest.issuer_ed25519_pub.clone();

    match manifest.verify() {
        Ok(true) => (true, issuer_pub),
        _ => (false, issuer_pub),
    }
}

/// Normalize a list of sidecar items (beacons or watermarks) to sorted
/// canonical JSON strings for exact comparison against the signed manifest.
///
/// This mirrors the Python `_canonical_items()` function that sorts the
/// JSON-serialized forms to detect any mismatch between the request sidecars
/// and the manifest's signed copies.
pub fn canonical_items(items: &[serde_json::Value]) -> Vec<String> {
    let mut result: Vec<String> = items
        .iter()
        .filter_map(|item| serde_jcs::to_string(item).ok())
        .collect();
    result.sort();
    result
}

/// Validate that the request beacons/watermarks exactly match the signed
/// manifest's beacons/watermarks. Returns the signed copies on success.
///
/// This is the v0.4.4 hardening check: the registry uses the manifest's
/// embedded copies as the source of truth. If the request sidecars differ
/// from what was signed, the registration is rejected.
pub fn validate_signed_artifacts(
    manifest_value: &serde_json::Value,
    req_beacons: &[serde_json::Value],
    req_watermarks: &[serde_json::Value],
) -> Result<(Vec<serde_json::Value>, Vec<serde_json::Value>), String> {
    let signed_beacons: Vec<serde_json::Value> = manifest_value
        .get("beacons")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let signed_watermarks: Vec<serde_json::Value> = manifest_value
        .get("watermarks")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if canonical_items(req_beacons) != canonical_items(&signed_beacons) {
        return Err("request beacons do not match signed manifest".into());
    }

    if canonical_items(req_watermarks) != canonical_items(&signed_watermarks) {
        return Err("request watermarks do not match signed manifest".into());
    }

    Ok((signed_beacons, signed_watermarks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_items_sorts_deterministically() {
        let a = serde_json::json!({"z": 1, "a": 2});
        let b = serde_json::json!({"a": 2, "z": 1});
        // Same logical object, different key order: canonical form should match.
        let ca = canonical_items(&[a]);
        let cb = canonical_items(&[b]);
        assert_eq!(ca, cb);
    }

    #[test]
    fn canonical_items_detects_difference() {
        let a = serde_json::json!({"token_id": "abc", "kind": "dns"});
        let b = serde_json::json!({"token_id": "xyz", "kind": "dns"});
        assert_ne!(canonical_items(&[a]), canonical_items(&[b]));
    }
}
