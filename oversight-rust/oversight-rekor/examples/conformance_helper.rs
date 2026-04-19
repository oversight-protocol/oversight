//! Cross-language conformance helper for oversight-rekor.
//!
//! Subcommands (read STDIN where applicable, write to STDOUT):
//!   pae <payload_type>      — read raw payload from stdin, write hex(PAE)
//!   verify <pub_hex>        — read DSSE envelope JSON from stdin, exit 0 if verifies
//!   sign <priv_hex>         — read statement JSON from stdin, write canonical envelope JSON
//!   payload <payload>       — write the canonical statement JSON for a tiny fixture
//!
//! Used by `tests/conformance_rekor.sh`. No network. Deterministic for a
//! given key + statement.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use oversight_rekor::{pae, sign_dsse, verify_dsse, DsseEnvelope, DSSE_PAYLOAD_TYPE};
use std::io::{self, Read, Write};

fn read_stdin() -> Vec<u8> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf).expect("read stdin");
    buf
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: conformance_helper <pae|verify|sign> [...]");
        std::process::exit(2);
    }
    match args[1].as_str() {
        "pae" => {
            let payload_type = args.get(2).cloned().unwrap_or_else(|| DSSE_PAYLOAD_TYPE.into());
            let payload = read_stdin();
            let out = pae(&payload_type, &payload);
            let stdout = io::stdout();
            stdout.lock().write_all(hex::encode(out).as_bytes()).unwrap();
        }
        "verify" => {
            let pub_hex = args.get(2).expect("pub hex required");
            let pub_bytes = hex::decode(pub_hex).expect("valid hex pub");
            let raw = read_stdin();
            let env_str = std::str::from_utf8(&raw).expect("utf-8 envelope");
            let env = DsseEnvelope::from_json(env_str).expect("parse envelope");
            if verify_dsse(&env, &pub_bytes) {
                println!("ok");
            } else {
                println!("fail");
                std::process::exit(1);
            }
        }
        "sign" => {
            let priv_hex = args.get(2).expect("priv hex required");
            let priv_bytes = hex::decode(priv_hex).expect("valid hex priv");
            let raw = read_stdin();
            let stmt: serde_json::Value =
                serde_json::from_slice(&raw).expect("parse statement");
            let env = sign_dsse(&stmt, &priv_bytes, "").expect("sign");
            let canon = env.to_canonical_json().expect("canonicalize");
            print!("{}", canon);
        }
        "payload_b64" => {
            // Read envelope from stdin, print the base64 payload.
            let raw = read_stdin();
            let env: DsseEnvelope =
                serde_json::from_slice(&raw).expect("parse envelope");
            print!("{}", env.payload_b64);
        }
        "decode_payload" => {
            // Read envelope from stdin, print decoded payload (the canonical statement bytes).
            let raw = read_stdin();
            let env: DsseEnvelope =
                serde_json::from_slice(&raw).expect("parse envelope");
            let bytes = B64.decode(env.payload_b64.as_bytes()).expect("b64");
            io::stdout().lock().write_all(&bytes).unwrap();
        }
        other => {
            eprintln!("unknown subcommand: {}", other);
            std::process::exit(2);
        }
    }
}
