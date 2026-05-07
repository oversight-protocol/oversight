//! # oversight CLI
//!
//! `oversight keygen | seal | open | inspect | watermark | detect-format` for Oversight sealed files.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use oversight_container::{open_sealed, seal, SealedFile};
use oversight_crypto::{self as crypto, ClassicIdentity};
use oversight_formats::{FormatAdapter, FormatRegistry};
use oversight_manifest::{Manifest, Recipient};
use oversight_policy::PolicyContext;

#[derive(Parser)]
#[command(name = "oversight")]
#[command(about = "Oversight — open protocol for provenance, attribution, and leak detection")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new classical identity (X25519 + Ed25519)
    Keygen {
        /// Output path for the identity JSON file
        #[arg(short, long)]
        out: PathBuf,
    },

    /// Seal a plaintext file for a recipient
    Seal {
        /// Plaintext input file
        #[arg(short, long)]
        input: PathBuf,

        /// Sealed output path
        #[arg(short, long)]
        output: PathBuf,

        /// Issuer identity JSON (from `keygen`)
        #[arg(short = 'I', long)]
        issuer: PathBuf,

        /// Recipient x25519 public key (hex)
        #[arg(short = 'R', long)]
        recipient_pub: String,

        /// Recipient ID (stable identifier, e.g. email)
        #[arg(long, default_value = "recipient")]
        recipient_id: String,

        /// Registry URL to bake into the manifest
        #[arg(long, default_value = "https://registry.example.com")]
        registry: String,
    },

    /// Open a sealed file
    Open {
        /// Sealed input file
        #[arg(short, long)]
        input: PathBuf,

        /// Plaintext output path (use `-` for stdout)
        #[arg(short, long)]
        output: PathBuf,

        /// Recipient identity JSON
        #[arg(short = 'R', long)]
        recipient: PathBuf,

        /// Local directory for max_opens counters
        #[arg(long, default_value = ".oversight/policy-state")]
        policy_state_dir: PathBuf,
    },

    /// Print the signed manifest + structural metadata of a sealed file
    Inspect {
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Embed a watermark into a file (auto-detects format)
    Watermark {
        /// Input file
        #[arg(short, long)]
        input: PathBuf,

        /// Output file (watermarked)
        #[arg(short, long)]
        output: PathBuf,

        /// Mark ID (hex). If omitted, generates a random 8-byte ID.
        #[arg(short, long)]
        mark_id: Option<String>,

        /// Force a specific format adapter (text, pdf, docx, image)
        #[arg(short, long)]
        format: Option<String>,
    },

    /// Extract watermarks from a file (auto-detects format)
    Extract {
        /// Input file to scan for watermarks
        #[arg(short, long)]
        input: PathBuf,

        /// Force a specific format adapter
        #[arg(short, long)]
        format: Option<String>,
    },

    /// Detect the format of a file and list available adapters
    DetectFormat {
        /// Input file to detect
        #[arg(short, long)]
        input: PathBuf,
    },
}

fn save_identity(id: &ClassicIdentity, path: &PathBuf) -> std::io::Result<()> {
    let json = serde_json::json!({
        "x25519_priv": hex::encode(id.x25519_priv.as_ref()),
        "x25519_pub":  hex::encode(id.x25519_pub),
        "ed25519_priv": hex::encode(id.ed25519_priv.as_ref()),
        "ed25519_pub":  hex::encode(id.ed25519_pub),
    });
    // 0600 file permissions on POSIX
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        use std::io::Write;
        f.write_all(serde_json::to_string_pretty(&json)?.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, serde_json::to_string_pretty(&json)?)?;
    }
    Ok(())
}

fn load_identity(path: &PathBuf) -> Result<ClassicIdentity, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let x_priv = hex::decode(v["x25519_priv"].as_str().ok_or("missing x25519_priv")?)?;
    let ed_priv = hex::decode(v["ed25519_priv"].as_str().ok_or("missing ed25519_priv")?)?;
    if x_priv.len() != 32 || ed_priv.len() != 32 {
        return Err("malformed identity file".into());
    }
    let mut x_arr = [0u8; 32];
    x_arr.copy_from_slice(&x_priv);
    let mut ed_arr = [0u8; 32];
    ed_arr.copy_from_slice(&ed_priv);
    Ok(ClassicIdentity::from_raw(x_arr, ed_arr))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen { out } => {
            let id = ClassicIdentity::generate();
            save_identity(&id, &out)?;
            println!("✓ new identity written to {}", out.display());
            println!("  x25519_pub:  {}", hex::encode(id.x25519_pub));
            println!("  ed25519_pub: {}", hex::encode(id.ed25519_pub));
            println!("  (file mode 0600)");
        }

        Commands::Seal {
            input,
            output,
            issuer,
            recipient_pub,
            recipient_id,
            registry,
        } => {
            let issuer_id = load_identity(&issuer)?;
            let plaintext = std::fs::read(&input)?;
            let recipient_pub_bytes = hex::decode(recipient_pub)?;
            if recipient_pub_bytes.len() != 32 {
                return Err("recipient_pub must decode to 32 bytes".into());
            }

            let mut manifest = Manifest::new(
                input.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
                crypto::content_hash(&plaintext),
                plaintext.len() as u64,
                "cli-issuer",
                hex::encode(issuer_id.ed25519_pub),
                Recipient {
                    recipient_id,
                    x25519_pub: hex::encode(&recipient_pub_bytes),
                    ed25519_pub: None,
                    p256_pub: None,
                },
                registry,
                "application/octet-stream",
                None,
                None,
                "GLOBAL",
            );
            let blob = seal(
                &plaintext,
                &mut manifest,
                issuer_id.ed25519_priv.as_ref(),
                &recipient_pub_bytes,
            )?;
            std::fs::write(&output, &blob)?;
            println!("✓ sealed {} -> {} ({} bytes)", input.display(), output.display(), blob.len());
            println!("  file_id: {}", manifest.file_id);
        }

        Commands::Open {
            input,
            output,
            recipient,
            policy_state_dir,
        } => {
            let recipient_id = load_identity(&recipient)?;
            let blob = std::fs::read(&input)?;
            let policy_ctx = PolicyContext::local_only(policy_state_dir)?;
            let (plaintext, manifest) =
                open_sealed(&blob, recipient_id.x25519_priv.as_ref(), None, Some(&policy_ctx))?;
            if output.as_os_str() == "-" {
                use std::io::Write;
                std::io::stdout().write_all(&plaintext)?;
            } else {
                std::fs::write(&output, &plaintext)?;
            }
            eprintln!("✓ opened {} ({} bytes)", input.display(), plaintext.len());
            eprintln!("  file_id:  {}", manifest.file_id);
            eprintln!("  issuer:   {}", manifest.issuer_id);
        }

        Commands::Inspect { input } => {
            let blob = std::fs::read(&input)?;
            let sf = SealedFile::from_bytes(&blob)?;
            let pretty = serde_json::to_string_pretty(&sf.manifest)?;
            println!("=== Manifest ===");
            println!("{}", pretty);
            println!();
            println!("=== Structure ===");
            println!("  suite_id:        {}", sf.suite_id);
            println!("  ciphertext_len:  {} bytes", sf.ciphertext.len());
            println!("  aead_nonce:      {}", hex::encode(sf.aead_nonce));
            println!("  signature valid: {}", sf.manifest.verify().unwrap_or(false));
        }

        Commands::Watermark {
            input,
            output,
            mark_id,
            format,
        } => {
            let data = std::fs::read(&input)?;
            let registry = FormatRegistry::default();

            let adapter = resolve_adapter(&registry, &data, format.as_deref(), &input)?;
            let mark_bytes = match mark_id {
                Some(hex_str) => hex::decode(&hex_str)?,
                None => {
                    let id = oversight_watermark::new_mark_id(8);
                    eprintln!("  generated mark_id: {}", hex::encode(&id));
                    id
                }
            };

            let marked = adapter.embed_watermark(&data, &mark_bytes)
                .map_err(|e| format!("embed failed: {}", e))?;
            std::fs::write(&output, &marked)?;
            println!(
                "watermarked {} -> {} ({} bytes, format: {})",
                input.display(),
                output.display(),
                marked.len(),
                adapter.name()
            );
            println!("  mark_id: {}", hex::encode(&mark_bytes));
        }

        Commands::Extract { input, format } => {
            let data = std::fs::read(&input)?;
            let registry = FormatRegistry::default();

            let adapter = resolve_adapter(&registry, &data, format.as_deref(), &input)?;
            let candidates = adapter.extract_watermark(&data)
                .map_err(|e| format!("extract failed: {}", e))?;

            println!(
                "=== Watermark extraction: {} (format: {}) ===",
                input.display(),
                adapter.name()
            );
            if candidates.is_empty() {
                println!("  no watermarks found");
            } else {
                for (i, c) in candidates.iter().enumerate() {
                    println!(
                        "  [{}] layer={}, mark_id={}, confidence={:.3}",
                        i,
                        c.layer,
                        hex::encode(&c.mark_id),
                        c.confidence
                    );
                }
            }
        }

        Commands::DetectFormat { input } => {
            let data = std::fs::read(&input)?;
            let registry = FormatRegistry::default();

            println!("=== Format detection: {} ===", input.display());
            println!("  file size: {} bytes", data.len());

            if let Some(adapter) = registry.detect(&data) {
                println!("  detected:  {}", adapter.name());
                println!("  extensions: {:?}", adapter.extensions());
            } else {
                println!("  detected:  (unknown)");
            }

            // Also try extension-based lookup
            if let Some(ext) = input.extension().and_then(|e| e.to_str()) {
                if let Some(adapter) = registry.by_extension(ext) {
                    println!("  by extension .{}: {}", ext, adapter.name());
                }
            }

            println!("  available adapters: {:?}", registry.adapter_names());
        }
    }
    Ok(())
}

/// Resolve which format adapter to use: explicit --format flag, or auto-detect
/// from file content (preferred) or extension (fallback).
fn resolve_adapter<'a>(
    registry: &'a FormatRegistry,
    data: &[u8],
    format_override: Option<&str>,
    path: &PathBuf,
) -> Result<&'a dyn FormatAdapter, Box<dyn std::error::Error>> {
    if let Some(name) = format_override {
        return registry
            .by_name(name)
            .ok_or_else(|| format!("unknown format: '{}'. available: {:?}", name, registry.adapter_names()).into());
    }

    // Try content-based detection first
    if let Some(adapter) = registry.detect(data) {
        return Ok(adapter);
    }

    // Fall back to extension
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if let Some(adapter) = registry.by_extension(ext) {
            return Ok(adapter);
        }
    }

    Err(format!(
        "could not detect format for '{}'. use --format to specify. available: {:?}",
        path.display(),
        registry.adapter_names()
    )
    .into())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}
