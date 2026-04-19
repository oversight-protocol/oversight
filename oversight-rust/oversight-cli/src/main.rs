//! # oversight CLI
//!
//! `oversight keygen | seal | open | inspect` for Oversight sealed files.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use oversight_container::{open_sealed, seal, SealedFile};
use oversight_crypto::{self as crypto, ClassicIdentity};
use oversight_manifest::{Manifest, Recipient};

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
    },

    /// Print the signed manifest + structural metadata of a sealed file
    Inspect {
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
        } => {
            let recipient_id = load_identity(&recipient)?;
            let blob = std::fs::read(&input)?;
            let (plaintext, manifest) =
                open_sealed(&blob, recipient_id.x25519_priv.as_ref(), None)?;
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
    }
    Ok(())
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
