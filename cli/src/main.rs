use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use jsonschema::JSONSchema;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

const ROOT_SCHEMA_RAW: &str = include_str!("../../schema.json");
const INGESTION_SCHEMA_RAW: &str = include_str!("../../ingestion.schema.json");
const TEMPLATE_RAW: &str = include_str!("../../template.moid.yaml");

#[derive(Parser)]
#[command(
    name = "moid",
    version,
    about = "Modulus IDentifier (MoID) manifest generator and cryptographic validator"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a starter moid.yaml manifest
    Init {
        /// Output file path
        #[arg(short, long, default_value = "moid.yaml")]
        output: PathBuf,

        /// Modulus paradigm (transformer, transformation_model, state_space, graph_network, neural_operator, hybrid)
        #[arg(short, long, default_value = "transformer")]
        modulus: String,

        /// Canonical identifier (e.g., org/model-name)
        #[arg(long, default_value = "organization/model-id")]
        id: String,
    },

    /// Compute streaming SHA-256 digests and emit a YAML checkpoints block
    Hash {
        /// One or more model weight/checkpoint files
        #[arg(required = true)]
        files: Vec<PathBuf>,

        /// Precision label to populate (e.g., bf16, fp16, fp32, int4)
        #[arg(short, long, default_value = "bf16")]
        precision: String,
    },

    /// Validate an ingestion_manifest.jsonl file and compute its seal hash
    Seal {
        /// Path to ingestion_manifest.jsonl
        #[arg(default_value = "ingestion_manifest.jsonl")]
        catalog: PathBuf,
    },

    /// Validate moid.yaml against schema.json and verify linked provenance hashes
    Validate {
        /// Path to moid.yaml
        #[arg(default_value = "moid.yaml")]
        manifest: PathBuf,

        /// Also recompute and verify SHA-256 hashes of local checkpoint files
        #[arg(long)]
        verify_weights: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            output,
            modulus,
            id,
        } => cmd_init(&output, &modulus, &id),
        Commands::Hash { files, precision } => cmd_hash(&files, &precision),
        Commands::Seal { catalog } => cmd_seal(&catalog),
        Commands::Validate {
            manifest,
            verify_weights,
        } => cmd_validate(&manifest, verify_weights),
    }
}

fn sha256_stream(path: &Path) -> Result<String> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open file for hashing: {}", path.display()))?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn cmd_init(output: &Path, modulus: &str, id: &str) -> Result<()> {
    if output.exists() {
        bail!("Refusing to overwrite existing file: {}", output.display());
    }

    let content = TEMPLATE_RAW
        .replace("modulus: \"transformer\"", &format!("modulus: \"{}\"", modulus))
        .replace("moid: \"holosacred/aether-moe-7b-v1\"", &format!("moid: \"{}\"", id))
        .replace("moid: \"organization/model-id\"", &format!("moid: \"{}\"", id));

    fs::write(output, content)
        .with_context(|| format!("Failed to write {}", output.display()))?;

    println!("Initialized {}", output.display());
    Ok(())
}

fn cmd_hash(files: &[PathBuf], precision: &str) -> Result<()> {
    println!("checkpoints:");
    for path in files {
        if !path.is_file() {
            bail!("Checkpoint file not found: {}", path.display());
        }
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("bin");
        let digest = sha256_stream(path)?;
        let normalized = path.to_string_lossy().replace('\\', "/");

        println!("  - path: \"{}\"", normalized);
        println!("    format: \"{}\"", ext);
        println!("    precision: \"{}\"", precision);
        println!("    quantization: \"none\"");
        println!("    sha256: \"{}\"", digest);
    }
    Ok(())
}

fn verify_jsonl_catalog(catalog_path: &Path) -> Result<(String, usize)> {
    let schema_val: Value = serde_json::from_str(INGESTION_SCHEMA_RAW)
        .context("Embedded ingestion.schema.json is invalid JSON")?;
    let compiled = JSONSchema::compile(&schema_val)
        .map_err(|e| anyhow::anyhow!("Failed to compile ingestion schema: {}", e))?;

    let digest = sha256_stream(catalog_path)?;
    let file = File::open(catalog_path)
        .with_context(|| format!("Failed to open catalog: {}", catalog_path.display()))?;
    let reader = BufReader::with_capacity(1024 * 1024, file);

    let mut record_count = 0usize;
    for (idx, line_res) in reader.lines().enumerate() {
        let line_num = idx + 1;
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let record: Value = serde_json::from_str(trimmed).with_context(|| {
            format!(
                "Invalid JSON on line {} of {}",
                line_num,
                catalog_path.display()
            )
        })?;

        if let Err(errors) = compiled.validate(&record) {
            let details: Vec<String> = errors
                .map(|e| format!("[{}] {}", e.instance_path, e))
                .collect();
            bail!(
                "Schema error on line {} of {}:\n  - {}",
                line_num,
                catalog_path.display(),
                details.join("\n  - ")
            );
        }
        record_count += 1;
    }

    Ok((digest, record_count))
}

fn cmd_seal(catalog: &Path) -> Result<()> {
    if !catalog.is_file() {
        bail!("Catalog file not found: {}", catalog.display());
    }

    let (digest, count) = verify_jsonl_catalog(catalog)?;
    println!("Verified {} records in {}", count, catalog.display());
    println!("\ndata_provenance:");
    println!(
        "  ingestion_catalog_file: \"{}\"",
        catalog.to_string_lossy().replace('\\', "/")
    );
    println!("  catalog_file_hash_sha256: \"{}\"", digest);
    Ok(())
}

fn cmd_validate(manifest_path: &Path, verify_weights: bool) -> Result<()> {
    if !manifest_path.is_file() {
        bail!("Manifest not found: {}", manifest_path.display());
    }

    let raw_yaml = fs::read_to_string(manifest_path)
        .with_context(|| format!("Failed to read {}", manifest_path.display()))?;
    let manifest_val: Value = serde_yaml::from_str(&raw_yaml)
        .with_context(|| format!("Failed to parse YAML in {}", manifest_path.display()))?;

    let root_schema: Value = serde_json::from_str(ROOT_SCHEMA_RAW)
        .context("Embedded schema.json is invalid JSON")?;
    let compiled = JSONSchema::compile(&root_schema)
        .map_err(|e| anyhow::anyhow!("Failed to compile root schema: {}", e))?;

    if let Err(errors) = compiled.validate(&manifest_val) {
        eprintln!("FAIL: {} failed schema validation:", manifest_path.display());
        for err in errors {
            let path = if err.instance_path.to_string().is_empty() {
                "<root>".to_string()
            } else {
                err.instance_path.to_string()
            };
            eprintln!("  - [{}] {}", path, err);
        }
        std::process::exit(1);
    }
    println!("OK: {} passed schema.json validation.", manifest_path.display());

    let base_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));

    if verify_weights {
        if let Some(checkpoints) = manifest_val.get("checkpoints").and_then(|v| v.as_array()) {
            for cp in checkpoints {
                let rel_path = cp.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let expected = cp.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
                let full_path = base_dir.join(rel_path);

                if !full_path.is_file() {
                    bail!("Missing local checkpoint file: {}", full_path.display());
                }
                let actual = sha256_stream(&full_path)?;
                if !actual.eq_ignore_ascii_case(expected) {
                    bail!(
                        "SHA-256 mismatch for {}:\n  Expected: {}\n  Actual:   {}",
                        rel_path,
                        expected,
                        actual
                    );
                }
                println!("OK: Checkpoint {} verified.", rel_path);
            }
        }
    }

    if let Some(prov) = manifest_val.get("data_provenance") {
        if let Some(cat_rel) = prov.get("ingestion_catalog_file").and_then(|v| v.as_str()) {
            let cat_path = base_dir.join(cat_rel);
            if cat_path.is_file() {
                let expected_hash = prov
                    .get("catalog_file_hash_sha256")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let (actual_hash, count) = verify_jsonl_catalog(&cat_path)?;

                if !actual_hash.eq_ignore_ascii_case(expected_hash) {
                    bail!(
                        "Ingestion catalog SHA-256 mismatch for {}:\n  Expected: {}\n  Actual:   {}",
                        cat_rel,
                        expected_hash,
                        actual_hash
                    );
                }
                println!(
                    "OK: {} verified ({} records, SHA-256 matched).",
                    cat_rel, count
                );
            }
        }
    }

    Ok(())
}
