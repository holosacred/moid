use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use jsonschema::JSONSchema;
use rayon::prelude::*;
use serde::Serialize;
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
    about = "Modulus IDentifier (MoID) manifest generator, inspector, and cryptographic validator"
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

        /// Stack role (generator, decision_policy, router, planner, verifier, critic_reward, world_model, perception_encoder, memory_indexer, orchestrator, hybrid)
        #[arg(short = 'r', long, default_value = "generator")]
        stack_role: String,

        /// Canonical identifier (e.g., org/model-name)
        #[arg(long, default_value = "organization/model-id")]
        id: String,
    },

    /// Compute parallel streaming SHA-256 digests (or parse SHA256SUMS) for checkpoints
    Hash {
        /// One or more model weight/checkpoint files
        #[arg(required_unless_present = "from_sha256sums")]
        files: Vec<PathBuf>,

        /// Parse an existing SHA256SUMS file instead of hashing local files
        #[arg(long)]
        from_sha256sums: Option<PathBuf>,

        /// Precision label to populate (e.g., bf16, fp16, fp32, int4)
        #[arg(short, long, default_value = "bf16")]
        precision: String,

        /// Quantization label to populate (e.g., none, awq_int4, gguf_q4_k_m)
        #[arg(short, long, default_value = "none")]
        quantization: String,

        /// Write/update the checkpoints block directly inside an existing moid.yaml
        #[arg(short, long)]
        write: Option<PathBuf>,
    },

    /// Validate an ingestion_manifest.jsonl file and compute its seal hash
    Seal {
        /// Path to ingestion_manifest.jsonl
        #[arg(default_value = "ingestion_manifest.jsonl")]
        catalog: PathBuf,

        /// Write/update data_provenance directly inside an existing moid.yaml
        #[arg(short, long)]
        write: Option<PathBuf>,
    },

    /// Validate moid.yaml against schema.json and verify linked provenance hashes
    Validate {
        /// Path to moid.yaml
        #[arg(default_value = "moid.yaml")]
        manifest: PathBuf,

        /// Also recompute and verify SHA-256 hashes of local checkpoint files in parallel
        #[arg(long)]
        verify_weights: bool,
    },

    /// Print a human-readable summary card for a moid.yaml manifest
    Inspect {
        /// Path to moid.yaml
        #[arg(default_value = "moid.yaml")]
        manifest: PathBuf,
    },

    /// Compare two moid.yaml manifests and highlight changes
    Diff {
        /// Path to older moid.yaml
        old_manifest: PathBuf,

        /// Path to newer moid.yaml
        new_manifest: PathBuf,
    },
}

#[derive(Serialize)]
struct CheckpointEntry {
    path: String,
    format: String,
    precision: String,
    quantization: String,
    sha256: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            output,
            modulus,
            stack_role,
            id,
        } => cmd_init(&output, &modulus, &stack_role, &id),
        Commands::Hash {
            files,
            from_sha256sums,
            precision,
            quantization,
            write,
        } => cmd_hash(
            &files,
            from_sha256sums.as_deref(),
            &precision,
            &quantization,
            write.as_deref(),
        ),
        Commands::Seal { catalog, write } => cmd_seal(&catalog, write.as_deref()),
        Commands::Validate {
            manifest,
            verify_weights,
        } => cmd_validate(&manifest, verify_weights),
        Commands::Inspect { manifest } => cmd_inspect(&manifest),
        Commands::Diff {
            old_manifest,
            new_manifest,
        } => cmd_diff(&old_manifest, &new_manifest),
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

fn cmd_init(output: &Path, modulus: &str, stack_role: &str, id: &str) -> Result<()> {
    if output.exists() {
        bail!("Refusing to overwrite existing file: {}", output.display());
    }

    let content = TEMPLATE_RAW
        .replace(
            "modulus: \"transformer\"",
            &format!("modulus: \"{}\"", modulus),
        )
        .replace(
            "stack_role: \"generator\"",
            &format!("stack_role: \"{}\"", stack_role),
        )
        .replace(
            "moid: \"holosacred/aether-moe-7b-v1\"",
            &format!("moid: \"{}\"", id),
        )
        .replace(
            "moid: \"organization/model-id\"",
            &format!("moid: \"{}\"", id),
        );

    fs::write(output, content)
        .with_context(|| format!("Failed to write {}", output.display()))?;

    println!("Initialized {}", output.display());
    Ok(())
}

fn parse_sha256sums(
    sums_path: &Path,
    precision: &str,
    quantization: &str,
) -> Result<Vec<CheckpointEntry>> {
    let raw = fs::read_to_string(sums_path)
        .with_context(|| format!("Failed to read {}", sums_path.display()))?;
    let mut entries = Vec::new();

    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (hash_part, file_part) = trimmed.split_once(char::is_whitespace).with_context(|| {
            format!("Malformed SHA256SUMS entry on line {}", idx + 1)
        })?;
        let digest = hash_part.trim().to_lowercase();
        if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("Invalid SHA-256 digest on line {}", idx + 1);
        }
        let cleaned_path = file_part
            .trim()
            .trim_start_matches('*')
            .trim_start_matches("./")
            .replace('\\', "/");
        let ext = Path::new(&cleaned_path)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("bin")
            .to_string();

        entries.push(CheckpointEntry {
            path: cleaned_path,
            format: ext,
            precision: precision.to_string(),
            quantization: quantization.to_string(),
            sha256: digest,
        });
    }

    if entries.is_empty() {
        bail!("No valid entries found in {}", sums_path.display());
    }
    Ok(entries)
}

fn cmd_hash(
    files: &[PathBuf],
    from_sha256sums: Option<&Path>,
    precision: &str,
    quantization: &str,
    write_target: Option<&Path>,
) -> Result<()> {
    let entries: Vec<CheckpointEntry> = if let Some(sums_path) = from_sha256sums {
        parse_sha256sums(sums_path, precision, quantization)?
    } else {
        files
            .par_iter()
            .map(|path| -> Result<CheckpointEntry> {
                if !path.is_file() {
                    bail!("Checkpoint file not found: {}", path.display());
                }
                let ext = path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("bin")
                    .to_string();
                let digest = sha256_stream(path)?;
                let normalized = path.to_string_lossy().replace('\\', "/");
                Ok(CheckpointEntry {
                    path: normalized,
                    format: ext,
                    precision: precision.to_string(),
                    quantization: quantization.to_string(),
                    sha256: digest,
                })
            })
            .collect::<Result<Vec<_>>>()?
    };

    if let Some(target_path) = write_target {
        let raw_yaml = fs::read_to_string(target_path)
            .with_context(|| format!("Failed to read {}", target_path.display()))?;
        let mut doc: serde_yaml::Value = serde_yaml::from_str(&raw_yaml)
            .with_context(|| format!("Failed to parse YAML in {}", target_path.display()))?;
        let map = doc
            .as_mapping_mut()
            .context("Root of target manifest must be a YAML mapping")?;
        let cp_val = serde_yaml::to_value(&entries)?;
        map.insert(
            serde_yaml::Value::String("checkpoints".to_string()),
            cp_val,
        );
        fs::write(target_path, serde_yaml::to_string(&doc)?)
            .with_context(|| format!("Failed to write {}", target_path.display()))?;
        println!(
            "Updated checkpoints in {} ({} entries).",
            target_path.display(),
            entries.len()
        );
    } else {
        println!("checkpoints:");
        for entry in &entries {
            println!("  - path: \"{}\"", entry.path);
            println!("    format: \"{}\"", entry.format);
            println!("    precision: \"{}\"", entry.precision);
            println!("    quantization: \"{}\"", entry.quantization);
            println!("    sha256: \"{}\"", entry.sha256);
        }
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

fn cmd_seal(catalog: &Path, write_target: Option<&Path>) -> Result<()> {
    if !catalog.is_file() {
        bail!("Catalog file not found: {}", catalog.display());
    }

    let (digest, count) = verify_jsonl_catalog(catalog)?;
    let normalized_cat = catalog.to_string_lossy().replace('\\', "/");

    if let Some(target_path) = write_target {
        let raw_yaml = fs::read_to_string(target_path)
            .with_context(|| format!("Failed to read {}", target_path.display()))?;
        let mut doc: serde_yaml::Value = serde_yaml::from_str(&raw_yaml)
            .with_context(|| format!("Failed to parse YAML in {}", target_path.display()))?;
        let root_map = doc
            .as_mapping_mut()
            .context("Root of target manifest must be a YAML mapping")?;
        let prov_key = serde_yaml::Value::String("data_provenance".to_string());
        if !root_map.contains_key(&prov_key) {
            root_map.insert(
                prov_key.clone(),
                serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            );
        }
        let prov_map = root_map
            .get_mut(&prov_key)
            .and_then(|v| v.as_mapping_mut())
            .context("data_provenance must be a YAML mapping")?;
        prov_map.insert(
            serde_yaml::Value::String("ingestion_catalog_file".to_string()),
            serde_yaml::Value::String(normalized_cat),
        );
        prov_map.insert(
            serde_yaml::Value::String("catalog_file_hash_sha256".to_string()),
            serde_yaml::Value::String(digest),
        );
        fs::write(target_path, serde_yaml::to_string(&doc)?)
            .with_context(|| format!("Failed to write {}", target_path.display()))?;
        println!(
            "Updated data_provenance in {} ({} records sealed).",
            target_path.display(),
            count
        );
    } else {
        println!("Verified {} records in {}", count, catalog.display());
        println!("\ndata_provenance:");
        println!("  ingestion_catalog_file: \"{}\"", normalized_cat);
        println!("  catalog_file_hash_sha256: \"{}\"", digest);
    }

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
    println!(
        "OK: {} passed schema.json validation.",
        manifest_path.display()
    );

    let base_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));

    if verify_weights {
        if let Some(checkpoints) = manifest_val.get("checkpoints").and_then(|v| v.as_array()) {
            let items: Vec<(String, String)> = checkpoints
                .iter()
                .map(|cp| {
                    let rel = cp
                        .get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let exp = cp
                        .get("sha256")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    (rel, exp)
                })
                .collect();

            items
                .par_iter()
                .try_for_each(|(rel_path, expected)| -> Result<()> {
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
                    Ok(())
                })?;
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

fn cmd_inspect(manifest_path: &Path) -> Result<()> {
    let raw_yaml = fs::read_to_string(manifest_path)
        .with_context(|| format!("Failed to read {}", manifest_path.display()))?;
    let v: Value = serde_yaml::from_str(&raw_yaml)
        .with_context(|| format!("Failed to parse YAML in {}", manifest_path.display()))?;

    let moid = v["moid"].as_str().unwrap_or("<unknown>");
    let name = v["model_name"]
        .as_str()
        .or_else(|| v["transformation_name"].as_str())
        .unwrap_or("<unnamed>");
    let modulus = v["modulus"].as_str().unwrap_or("<unknown>");
    let role = v["stack_role"].as_str().unwrap_or("<unspecified>");
    let primary_domain = v["domain_focus"]["primary"].as_str().unwrap_or("<none>");
    let tier = v["licensing"]["tier"].as_str().unwrap_or("<unknown>");
    let spdx = v["licensing"]["spdx_license"].as_str().unwrap_or("<unknown>");
    let open_w = v["access_control"]["open_weights"].as_bool().unwrap_or(false);
    let open_c = v["access_control"]["open_code"].as_bool().unwrap_or(false);
    let open_d = v["access_control"]["open_data"].as_bool().unwrap_or(false);
    let total_p = v["parameters"]["total_count"].as_u64().unwrap_or(0);
    let active_p = v["parameters"]["active_count"].as_u64().unwrap_or(total_p);
    let precision = v["parameters"]["base_precision"].as_str().unwrap_or("?");
    let cp_count = v["checkpoints"].as_array().map(|a| a.len()).unwrap_or(0);
    let distilled = v["distillation"]["is_distilled"].as_bool().unwrap_or(false);
    let upstream = v["stack_spec"]["upstream_moids"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    let downstream = v["stack_spec"]["downstream_moids"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    let catalog = v["data_provenance"]["ingestion_catalog_file"]
        .as_str()
        .unwrap_or("<none>");

    println!("MoID:         {}", moid);
    println!("Name:         {}", name);
    println!(
        "Architecture: {} | Role: {} | Focus: {}",
        modulus, role, primary_domain
    );
    println!(
        "License:      {} ({}) | Open: weights={}, code={}, data={}",
        tier, spdx, open_w, open_c, open_d
    );
    println!(
        "Parameters:   {} total / {} active ({})",
        total_p, active_p, precision
    );
    if open_w {
        println!("Checkpoints:  {} file(s)", cp_count);
    } else {
        let provider = v["endpoint"]["provider"].as_str().unwrap_or("API");
        println!("Endpoint:     {} (closed weights)", provider);
    }
    println!("Distilled:    {}", distilled);
    println!(
        "Stack Links:  upstream={}, downstream={}",
        upstream, downstream
    );
    println!("Provenance:   {}", catalog);
    Ok(())
}

fn cmd_diff(old_path: &Path, new_path: &Path) -> Result<()> {
    let old_v: Value = serde_yaml::from_str(&fs::read_to_string(old_path)?)?;
    let new_v: Value = serde_yaml::from_str(&fs::read_to_string(new_path)?)?;

    let fields: [(&str, &[&str]); 10] = [
        ("moid", &["moid"]),
        ("version", &["version"]),
        ("modulus", &["modulus"]),
        ("stack_role", &["stack_role"]),
        ("licensing.tier", &["licensing", "tier"]),
        ("licensing.spdx_license", &["licensing", "spdx_license"]),
        ("parameters.total_count", &["parameters", "total_count"]),
        ("parameters.active_count", &["parameters", "active_count"]),
        (
            "distillation.is_distilled",
            &["distillation", "is_distilled"],
        ),
        (
            "data_provenance.catalog_file_hash_sha256",
            &["data_provenance", "catalog_file_hash_sha256"],
        ),
    ];

    let mut diffs = 0usize;
    for (label, path) in fields {
        let a = path.iter().fold(&old_v, |acc, k| &acc[*k]);
        let b = path.iter().fold(&new_v, |acc, k| &acc[*k]);
        if a != b {
            println!("~ {}: {} -> {}", label, a, b);
            diffs += 1;
        }
    }

    if diffs == 0 {
        println!("No differences detected across tracked MoID fields.");
    }
    Ok(())
}
