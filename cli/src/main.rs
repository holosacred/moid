use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use jsonschema::{Registry, Resource, Validator};
use rayon::prelude::*;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

const COMMON_SCHEMA_RAW: &str = include_str!("../../schemas/v0.3.0-rc8/common.schema.json");
const MOID_SCHEMA_RAW: &str = include_str!("../../schemas/v0.3.0-rc8/moid.schema.json");
const INGESTION_SCHEMA_RAW: &str = include_str!("../../schemas/v0.3.0-rc8/ingestion.schema.json");
const PUBLISHER_SCHEMA_RAW: &str = include_str!("../../schemas/v0.3.0-rc8/publisher.schema.json");
const TEMPLATE_RAW: &str = include_str!("../../template.moid.yaml");

const COMMON_ID: &str = "https://moid.info/schemas/v0.3.0-rc8/common.schema.json";
const DISCLOSURE_SECTIONS: [&str; 6] = [
    "modulus", "domain_focus", "parameters", "lineage", "licensing", "data_provenance",
];
const EMPTY_HASHES: [&str; 2] = [
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
];
const OSI_ALLOWLIST: [&str; 9] = [
    "Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "GPL-3.0-only",
    "GPL-3.0-or-later", "LGPL-3.0-only", "MPL-2.0", "ISC",
];
const DOC_ALLOWLIST: [&str; 3] = ["CC-BY-4.0", "CC-BY-SA-4.0", "CC0-1.0"];

#[derive(Parser)]
#[command(name = "moid", version, about = "MoID (moid.info) manifest validator, hasher, and inspector")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(short, long, default_value = "moid.yaml")]
        output: PathBuf,
        #[arg(long, default_value = "organization/model-slug")]
        id: String,
    },
    Hash {
        files: Vec<PathBuf>,
        #[arg(short, long, default_value = "bf16")]
        precision: String,
        #[arg(long, default_value = "full_weights")]
        kind: String,
    },
    Seal {
        #[arg(default_value = "ingestion_manifest.jsonl")]
        catalog: PathBuf,
        #[arg(long)]
        non_draft: bool,
    },
    Validate {
        #[arg(default_value = "moid.yaml")]
        manifest: PathBuf,
        #[arg(long)]
        verify_files: bool,
        #[arg(long)]
        verify_catalog: bool,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        schema_only: bool,
    },
    ValidatePublisher {
        #[arg(default_value = "moid-publisher.json")]
        binding: PathBuf,
        #[arg(long)]
        serial_state: Option<PathBuf>,
        #[arg(long)]
        backlink_file: Option<PathBuf>,
        #[arg(long)]
        default_branch: Option<String>,
        #[arg(long)]
        dns_txt_file: Option<PathBuf>,
        #[arg(long)]
        continuity_signer: Option<String>,
        #[arg(long)]
        fail_on_continuity_break: bool,
        #[arg(long)]
        schema_only: bool,
    },
    Inspect {
        #[arg(default_value = "moid.yaml")]
        manifest: PathBuf,
        #[arg(long)]
        verify_files: bool,
    },
    Diff {
        old_manifest: PathBuf,
        new_manifest: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Init { output, id } => cmd_init(&output, &id),
        Commands::Hash { files, precision, kind } => cmd_hash(&files, &precision, &kind),
        Commands::Seal { catalog, non_draft } => cmd_seal(&catalog, non_draft),
        Commands::Validate { manifest, verify_files, verify_catalog, strict, schema_only } => {
            cmd_validate(&manifest, verify_files, verify_catalog, strict, schema_only)
        }
        Commands::ValidatePublisher { binding, serial_state, backlink_file, default_branch, dns_txt_file, continuity_signer, fail_on_continuity_break, schema_only } => cmd_validate_publisher(&binding, serial_state.as_deref(), backlink_file.as_deref(), default_branch.as_deref(), dns_txt_file.as_deref(), continuity_signer.as_deref(), fail_on_continuity_break, schema_only),
        Commands::Inspect { manifest, verify_files } => cmd_inspect(&manifest, verify_files),
        Commands::Diff { old_manifest, new_manifest } => cmd_diff(&old_manifest, &new_manifest),
    }
}

fn build_validator(root_raw: &str) -> Result<Validator> {
    let common_val: Value = serde_json::from_str(COMMON_SCHEMA_RAW)?;
    let root_val: Value = serde_json::from_str(root_raw)?;
    let registry = Registry::new()
        .add(COMMON_ID, Resource::from_contents(common_val))
        .map_err(|e| anyhow::anyhow!("Registry add error: {}", e))?
        .prepare()
        .map_err(|e| anyhow::anyhow!("Registry prepare error: {}", e))?;
    jsonschema::draft202012::options()
        .with_registry(&registry)
        .offline()
        .should_validate_formats(true)
        .build(&root_val)
        .map_err(|e| anyhow::anyhow!("Schema build error: {}", e))
}

fn parse_yaml_12(path: &Path) -> Result<Value> {
    let raw = fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let yv: serde_yaml::Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse YAML in {}", path.display()))?;
    check_yaml_safety(&yv)?;
    Ok(serde_json::to_value(yv)?)
}

fn check_yaml_safety(v: &serde_yaml::Value) -> Result<()> {
    match v {
        serde_yaml::Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    bail!("SCHEMA-01: Non-finite float (NaN/Inf) not allowed");
                }
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq { check_yaml_safety(item)?; }
        }
        serde_yaml::Value::Mapping(map) => {
            for (_, val) in map { check_yaml_safety(val)?; }
        }
        _ => {}
    }
    Ok(())
}

fn canonical_json_bytes(v: &Value) -> Vec<u8> {
    fn sort_val(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut sorted = Map::new();
                for k in keys { sorted.insert(k.clone(), sort_val(&map[k])); }
                Value::Object(sorted)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(sort_val).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_vec(&sort_val(v)).unwrap_or_default()
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{}", hex::encode(h.finalize()))
}

fn sha256_stream(path: &Path) -> Result<(String, u64)> {
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((format!("sha256:{}", hex::encode(hasher.finalize())), total))
}

fn cmd_init(output: &Path, id: &str) -> Result<()> {
    if output.exists() { bail!("Refusing to overwrite {}", output.display()); }
    let ns = id.split('/').next().unwrap_or("organization");
    let content = TEMPLATE_RAW
        .replace("holosacred/arbiter-nano-hybrid", id)
        .replace("namespace: \"holosacred\"", &format!("namespace: \"{}\"", ns));
    fs::write(output, content)?;
    println!("Initialized {}", output.display());
    Ok(())
}

fn cmd_hash(files: &[PathBuf], precision: &str, kind: &str) -> Result<()> {
    if files.is_empty() { bail!("Provide at least one checkpoint file."); }
    let results: Vec<(String, String, String, u64)> = files
        .par_iter()
        .map(|p| -> Result<_> {
            let (digest, size) = sha256_stream(p)?;
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("other").to_string();
            Ok((p.to_string_lossy().replace('\\', "/"), ext, digest, size))
        })
        .collect::<Result<Vec<_>>>()?;

    println!("checkpoints:");
    println!("  - id: \"primary\"");
    println!("    artifact_kind: \"{}\"", kind);
    println!("    format: \"{}\"", results[0].1);
    println!("    precision: \"{}\"", precision);
    println!("    files:");
    for (p, _, d, sz) in results {
        println!("      - path: \"{}\"\n        digest: \"{}\"\n        byte_size: {}", p, d, sz);
    }
    Ok(())
}

fn validate_catalog_file(catalog_path: &Path, non_draft: bool) -> Result<(String, HashMap<String, Value>, HashSet<String>)> {
    let validator = build_validator(INGESTION_SCHEMA_RAW)?;
    let (digest, _) = sha256_stream(catalog_path)?;
    let file = File::open(catalog_path).with_context(|| format!("Failed to open {}", catalog_path.display()))?;
    let mut records: HashMap<String, Value> = HashMap::new();
    let mut parents: HashSet<String> = HashSet::new();
    let mut top_levels: HashSet<String> = HashSet::new();

    for (idx, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() { continue; }
        let rec: Value = serde_json::from_str(t)
            .with_context(|| format!("CAT-01: Invalid JSON on line {}", idx + 1))?;
        let errs: Vec<String> = validator.iter_errors(&rec).map(|e| format!("path={} msg={}", e.instance_path(), e)).collect();
        if !errs.is_empty() {
            bail!("CAT-01: Schema error on line {}:\n  - {}", idx + 1, errs.join("\n  - "));
        }
        let id = rec["record_id"].as_str().unwrap().to_string();
        if records.contains_key(&id) { bail!("CAT-01: Duplicate record_id '{}'", id); }
        if let Some(pid) = rec.get("parent_record_id").and_then(|v| v.as_str()) {
            parents.insert(pid.to_string());
        } else {
            top_levels.insert(rec["record_level"].as_str().unwrap().to_string());
        }
        if non_draft {
            if let Some(d) = rec.get("digest").and_then(|v| v.as_str()) {
                if d.starts_with("placeholder:") { bail!("CAT-01: Placeholder digest in non-draft record '{}'", id); }
            }
        }
        records.insert(id, rec);
    }

    if top_levels.len() > 1 {
        bail!("CAT-01: Unlinked mixed record_levels ({:?}) without parent_record_id", top_levels);
    }
    for (id, rec) in &records {
        if let Some(pid) = rec.get("parent_record_id").and_then(|v| v.as_str()) {
            if !records.contains_key(pid) { bail!("CAT-01: Record '{}' references missing parent '{}'", id, pid); }
            let mut cur = pid;
            let mut seen = HashSet::from([id.as_str()]);
            while let Some(next_p) = records.get(cur).and_then(|r| r.get("parent_record_id")).and_then(|v| v.as_str()) {
                if !seen.insert(cur) { bail!("CAT-01: Cycle in parent_record_id at '{}'", cur); }
                cur = next_p;
            }
        }
        let is_non_leaf = parents.contains(id);
        if is_non_leaf && rec.get("digest").is_some() {
            bail!("CAT-01: Non-leaf parent record '{}' MUST NOT carry a digest", id);
        }
        if !is_non_leaf && non_draft && rec.get("digest").is_none() {
            bail!("CAT-01: Leaf record '{}' requires digest in non-draft catalog", id);
        }
    }
    Ok((digest, records, parents))
}

fn cmd_seal(catalog: &Path, non_draft: bool) -> Result<()> {
    let (digest, records, parents) = validate_catalog_file(catalog, non_draft)?;
    let leaves = records.len().saturating_sub(parents.len());
    println!("OK: {} verified ({} records, {} leaves).", catalog.display(), records.len(), leaves);
    println!("digest: \"{}\"", digest);
    Ok(())
}

fn parse_rfc3339_epoch(s: &str) -> Result<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b't') || b[13] != b':' || b[16] != b':' {
        bail!("Invalid RFC 3339 timestamp '{}'", s);
    }
    let y: i64 = s[0..4].parse()?;
    let m: i64 = s[5..7].parse()?;
    let d: i64 = s[8..10].parse()?;
    let hh: i64 = s[11..13].parse()?;
    let mm: i64 = s[14..16].parse()?;
    let ss: i64 = s[17..19].parse()?;
    let mut idx = 19;
    if idx < b.len() && b[idx] == b'.' {
        idx += 1;
        while idx < b.len() && b[idx].is_ascii_digit() { idx += 1; }
    }
    let offset_sec: i64 = if idx < b.len() && (b[idx] == b'Z' || b[idx] == b'z') {
        0
    } else if idx + 6 == b.len() && (b[idx] == b'+' || b[idx] == b'-') && b[idx + 3] == b':' {
        let sign = if b[idx] == b'+' { 1 } else { -1 };
        let oh: i64 = s[idx + 1..idx + 3].parse()?;
        let om: i64 = s[idx + 4..idx + 6].parse()?;
        sign * (oh * 3600 + om * 60)
    } else {
        bail!("Invalid RFC 3339 timezone in '{}'", s);
    };
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Ok(days * 86400 + hh * 3600 + mm * 60 + ss - offset_sec)
}

fn identity_key_id(id: &Value) -> String {
    match id["kind"].as_str().unwrap_or("") {
        "pgp" => id["fingerprint"].as_str().unwrap_or("").to_ascii_uppercase(),
        "ssh" => id["fingerprint"].as_str().unwrap_or("").to_string(),
        "minisign" => id["public_key"].as_str().unwrap_or("").to_string(),
        "key" => id["key_fingerprint"].as_str().unwrap_or("").to_string(),
        "oidc" => id["subject"].as_str().unwrap_or("").to_string(),
        _ => String::new(),
    }
}

fn extract_proof_blob_rest<'a>(plat: &str, uri: &'a str) -> Option<&'a str> {
    let marker = match plat {
        "github" | "huggingface" => "/blob/",
        "gitlab" => "/-/blob/",
        "codeberg" => "/src/branch/",
        _ => return None,
    };
    uri.split_once(marker).map(|(_, rest)| rest)
}

fn is_hex_sha(seg: &str) -> bool {
    (seg.len() == 40 || seg.len() == 64) && seg.bytes().all(|b| b.is_ascii_hexdigit())
}

#[allow(clippy::too_many_arguments)]
fn cmd_validate_publisher(
    binding: &Path,
    serial_state: Option<&Path>,
    backlink_file: Option<&Path>,
    default_branch: Option<&str>,
    dns_txt_file: Option<&Path>,
    continuity_signer: Option<&str>,
    fail_on_continuity_break: bool,
    schema_only: bool,
) -> Result<()> {
    let validator = build_validator(PUBLISHER_SCHEMA_RAW)?;
    let val: Value = serde_json::from_str(&fs::read_to_string(binding)?)?;
    let errs: Vec<String> = validator.iter_errors(&val).map(|e| format!("path={} msg={}", e.instance_path(), e)).collect();
    if !errs.is_empty() {
        bail!("FAIL [SCHEMA-01]: {} failed publisher.schema.json:\n  - {}", binding.display(), errs.join("\n  - "));
    }
    if schema_only {
        println!("OK [SCHEMA-01]: {} passed publisher.schema.json.", binding.display());
        return Ok(());
    }
    let updated_s = val["updated_at"].as_str().unwrap_or("");
    let expires_s = val["expires_at"].as_str().unwrap_or("");
    let updated_ts = parse_rfc3339_epoch(updated_s)?;
    let expires_ts = parse_rfc3339_epoch(expires_s)?;
    if expires_ts <= updated_ts {
        bail!("FAIL [PUB-01]: expires_at ({}) must be strictly after updated_at ({})", expires_s, updated_s);
    }
    if expires_ts - updated_ts > 365 * 86400 {
        bail!("FAIL [PUB-01]: binding lifetime exceeds maximum 365 days ({} -> {})", updated_s, expires_s);
    }
    let ns = val["namespace"].as_str().unwrap_or("");
    let dom = val["domain"].as_str().unwrap_or("");
    let mode = val.pointer("/namespace_claim/mode").and_then(|v| v.as_str()).unwrap_or("");
    if mode == "domain_exact" && ns != dom {
        bail!("FAIL [PUB-01]: domain_exact claim requires namespace '{}' == domain '{}'", ns, dom);
    }
    if mode == "platform_bidirectional" {
        let plat = val.pointer("/namespace_claim/platform").and_then(|v| v.as_str()).unwrap_or("");
        let acct = val.pointer("/namespace_claim/platform_account").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        if acct != ns.to_ascii_lowercase() {
            bail!("FAIL [PUB-01]: platform_account '{}' must match namespace '{}' (case-insensitive)", acct, ns);
        }
        let uri_raw = val.pointer("/namespace_claim/platform_proof_uri").and_then(|v| v.as_str()).unwrap_or("");
        let uri_lower = uri_raw.to_ascii_lowercase();
        let prefix = match plat {
            "github" => "https://github.com/",
            "huggingface" => "https://huggingface.co/",
            "gitlab" => "https://gitlab.com/",
            "codeberg" => "https://codeberg.org/",
            _ => bail!("FAIL [PUB-01]: unsupported platform '{}'", plat),
        };
        let rest_acct = uri_lower.strip_prefix(prefix).unwrap_or("");
        let ok_acct = rest_acct == acct || rest_acct.starts_with(&format!("{}/", acct));
        if !ok_acct {
            bail!("FAIL [PUB-01]: platform_proof_uri '{}' does not match platform_account '{}'", uri_raw, acct);
        }
        if let Some(blob_rest) = extract_proof_blob_rest(plat, uri_raw) {
            let first_seg = blob_rest.split('/').next().unwrap_or("");
            if is_hex_sha(first_seg) {
                bail!("FAIL [NET-05]: commit SHA ref '{}' forbidden; proof URI must target the default branch name", first_seg);
            }
            if let Some(def_br) = default_branch {
                if !blob_rest.starts_with(&format!("{}/", def_br)) {
                    bail!("FAIL [NET-05]: proof URI ref in '{}' does not match repository default branch '{}'", uri_raw, def_br);
                }
                println!("OK [NET-05]: proof URI matches default branch '{}'.", def_br);
            }
        }
        if let Some(bf) = backlink_file {
            let body = fs::read_to_string(bf)?.to_ascii_lowercase();
            let needle_well_known = format!("https://{}/.well-known/moid-publisher.json", dom.to_ascii_lowercase());
            let needle_root = format!("https://{}", dom.to_ascii_lowercase());
            if !body.contains(&needle_well_known) && !body.contains(&needle_root) {
                bail!("FAIL [NET-05]: platform profile at '{}' lacks back-link to '{}'", uri_raw, needle_root);
            }
            println!("OK [NET-05]: platform back-link to '{}' verified.", dom);
        }
    }
    let allowed: HashSet<Vec<u8>> = val["allowed_identities"]
        .as_array().map(|a| a.iter().map(canonical_json_bytes).collect()).unwrap_or_default();
    let mut compromised_ids: HashSet<String> = HashSet::new();
    if let Some(revs) = val.get("revoked_identities").and_then(|v| v.as_array()) {
        for r in revs {
            if allowed.contains(&canonical_json_bytes(&r["identity"])) {
                bail!("FAIL [PUB-01]: identity appears in both allowed_identities and revoked_identities");
            }
            if r.get("reason").and_then(|v| v.as_str()) == Some("key_compromise") {
                compromised_ids.insert(identity_key_id(&r["identity"]));
            }
        }
    }
    if let Some(anchor) = val.get("dns_txt_anchor").and_then(|v| v.as_str()) {
        let expected_anchor = format!("_moid.{}", dom.to_ascii_lowercase());
        if anchor.to_ascii_lowercase() != expected_anchor {
            bail!("FAIL [PUB-01]: dns_txt_anchor '{}' must equal '{}'", anchor, expected_anchor);
        }
    }
    let jcs = sha256_bytes(&canonical_json_bytes(&val));
    if let Some(txt_path) = dns_txt_file {
        let txt = fs::read_to_string(txt_path)?;
        let expected_kv = format!("jcs={}", jcs);
        let matched = txt.lines().any(|l| l.contains("v=moid1;") && l.contains(&expected_kv));
        if !matched {
            bail!("FAIL [NET-06]: DNS TXT record at '{}' does not anchor 'v=moid1; {}'", txt_path.display(), expected_kv);
        }
        println!("OK [NET-06]: DNS TXT anchor verified ({}).", expected_kv);
    }
    let serial = val["serial"].as_u64().unwrap_or(0);
    if let Some(state_path) = serial_state {
        let mut state: Map<String, Value> = if state_path.exists() {
            serde_json::from_str(&fs::read_to_string(state_path)?)?
        } else {
            Map::new()
        };
        if let Some(prev) = state.get(ns) {
            let prev_serial = prev["serial"].as_u64().unwrap_or(0);
            let prev_jcs = prev["jcs_digest"].as_str().unwrap_or("");
            if serial < prev_serial {
                bail!("FAIL [PUB-01]: serial rollback for '{}' (got {}, highest seen {})", ns, serial, prev_serial);
            }
            if serial == prev_serial && jcs != prev_jcs {
                bail!("FAIL [PUB-01]: serial equivocation for '{}' (serial {} seen with different digest)", ns, serial);
            }
            if serial > prev_serial {
                let prev_ids: HashSet<String> = prev.get("allowed_identities")
                    .and_then(|a| a.as_array())
                    .map(|arr| arr.iter().map(identity_key_id).collect())
                    .unwrap_or_default();
                let mut continuity_ok = false;
                let mut reason = format!(
                    "serial advanced ({} -> {}) for '{}' without a verified continuity signature from prior allowed_identities",
                    prev_serial, serial, ns
                );
                if let Some(signer) = continuity_signer {
                    let norm_signer = if signer.len() == 40 || signer.len() == 64 {
                        signer.to_ascii_uppercase()
                    } else {
                        signer.to_string()
                    };
                    if compromised_ids.contains(&norm_signer) {
                        reason = format!("continuity signer '{}' was revoked for key_compromise and cannot authorize rotation", signer);
                    } else if prev_ids.contains(&norm_signer) {
                        continuity_ok = true;
                        println!("OK [PUB-01]: key continuity verified via prior identity '{}'.", signer);
                    } else {
                        reason = format!("continuity signer '{}' is not in prior binding's allowed_identities", signer);
                    }
                }
                if !continuity_ok {
                    eprintln!("WARN [CONTINUITY_BREAK]: {}", reason);
                    if fail_on_continuity_break {
                        bail!("FAIL [CONTINUITY_BREAK]: {}", reason);
                    }
                }
            }
        }
        let mut entry = Map::new();
        entry.insert("serial".into(), Value::from(serial));
        entry.insert("jcs_digest".into(), Value::from(jcs.clone()));
        entry.insert("allowed_identities".into(), val["allowed_identities"].clone());
        state.insert(ns.to_string(), Value::Object(entry));
        fs::write(state_path, serde_json::to_string_pretty(&Value::Object(state))?)?;
    }
    println!("OK [PUB-01]: {} passed publisher.schema.json (serial={}, jcs={}).", binding.display(), serial, jcs);
    Ok(())
}

fn collect_digests(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) if s.starts_with("sha256:") || s.starts_with("blake3:") => out.push(s.clone()),
        Value::Array(a) => for i in a { collect_digests(i, out); },
        Value::Object(m) => for (_, val) in m { collect_digests(val, out); },
        _ => {}
    }
}

fn cmd_validate(manifest_path: &Path, verify_files: bool, verify_catalog: bool, strict: bool, schema_only: bool) -> Result<()> {
    let v = parse_yaml_12(manifest_path)?;
    let validator = build_validator(MOID_SCHEMA_RAW)?;
    let errs: Vec<String> = validator.iter_errors(&v).map(|e| format!("path={} msg={}", e.instance_path(), e)).collect();
    if !errs.is_empty() {
        bail!("FAIL [SCHEMA-01]: {}:\n  - {}", manifest_path.display(), errs.join("\n  - "));
    }
    println!("OK [SCHEMA-01]: {} passed moid.schema.json (Draft 2020-12).", manifest_path.display());
    if schema_only { return Ok(()); }

    let mut warnings: Vec<String> = Vec::new();
    let status = v["manifest_status"].as_str().unwrap_or("draft");
    let non_draft = status != "draft";

    let moid = v["moid"].as_str().unwrap_or("");
    let ns = v["publisher"]["namespace"].as_str().unwrap_or("");
    if moid.split('/').next() != Some(ns) {
        bail!("FAIL [ID-01]: moid prefix '{}' != publisher.namespace '{}'", moid, ns);
    }

    if let Some(moe) = v.pointer("/modulus/moe_spec") {
        if moe["active_experts_per_token"].as_u64() > moe["num_experts"].as_u64() {
            bail!("FAIL [ARCH-01]: active_experts_per_token exceeds num_experts");
        }
    }

    if let (Some(prim), Some(weights)) = (
        v.pointer("/domain_focus/primary").and_then(|x| x.as_str()),
        v.pointer("/domain_focus/focus_weights").and_then(|x| x.as_object()),
    ) {
        if !weights.contains_key(prim) {
            bail!("FAIL [FOCUS-01]: domain_focus.primary '{}' not in focus_weights keys", prim);
        }
    }

    let mut digests = Vec::new();
    collect_digests(&v, &mut digests);
    for d in &digests {
        if EMPTY_HASHES.contains(&d.as_str()) {
            if non_draft { bail!("FAIL [HYGIENE-01]: empty-input digest '{}' forbidden in {}", d, status); }
            warnings.push(format!("WARN [HYGIENE-01]: empty-input digest '{}'", d));
        }
    }

    let cp_ids: HashSet<String> = v.get("checkpoints").and_then(|c| c.as_array())
        .map(|a| a.iter().filter_map(|x| x["id"].as_str().map(String::from)).collect())
        .unwrap_or_default();
    let mut produced_by: HashMap<String, String> = HashMap::new();
    if let Some(acts) = v.pointer("/lineage/derivations").and_then(|d| d.as_array()) {
        for act in acts {
            let aid = act["id"].as_str().unwrap_or("?");
            if let Some(prods) = act.get("produces").and_then(|p| p.as_array()) {
                for p in prods.iter().filter_map(|x| x.as_str()) {
                    if !cp_ids.contains(p) { bail!("FAIL [DAG-01]: activity '{}' produces unknown checkpoint '{}'", aid, p); }
                    if let Some(prev) = produced_by.insert(p.to_string(), aid.to_string()) {
                        bail!("FAIL [DAG-01]: checkpoint '{}' produced by multiple activities ('{}' and '{}')", p, prev, aid);
                    }
                }
            }
            let mut sums: HashMap<&str, f64> = HashMap::new();
            if let Some(inputs) = act.get("inputs").and_then(|i| i.as_array()) {
                for inp in inputs {
                    if let Some(lcid) = inp.pointer("/target_ref/local_checkpoint_id").and_then(|x| x.as_str()) {
                        if !cp_ids.contains(lcid) { bail!("FAIL [DAG-01]: unknown local_checkpoint_id '{}'", lcid); }
                    }
                    if let (Some(val), Some(basis)) = (
                        inp.pointer("/contribution/value").and_then(|x| x.as_f64()),
                        inp.pointer("/contribution/basis").and_then(|x| x.as_str()),
                    ) {
                        *sums.entry(basis).or_insert(0.0) += val;
                    }
                }
            }
            for basis in ["sample_share", "token_share"] {
                if let Some(&s) = sums.get(basis) {
                    if s > 1.0 + 1e-4 { bail!("FAIL [CONTRIB-01]: activity '{}' {} sum {:.4} > 1.0", aid, basis, s); }
                }
            }
        }
    }

    if v.pointer("/openness/self_declared_alignment/osaid_1_0").and_then(|x| x.as_bool()) == Some(true) {
        let base_spdx = v.pointer("/licensing/spdx_expression").and_then(|x| x.as_str()).unwrap_or("");
        for comp in ["weights", "training_code", "inference_code", "data_information"] {
            if v["openness"][comp].as_str() != Some("public") {
                warnings.push(format!("ADVISORY [OPEN-01]: osaid_1_0 claimed but openness.{} is not public", comp));
            }
            let eff = v.pointer(&format!("/licensing/component_licenses/{}", comp)).and_then(|x| x.as_str()).unwrap_or(base_spdx);
            let allowed = if comp == "data_information" {
                OSI_ALLOWLIST.contains(&eff) || DOC_ALLOWLIST.contains(&eff)
            } else {
                OSI_ALLOWLIST.contains(&eff)
            };
            if !allowed {
                warnings.push(format!("ADVISORY [OPEN-01]: osaid_1_0 claimed but {} license '{}' is not in advisory allowlist", comp, eff));
            }
        }
    }

    let base_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));

    if verify_files {
        if let Some(cps) = v.get("checkpoints").and_then(|c| c.as_array()) {
            let mut file_tasks = Vec::new();
            for cp in cps {
                if let Some(files) = cp["files"].as_array() {
                    for f in files {
                        if let Some(dig) = f.get("digest").and_then(|x| x.as_str()) {
                            if !dig.starts_with("placeholder:") {
                                file_tasks.push((f["path"].as_str().unwrap().to_string(), dig.to_string(), f.get("byte_size").and_then(|x| x.as_u64())));
                            }
                        }
                    }
                }
            }
            file_tasks.par_iter().try_for_each(|(rel, exp, exp_sz)| -> Result<()> {
                let (act, sz) = sha256_stream(&base_dir.join(rel))?;
                if &act != exp { bail!("FAIL [FILE-01]: {} digest mismatch (expected {}, got {})", rel, exp, act); }
                if let Some(es) = exp_sz { if sz != *es { bail!("FAIL [FILE-01]: {} byte_size mismatch", rel); } }
                println!("OK [FILE-01]: {} verified (integrity).", rel);
                Ok(())
            })?;
        }
    }

    if verify_catalog {
        if let Some(cat_rel) = v.pointer("/data_provenance/ingestion_catalog/path").and_then(|x| x.as_str()) {
            let cat_path = base_dir.join(cat_rel);
            let (actual_digest, records, _parents) = validate_catalog_file(&cat_path, non_draft)?;
            let exp_digest = v.pointer("/data_provenance/ingestion_catalog/digest").and_then(|x| x.as_str()).unwrap_or("");
            if !exp_digest.starts_with("placeholder:") && actual_digest != exp_digest {
                bail!("FAIL [CAT-01]: catalog digest mismatch");
            }
            if let Some(acts) = v.pointer("/lineage/derivations").and_then(|d| d.as_array()) {
                for act in acts {
                    let is_seq_sft = act.pointer("/distillation_spec/mode").and_then(|x| x.as_str()) == Some("sequence_sft");
                    if let Some(inputs) = act.get("inputs").and_then(|i| i.as_array()) {
                        for inp in inputs {
                            if let Some(ids) = inp.get("catalog_record_ids").and_then(|x| x.as_array()) {
                                let mut any_synth = false;
                                for rid in ids.iter().filter_map(|x| x.as_str()) {
                                    let rec = records.get(rid).with_context(|| format!("FAIL [CAT-01]: missing catalog_record_id '{}'", rid))?;
                                    if rec.pointer("/synthetic/is_synthetic").and_then(|x| x.as_bool()) == Some(true)
                                        && rec.pointer("/synthetic/generator_ref").is_some()
                                    {
                                        any_synth = true;
                                        if let Some(gb) = inp.get("generated_by") {
                                            if gb != rec.pointer("/synthetic/generator_ref").unwrap() {
                                                bail!("FAIL [CAT-01]: input generated_by disagrees with catalog generator_ref on '{}'", rid);
                                            }
                                        }
                                    }
                                }
                                if is_seq_sft && !any_synth && inp.get("generated_by").is_none() {
                                    bail!("FAIL [CAT-01]: sequence_sft catalog_record_ids must include at least one synthetic record with generator_ref");
                                }
                            }
                        }
                    }
                }
            }
            println!("OK [CAT-01]: {} verified ({} records).", cat_rel, records.len());
        }
    }

    for w in &warnings { eprintln!("{}", w); }
    if strict && (status == "draft" || !warnings.is_empty()) {
        bail!("FAIL [STRICT-01]: strict mode rejected draft status or {} warning(s)", warnings.len());
    }
    Ok(())
}

fn cmd_inspect(manifest_path: &Path, verify_files: bool) -> Result<()> {
    let v = parse_yaml_12(manifest_path)?;
    let jcs_digest = sha256_bytes(&canonical_json_bytes(&v));
    let mut disclosed = 0usize;
    let mut partial = 0usize;
    let mut undisclosed = 0usize;
    for sec in DISCLOSURE_SECTIONS {
        match v.get(sec).and_then(|s| s.get("disclosure_status")).and_then(|x| x.as_str()) {
            Some("disclosed") => disclosed += 1,
            Some("partial") => partial += 1,
            _ => undisclosed += 1,
        }
    }
    println!("Manifest ID:  ({}, {})", v["moid"].as_str().unwrap_or("?"), jcs_digest);
    println!("Name/Version: {} ({}) [{}]", v["name"].as_str().unwrap_or("?"), v["model_version"].as_str().unwrap_or("?"), v["manifest_status"].as_str().unwrap_or("?"));
    println!("Assertion:    {} by {}", v["manifest_assertion"]["assertion_type"].as_str().unwrap_or("?"), v["manifest_assertion"]["asserted_by"]["name"].as_str().unwrap_or("?"));
    println!("Stack Role:   {} | Modulus: {}/{}", v["stack_roles"]["primary_role"].as_str().unwrap_or("?"), v["modulus"]["family"].as_str().unwrap_or("undisclosed"), v["modulus"]["paradigm"].as_str().unwrap_or("undisclosed"));
    println!("Disclosure:   {}/6 disclosed, {}/6 partial, {}/6 undisclosed/unknown", disclosed, partial, undisclosed);
    if verify_files {
        cmd_validate(manifest_path, true, false, false, false)?;
        println!("Verified Run: SCHEMA-01 + FILE-01 (integrity) executed.");
    } else {
        println!("Verified Run: 0 external checks verified (run with --verify-files / --verify-catalog to verify).");
    }
    Ok(())
}

fn cmd_diff(old_p: &Path, new_p: &Path) -> Result<()> {
    let a = parse_yaml_12(old_p)?;
    let b = parse_yaml_12(new_p)?;
    for ptr in ["/moid", "/model_version", "/manifest_status", "/modulus/family", "/stack_roles/primary_role", "/parameters/total", "/licensing/spdx_expression"] {
        if a.pointer(ptr) != b.pointer(ptr) {
            println!("~ {}: {:?} -> {:?}", ptr, a.pointer(ptr), b.pointer(ptr));
        }
    }
    Ok(())
}
