use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

fn moid_bin() -> &'static str {
    env!("CARGO_BIN_EXE_moid")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn test_template_and_examples_validate() {
    let root = repo_root();
    let targets = [
        "template.moid.yaml",
        "examples/dense_transformer_generator.moid.yaml",
        "examples/neural_operator_world_model.moid.yaml",
        "examples/state_space_decision_policy.moid.yaml",
        "examples/closed_weight_api_model.moid.yaml",
    ];

    for rel in targets {
        let path = root.join(rel);
        let out = Command::new(moid_bin())
            .args(["validate", path.to_str().unwrap()])
            .output()
            .expect("failed to execute moid");
        assert!(
            out.status.success(),
            "Validation failed for {}: {}",
            rel,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn test_hash_seal_write_inspect_and_tamper_detection() {
    let dir = tempdir().unwrap();
    let weights_dir = dir.path().join("weights");
    fs::create_dir_all(&weights_dir).unwrap();

    let shard = weights_dir.join("model-00001-of-00001.safetensors");
    fs::write(&shard, b"synthetic tensor payload bytes").unwrap();

    let catalog = dir.path().join("ingestion_manifest.jsonl");
    fs::write(
        &catalog,
        r#"{"source_id":"src_001","source_uri":"https://example.org/doc.pdf","media_category":"documentary_text","content_hash_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","license_tier":"copycenter","spdx_license":"CC-BY-4.0"}"#,
    )
    .unwrap();

    let manifest = dir.path().join("moid.yaml");

    let init_out = Command::new(moid_bin())
        .current_dir(dir.path())
        .args([
            "init",
            "--modulus",
            "state_space",
            "--stack-role",
            "decision_policy",
            "--id",
            "holosacred/test-policy-v1",
        ])
        .output()
        .unwrap();
    assert!(init_out.status.success());

    let hash_out = Command::new(moid_bin())
        .current_dir(dir.path())
        .args([
            "hash",
            "weights/model-00001-of-00001.safetensors",
            "--write",
            "moid.yaml",
        ])
        .output()
        .unwrap();
    assert!(
        hash_out.status.success(),
        "{}",
        String::from_utf8_lossy(&hash_out.stderr)
    );

    let seal_out = Command::new(moid_bin())
        .current_dir(dir.path())
        .args(["seal", "ingestion_manifest.jsonl", "--write", "moid.yaml"])
        .output()
        .unwrap();
    assert!(
        seal_out.status.success(),
        "{}",
        String::from_utf8_lossy(&seal_out.stderr)
    );

    let val_ok = Command::new(moid_bin())
        .current_dir(dir.path())
        .args(["validate", "moid.yaml", "--verify-weights"])
        .output()
        .unwrap();
    assert!(
        val_ok.status.success(),
        "{}",
        String::from_utf8_lossy(&val_ok.stderr)
    );

    let inspect_out = Command::new(moid_bin())
        .args(["inspect", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(inspect_out.status.success());
    let inspect_stdout = String::from_utf8_lossy(&inspect_out.stdout);
    assert!(inspect_stdout.contains("decision_policy"));
    assert!(inspect_stdout.contains("holosacred/test-policy-v1"));

    // Tamper 1 byte and verify detection
    fs::write(&shard, b"synthetic tensor payload bytes!").unwrap();
    let val_fail = Command::new(moid_bin())
        .current_dir(dir.path())
        .args(["validate", "moid.yaml", "--verify-weights"])
        .output()
        .unwrap();
    assert!(!val_fail.status.success());
    assert!(String::from_utf8_lossy(&val_fail.stderr).contains("SHA-256 mismatch"));
}

#[test]
fn test_hash_from_sha256sums_and_diff() {
    let dir = tempdir().unwrap();
    let sums = dir.path().join("SHA256SUMS");
    fs::write(
        &sums,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  weights/part1.safetensors\n4d9f8c6b1a2e3f4056789abcde0123456789abcdef0123456789abcdef012345 *weights/part2.safetensors\n",
    )
    .unwrap();

    let out = Command::new(moid_bin())
        .args(["hash", "--from-sha256sums", sums.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("weights/part1.safetensors"));
    assert!(stdout.contains("weights/part2.safetensors"));

    let root = repo_root();
    let diff_out = Command::new(moid_bin())
        .args([
            "diff",
            root.join("examples/dense_transformer_generator.moid.yaml")
                .to_str()
                .unwrap(),
            root.join("examples/state_space_decision_policy.moid.yaml")
                .to_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert!(diff_out.status.success());
    let diff_stdout = String::from_utf8_lossy(&diff_out.stdout);
    assert!(diff_stdout.contains("~ modulus:"));
    assert!(diff_stdout.contains("~ stack_role:"));
}

#[test]
fn test_rejects_invalid_manifest_cases() {
    let dir = tempdir().unwrap();

    // Case 1: open_weights: true without checkpoints
    let missing_cp = dir.path().join("missing_cp.yaml");
    fs::write(
        &missing_cp,
        r#"
moid_version: "0.2.0"
modulus: "transformer"
stack_role: "generator"
moid: "holosacred/bad-v1"
model_name: "Bad Model"
licensing:
  tier: "copycenter"
  spdx_license: "MIT"
access_control:
  open_weights: true
  open_code: true
  open_data: true
  reproducibility: "full"
domain_focus:
  primary: "language"
  focus_weights:
    language: 1.0
parameters:
  total_count: 100
  base_precision: "bf16"
transformer_spec:
  vocabulary_size: 1000
  context_length: 1024
data_provenance:
  ingestion_catalog_file: "ingestion.jsonl"
  catalog_file_hash_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
"#,
    )
    .unwrap();

    let out1 = Command::new(moid_bin())
        .args(["validate", missing_cp.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out1.status.success());

    // Case 2: invalid stack_role enum
    let bad_role = dir.path().join("bad_role.yaml");
    fs::write(
        &bad_role,
        r#"
moid_version: "0.2.0"
modulus: "state_space"
stack_role: "unknown_component"
moid: "holosacred/bad-v2"
licensing:
  tier: "copycenter"
  spdx_license: "MIT"
access_control:
  open_weights: false
  open_code: true
  open_data: true
  reproducibility: "partial"
domain_focus:
  primary: "math"
  focus_weights:
    math: 1.0
parameters:
  total_count: 100
  base_precision: "bf16"
data_provenance:
  ingestion_catalog_file: "ingestion.jsonl"
  catalog_file_hash_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
"#,
    )
    .unwrap();

    let out2 = Command::new(moid_bin())
        .args(["validate", bad_role.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out2.status.success());
}
