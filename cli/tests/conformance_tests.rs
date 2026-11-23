use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn moid_bin() -> &'static str { env!("CARGO_BIN_EXE_moid") }
fn root() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf() }

#[test]
fn test_all_valid_conformance_fixtures() {
    let dir = root().join("conformance/valid");
    let mut entries: Vec<_> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for p in entries {
        let name = p.file_name().unwrap().to_str().unwrap();
        let out = if name.ends_with(".yaml") {
            Command::new(moid_bin()).args(["validate", p.to_str().unwrap()]).output().unwrap()
        } else if name.ends_with(".json") {
            Command::new(moid_bin()).args(["validate-publisher", p.to_str().unwrap()]).output().unwrap()
        } else if name.ends_with(".jsonl") {
            Command::new(moid_bin()).args(["seal", p.to_str().unwrap(), "--non-draft"]).output().unwrap()
        } else { continue; };
        assert!(out.status.success(), "Expected PASS for valid/{}: {}", name, String::from_utf8_lossy(&out.stderr));
    }
}

#[test]
fn test_all_schema_invalid_fixtures_fail_schema_only() {
    let dir = root().join("conformance/invalid");
    let mut entries: Vec<_> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for p in entries {
        let name = p.file_name().unwrap().to_str().unwrap();
        if !name.starts_with("schema_") { continue; }
        let out = if name.ends_with(".json") {
            Command::new(moid_bin()).args(["validate-publisher", p.to_str().unwrap()]).output().unwrap()
        } else {
            Command::new(moid_bin()).args(["validate", "--schema-only", p.to_str().unwrap()]).output().unwrap()
        };
        assert!(!out.status.success(), "Expected SCHEMA FAIL for invalid/{}, but it PASSED", name);
    }
}

#[test]
fn test_cli_semantic_catalog_and_publisher_negatives() {
    let inv = root().join("conformance/invalid");
    for f in [
        "cli_20_duplicate_checkpoint_producer.yaml",
        "cli_21_contrib_share_exceeds_one.yaml",
        "cli_26_moid_namespace_mismatch.yaml",
        "cli_27_dangling_local_and_produces.yaml",
    ] {
        let out = Command::new(moid_bin()).args(["validate", inv.join(f).to_str().unwrap()]).output().unwrap();
        assert!(!out.status.success(), "Expected CLI FAIL for {}", f);
    }
    for f in [
        "cli_22_mixed_level_unlinked.jsonl",
        "cli_23_nonleaf_digest.jsonl",
        "cli_24_nondraft_leaf_no_digest.jsonl",
    ] {
        let out = Command::new(moid_bin()).args(["seal", inv.join(f).to_str().unwrap(), "--non-draft"]).output().unwrap();
        assert!(!out.status.success(), "Expected CAT-01 FAIL for {}", f);
    }
    for f in [
        "cli_28_publisher_allowed_and_revoked.json",
        "cli_29_publisher_expired_before_updated.json",
    ] {
        let out = Command::new(moid_bin()).args(["validate-publisher", inv.join(f).to_str().unwrap()]).output().unwrap();
        assert!(!out.status.success(), "Expected PUB-01 FAIL for {}", f);
    }
    let adv = Command::new(moid_bin()).args(["validate", inv.join("cli_25_osaid_advisory_non_osi_code.yaml").to_str().unwrap()]).output().unwrap();
    assert!(adv.status.success(), "Advisory OPEN-01 should warn, not hard-fail");
    assert!(String::from_utf8_lossy(&adv.stderr).contains("ADVISORY [OPEN-01]"));
}
