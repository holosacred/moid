use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

fn moid_bin() -> &'static str { env!("CARGO_BIN_EXE_moid") }
fn root() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf() }

#[test]
fn test_manifest_expected_error_assertions() {
    let manifest_raw = fs::read_to_string(root().join("conformance/manifest.json")).unwrap();
    let cases: Vec<Value> = serde_json::from_str(&manifest_raw).unwrap();
    for c in cases {
        let file = root().join(c["file"].as_str().unwrap());
        let expect = c["expect"].as_str().unwrap();
        let layer = c["layer"].as_str().unwrap();
        let schema = c["schema"].as_str().unwrap();

        if expect == "PASS" {
            let args = match schema {
                "publisher" => vec!["validate-publisher", file.to_str().unwrap()],
                "ingestion" => vec!["seal", file.to_str().unwrap(), "--non-draft"],
                _ => vec!["validate", file.to_str().unwrap()],
            };
            let out = Command::new(moid_bin()).args(&args).output().unwrap();
            assert!(out.status.success(), "Expected PASS for {:?}: {}", file, String::from_utf8_lossy(&out.stderr));
        } else if layer == "schema" {
            let exp_path = c["expected_path"].as_str().unwrap();
            let args = if schema == "publisher" {
                vec!["validate-publisher", "--schema-only", file.to_str().unwrap()]
            } else {
                vec!["validate", "--schema-only", file.to_str().unwrap()]
            };
            let out = Command::new(moid_bin()).args(&args).output().unwrap();
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(!out.status.success(), "Expected SCHEMA FAIL for {:?}", file);
            assert!(stderr.contains(&format!("path={} ", exp_path)), "Wrong error path for {:?}: expected 'path={} ', got:\n{}", file, exp_path, stderr);
        } else {
            let rule = c["expected_rule"].as_str().unwrap();
            let msg = c["expected_msg"].as_str().unwrap();
            let args = match layer {
                "cat" => vec!["seal", file.to_str().unwrap(), "--non-draft"],
                "pub" => vec!["validate-publisher", file.to_str().unwrap()],
                _ => vec!["validate", file.to_str().unwrap()],
            };
            let out = Command::new(moid_bin()).args(&args).output().unwrap();
            let stderr = String::from_utf8_lossy(&out.stderr);
            if expect == "WARN" { assert!(out.status.success()); } else { assert!(!out.status.success()); }
            assert!(stderr.contains(rule) && stderr.contains(msg), "Wrong CLI error for {:?}: expected {} + {}, got:\n{}", file, rule, msg, stderr);
        }
    }
}

#[test]
fn test_publisher_serial_rollback_equivocation_and_net05_backlink() {
    let dir = tempdir().unwrap();
    let state = dir.path().join("serials.json");
    let pub_valid = root().join("conformance/valid/05_publisher_binding_gpg.json");
    let backlink_ok = root().join("conformance/valid/09_backlink_profile_valid.html");
    let backlink_bad = root().join("conformance/invalid/cli_33_backlink_missing.html");

    // 1. Valid NET-05 back-link + serial 2 saved to state
    let mut b2: Value = serde_json::from_str(&fs::read_to_string(&pub_valid).unwrap()).unwrap();
    b2["serial"] = Value::from(2);
    let b2_path = dir.path().join("b2.json");
    fs::write(&b2_path, serde_json::to_string_pretty(&b2).unwrap()).unwrap();
    let ok = Command::new(moid_bin())
        .args(["validate-publisher", b2_path.to_str().unwrap(), "--serial-state", state.to_str().unwrap(), "--backlink-file", backlink_ok.to_str().unwrap()])
        .output().unwrap();
    assert!(ok.status.success(), "Expected PASS with valid backlink & serial 2: {}", String::from_utf8_lossy(&ok.stderr));

    // 2. Missing NET-05 back-link fails
    let bad_bl = Command::new(moid_bin())
        .args(["validate-publisher", b2_path.to_str().unwrap(), "--backlink-file", backlink_bad.to_str().unwrap()])
        .output().unwrap();
    assert!(!bad_bl.status.success() && String::from_utf8_lossy(&bad_bl.stderr).contains("NET-05"));

    // 3. Serial rollback (serial 1 < 2) fails PUB-01
    let rollback = Command::new(moid_bin())
        .args(["validate-publisher", pub_valid.to_str().unwrap(), "--serial-state", state.to_str().unwrap()])
        .output().unwrap();
    assert!(!rollback.status.success() && String::from_utf8_lossy(&rollback.stderr).contains("serial rollback"));

    // 4. Same-serial equivocation (serial 2 with modified display_name) fails PUB-01
    b2["display_name"] = Value::from("Equivocated Name");
    let b2_eq = dir.path().join("b2_eq.json");
    fs::write(&b2_eq, serde_json::to_string_pretty(&b2).unwrap()).unwrap();
    let eq = Command::new(moid_bin())
        .args(["validate-publisher", b2_eq.to_str().unwrap(), "--serial-state", state.to_str().unwrap()])
        .output().unwrap();
    assert!(!eq.status.success() && String::from_utf8_lossy(&eq.stderr).contains("serial equivocation"));
}
