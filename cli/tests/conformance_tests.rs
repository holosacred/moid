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
            let mut args: Vec<String> = match layer {
                "cat" => vec!["seal".into(), file.to_string_lossy().into(), "--non-draft".into()],
                "pub" => vec!["validate-publisher".into(), file.to_string_lossy().into()],
                _ => vec!["validate".into(), file.to_string_lossy().into()],
            };
            if let Some(extras) = c.get("extra_args").and_then(|v| v.as_array()) {
                for a in extras.iter().filter_map(|v| v.as_str()) {
                    args.push(a.to_string());
                }
            }
            let out = Command::new(moid_bin()).args(&args).output().unwrap();
            let stderr = String::from_utf8_lossy(&out.stderr);
            if expect == "WARN" { assert!(out.status.success()); } else { assert!(!out.status.success()); }
            assert!(stderr.contains(rule) && stderr.contains(msg), "Wrong CLI error for {:?}: expected {} + {}, got:\n{}", file, rule, msg, stderr);
        }
    }
}

#[test]
fn test_publisher_trust_continuity_and_network_rules() {
    let dir = tempdir().unwrap();
    let state = dir.path().join("serials.json");
    let pub_valid = root().join("conformance/valid/05_publisher_binding_gpg.json");
    let backlink_ok = root().join("conformance/valid/09_backlink_profile_valid.html");
    let backlink_bad = root().join("conformance/invalid/cli_33_backlink_missing.html");

    // 1. Valid NET-05 back-link + default-branch match + serial 2 saved to state
    let mut b2: Value = serde_json::from_str(&fs::read_to_string(&pub_valid).unwrap()).unwrap();
    b2["serial"] = Value::from(2);
    let b2_path = dir.path().join("b2.json");
    fs::write(&b2_path, serde_json::to_string_pretty(&b2).unwrap()).unwrap();
    let ok = Command::new(moid_bin())
        .args(["validate-publisher", b2_path.to_str().unwrap(), "--serial-state", state.to_str().unwrap(), "--backlink-file", backlink_ok.to_str().unwrap(), "--default-branch", "main"])
        .output().unwrap();
    assert!(ok.status.success(), "Expected PASS with valid backlink, default-branch & serial 2: {}", String::from_utf8_lossy(&ok.stderr));

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

    // 4. Same-serial equivocation fails PUB-01
    let mut b2_mod = b2.clone();
    b2_mod["display_name"] = Value::from("Equivocated Name");
    let b2_eq = dir.path().join("b2_eq.json");
    fs::write(&b2_eq, serde_json::to_string_pretty(&b2_mod).unwrap()).unwrap();
    let eq = Command::new(moid_bin())
        .args(["validate-publisher", b2_eq.to_str().unwrap(), "--serial-state", state.to_str().unwrap()])
        .output().unwrap();
    assert!(!eq.status.success() && String::from_utf8_lossy(&eq.stderr).contains("serial equivocation"));

    // 5. NET-06 multi-record DNS TXT rotation (two v=moid1; lines; second matches) & mismatch
    let ok_out = String::from_utf8_lossy(&ok.stdout);
    let jcs_part = ok_out.split("jcs=").nth(1).unwrap().split(')').next().unwrap();
    let dns_multi = dir.path().join("dns_multi.txt");
    let dns_bad = dir.path().join("dns_bad.txt");
    fs::write(&dns_multi, format!("v=moid1; jcs=sha256:1111111111111111111111111111111111111111111111111111111111111111\nv=moid1; jcs={}\n", jcs_part)).unwrap();
    fs::write(&dns_bad, "v=moid1; jcs=sha256:0000000000000000000000000000000000000000000000000000000000000000\n").unwrap();
    let d_pass = Command::new(moid_bin())
        .args(["validate-publisher", b2_path.to_str().unwrap(), "--dns-txt-file", dns_multi.to_str().unwrap()])
        .output().unwrap();
    assert!(d_pass.status.success(), "Expected NET-06 multi-record PASS: {}", String::from_utf8_lossy(&d_pass.stderr));
    let d_fail = Command::new(moid_bin())
        .args(["validate-publisher", b2_path.to_str().unwrap(), "--dns-txt-file", dns_bad.to_str().unwrap()])
        .output().unwrap();
    assert!(!d_fail.status.success() && String::from_utf8_lossy(&d_fail.stderr).contains("NET-06"));

    // 6. Rotation to serial 3: valid continuity via prior PGP key -> PASS without warning
    let mut b3 = b2.clone();
    b3["serial"] = Value::from(3);
    let b3_path = dir.path().join("b3.json");
    fs::write(&b3_path, serde_json::to_string_pretty(&b3).unwrap()).unwrap();
    let rot_ok = Command::new(moid_bin())
        .args(["validate-publisher", b3_path.to_str().unwrap(), "--serial-state", state.to_str().unwrap(), "--continuity-signer", "0123456789ABCDEF0123456789ABCDEF01234567"])
        .output().unwrap();
    assert!(rot_ok.status.success() && !String::from_utf8_lossy(&rot_ok.stderr).contains("CONTINUITY_BREAK"));

    // 7. Rotation to serial 4 without continuity signer -> PASS with WARN [CONTINUITY_BREAK] (and fails if --fail-on-continuity-break)
    let mut b4 = b3.clone();
    b4["serial"] = Value::from(4);
    let b4_path = dir.path().join("b4.json");
    fs::write(&b4_path, serde_json::to_string_pretty(&b4).unwrap()).unwrap();
    let rot_fail_closed = Command::new(moid_bin())
        .args(["validate-publisher", b4_path.to_str().unwrap(), "--serial-state", state.to_str().unwrap(), "--fail-on-continuity-break"])
        .output().unwrap();
    assert!(!rot_fail_closed.status.success() && String::from_utf8_lossy(&rot_fail_closed.stderr).contains("CONTINUITY_BREAK"));
    let rot_warn = Command::new(moid_bin())
        .args(["validate-publisher", b4_path.to_str().unwrap(), "--serial-state", state.to_str().unwrap()])
        .output().unwrap();
    assert!(rot_warn.status.success() && String::from_utf8_lossy(&rot_warn.stderr).contains("WARN [CONTINUITY_BREAK]"));

    // 8. Rotation to serial 5 signed by a key revoked for key_compromise -> WARN [CONTINUITY_BREAK] (fails closed with flag)
    let mut b5 = b4.clone();
    b5["serial"] = Value::from(5);
    b5["allowed_identities"] = serde_json::json!([
        { "kind": "pgp", "fingerprint": "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333" }
    ]);
    b5["revoked_identities"] = serde_json::json!([
        { "identity": { "kind": "pgp", "fingerprint": "0123456789ABCDEF0123456789ABCDEF01234567" }, "revoked_at": "2026-11-24T12:00:00Z", "reason": "key_compromise" }
    ]);
    let b5_path = dir.path().join("b5.json");
    fs::write(&b5_path, serde_json::to_string_pretty(&b5).unwrap()).unwrap();
    let comp = Command::new(moid_bin())
        .args(["validate-publisher", b5_path.to_str().unwrap(), "--serial-state", state.to_str().unwrap(), "--continuity-signer", "0123456789ABCDEF0123456789ABCDEF01234567", "--fail-on-continuity-break"])
        .output().unwrap();
    assert!(!comp.status.success() && String::from_utf8_lossy(&comp.stderr).contains("key_compromise"));
}

#[test]
fn test_canonicalize_and_minisign_sig01() {
    let dir = tempdir().unwrap();
    let pub_valid = root().join("conformance/valid/05_publisher_binding_gpg.json");

    // 1. moid canonicalize emits valid compact RFC 8785 JCS JSON without trailing newline
    let canon = Command::new(moid_bin())
        .args(["canonicalize", pub_valid.to_str().unwrap()])
        .output().unwrap();
    assert!(canon.status.success(), "canonicalize failed: {}", String::from_utf8_lossy(&canon.stderr));
    let canon_str = String::from_utf8(canon.stdout).unwrap();
    assert!(!canon_str.ends_with('\n'), "JCS output must not have trailing newline");
    let parsed: Value = serde_json::from_str(&canon_str).unwrap();
    assert_eq!(parsed["spec_version"], "0.3.0");

    // 2. minisign-v1 binding with tampered signature must fail SIG-01
    let mut ms_pub: Value = serde_json::from_str(&fs::read_to_string(&pub_valid).unwrap()).unwrap();
    ms_pub["allowed_identities"] = serde_json::json!([
        { "kind": "minisign", "public_key": "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3" }
    ]);
    ms_pub["binding_signature"] = serde_json::json!({
        "format": "minisign-v1",
        "path": "./moid-publisher.json.minisig"
    });
    let ms_path = dir.path().join("ms_pub.json");
    fs::write(&ms_path, serde_json::to_string_pretty(&ms_pub).unwrap()).unwrap();
    let bad_sig = dir.path().join("bad.minisig");
    fs::write(&bad_sig, "untrusted comment: forged\nRWRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\ntrusted comment: forged\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n").unwrap();
    let fail = Command::new(moid_bin())
        .args(["validate-publisher", ms_path.to_str().unwrap(), "--binding-sig", bad_sig.to_str().unwrap()])
        .output().unwrap();
    assert!(!fail.status.success() && String::from_utf8_lossy(&fail.stderr).contains("SIG-01"),
        "Expected SIG-01 failure on forged minisign signature, got: {}", String::from_utf8_lossy(&fail.stderr));
}
