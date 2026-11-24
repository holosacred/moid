import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";

const readYaml = (p) => YAML.parse(fs.readFileSync(p, "utf8"), { schema: "core" });
const writeYaml = (name, obj) => fs.writeFileSync(path.join("conformance/invalid", name), YAML.stringify(obj));
const writeJson = (name, obj) => fs.writeFileSync(path.join("conformance/invalid", name), JSON.stringify(obj, null, 2));

const ex1 = () => readYaml("examples/01_first_party_hybrid_policy.moid.yaml");
const ex2 = () => readYaml("examples/02_third_party_deepseek_distill.moid.yaml");
const ex3 = () => readYaml("examples/03_closed_api_orchestrator.moid.yaml");
const ex4 = () => readYaml("examples/04_third_party_community_gguf.moid.yaml");
const pub = () => JSON.parse(fs.readFileSync("conformance/valid/05_publisher_binding_gpg.json", "utf8"));
const realSha = (n) => `sha256:${String(n).repeat(64).slice(0, 64).replace(/[^0-9a-f]/g, "a")}`;

// Valid 07: release signed all-undisclosed
const allUndisc = ex3();
allUndisc.domain_focus = { disclosure_status: "undisclosed" };
allUndisc.licensing = { disclosure_status: "undisclosed" };
fs.writeFileSync("conformance/valid/07_release_signed_all_undisclosed.moid.yaml", YAML.stringify(allUndisc));

const manifest = [];
const addValid = (file, schema) => manifest.push({ file: `conformance/valid/${file}`, schema, expect: "PASS", layer: "both" });
const addSchemaNeg = (file, schema, expected_path, expected_ajv_keyword) =>
  manifest.push({ file: `conformance/invalid/${file}`, schema, expect: "FAIL", layer: "schema", expected_path, expected_ajv_keyword });
const addCliNeg = (file, schema, expect, layer, expected_rule, expected_msg) =>
  manifest.push({ file: `conformance/invalid/${file}`, schema, expect, layer, expected_rule, expected_msg });

for (const [file, schema] of [
  ["01_first_party_hybrid_policy.moid.yaml", "moid"],
  ["02_third_party_deepseek_distill.moid.yaml", "moid"],
  ["03_closed_api_orchestrator.moid.yaml", "moid"],
  ["04_third_party_community_gguf.moid.yaml", "moid"],
  ["05_publisher_binding_gpg.json", "publisher"],
  ["06_hierarchical_ingestion.jsonl", "ingestion"],
  ["07_release_signed_all_undisclosed.moid.yaml", "moid"],
  ["08_publisher_binding_long_domain.json", "publisher"],
]) addValid(file, schema);

let f, p;
// 01–23: core + rc5 schema negatives with exact expected instancePath & keyword
f = ex1(); f.manifest_status = "release"; writeYaml("schema_01_release_placeholder_digest.yaml", f);
addSchemaNeg("schema_01_release_placeholder_digest.yaml", "moid", "/checkpoints/0/files/0/digest", "pattern");

f = ex1(); f.manifest_status = "deprecated"; writeYaml("schema_02_deprecated_placeholder_digest.yaml", f);
addSchemaNeg("schema_02_deprecated_placeholder_digest.yaml", "moid", "/checkpoints/0/files/0/digest", "pattern");

f = ex2(); f.manifest_status = "release"; writeYaml("schema_03_release_placeholder_revision.yaml", f);
addSchemaNeg("schema_03_release_placeholder_revision.yaml", "moid", "/lineage/derivations/0/inputs/0/target_ref/revision", "pattern");

f = ex2(); f.lineage.derivations[0].inputs[0].target_ref.revision = "unverified-free-text"; writeYaml("schema_04_junk_revision_string.yaml", f);
addSchemaNeg("schema_04_junk_revision_string.yaml", "moid", "/lineage/derivations/0/inputs/0/target_ref/revision", "oneOf");

f = ex3(); f.openness.weights = "public"; f.checkpoints = [{ id: "w1", artifact_kind: "full_weights", format: "safetensors", precision: "bf16", files: [{ path: "w.safetensors" }] }]; writeYaml("schema_05_release_open_weights_no_digest.yaml", f);
addSchemaNeg("schema_05_release_open_weights_no_digest.yaml", "moid", "/checkpoints/0/files/0", "required");

f = ex3(); f.manifest_status = "draft"; writeYaml("schema_06_draft_with_attestation.yaml", f);
addSchemaNeg("schema_06_draft_with_attestation.yaml", "moid", "/manifest_status", "not");

f = ex1(); f.lineage.derivations[0].inputs = [{ role: "training_data", catalog_record_ids: ["shard-code-01"] }]; writeYaml("schema_07_distill_online_without_teacher.yaml", f);
addSchemaNeg("schema_07_distill_online_without_teacher.yaml", "moid", "/lineage/derivations/0/inputs", "contains");

f = ex2(); f.lineage.derivations[0].inputs.push({ role: "teacher", target_ref: { manifest_digest: realSha(1) } }); writeYaml("schema_08_distill_sequence_sft_with_teacher.yaml", f);
addSchemaNeg("schema_08_distill_sequence_sft_with_teacher.yaml", "moid", "/lineage/derivations/0/inputs/3/role", "enum");

f = ex4(); f.lineage.derivations[0].inputs = [{ role: "calibration_data", undisclosed_summary: "calib only" }]; writeYaml("schema_09_quantize_calibration_only.yaml", f);
addSchemaNeg("schema_09_quantize_calibration_only.yaml", "moid", "/lineage/derivations/0/inputs", "contains");

f = ex4(); delete f.lineage.derivations[0].quantization_spec; writeYaml("schema_10_quantize_missing_spec.yaml", f);
addSchemaNeg("schema_10_quantize_missing_spec.yaml", "moid", "/lineage/derivations/0", "required");

f = ex2(); f.lineage.derivations = [{ id: "ft1", activity_type: "fine_tune", inputs: [{ role: "training_data", undisclosed_summary: "sft" }], produces: ["hf-safetensors-primary"] }]; writeYaml("schema_11_fine_tune_without_base.yaml", f);
addSchemaNeg("schema_11_fine_tune_without_base.yaml", "moid", "/lineage/derivations/0/inputs", "contains");

f = ex2(); f.lineage.derivations = [{ id: "ft2", activity_type: "fine_tune", inputs: [{ role: "base_weights", target_ref: { manifest_digest: realSha(2) } }], produces: ["hf-safetensors-primary"], quantization_spec: { method: "awq" } }]; writeYaml("schema_12_fine_tune_with_quant_spec.yaml", f);
addSchemaNeg("schema_12_fine_tune_with_quant_spec.yaml", "moid", "/lineage/derivations/0/quantization_spec", "false schema");

f = ex1(); f.lineage.weight_initialization = "from_model"; f.lineage.derivations = [f.lineage.derivations[0]]; writeYaml("schema_13_from_model_no_parent_weights.yaml", f);
addSchemaNeg("schema_13_from_model_no_parent_weights.yaml", "moid", "/lineage/derivations", "contains");

f = ex1(); f.lineage.derivations[0].inputs.push({ role: "base_weights", target_ref: { manifest_digest: realSha(3) } }); writeYaml("schema_14_random_init_external_base.yaml", f);
addSchemaNeg("schema_14_random_init_external_base.yaml", "moid", "/lineage/derivations/0/inputs/2/target_ref", "required");

f = ex2(); delete f.lineage.derivations[0].produces; f.lineage.derivations[0].produces_endpoint = true; writeYaml("schema_15_produces_endpoint_no_endpoint.yaml", f);
addSchemaNeg("schema_15_produces_endpoint_no_endpoint.yaml", "moid", "", "required");

f = ex2(); f.openness.self_declared_alignment = { osaid_1_0: false }; writeYaml("schema_16_third_party_self_declared.yaml", f);
addSchemaNeg("schema_16_third_party_self_declared.yaml", "moid", "/openness/self_declared_alignment", "false schema");

f = ex1(); f.openness.training_data = "unknown"; writeYaml("schema_17_repro_full_unknown_data.yaml", f);
addSchemaNeg("schema_17_repro_full_unknown_data.yaml", "moid", "/openness/training_data", "enum");

f = ex3(); f.released_at = "2026-13-45"; writeYaml("schema_18_malformed_released_at.yaml", f);
addSchemaNeg("schema_18_malformed_released_at.yaml", "moid", "/released_at", "format");

fs.writeFileSync("conformance/invalid/schema_19_yaml11_unquoted_yes.yaml", fs.readFileSync("examples/01_first_party_hybrid_policy.moid.yaml", "utf8").replace("deterministic: true", "deterministic: yes"));
addSchemaNeg("schema_19_yaml11_unquoted_yes.yaml", "moid", "/stack_spec/deterministic", "type");

f = ex1(); f.lineage.weight_initialization = "from_model"; f.lineage.derivations = [f.lineage.derivations[1]]; writeYaml("schema_20_G01_from_model_local_only.yaml", f);
addSchemaNeg("schema_20_G01_from_model_local_only.yaml", "moid", "/lineage/derivations", "contains");

f = ex3(); f.manifest_assertion.attestation = { format: "pgp-detached-v1", path: "x.asc", canonicalization: "rfc8785-jcs" }; writeYaml("schema_21_G02_attestation_identity_mismatch.yaml", f);
addSchemaNeg("schema_21_G02_attestation_identity_mismatch.yaml", "moid", "/manifest_assertion/asserted_by/identity/kind", "const");

f = ex3(); f.parameters = { disclosure_status: "undisclosed", total: 7600000000 }; writeYaml("schema_22_G03_undisclosed_with_value.yaml", f);
addSchemaNeg("schema_22_G03_undisclosed_with_value.yaml", "moid", "/parameters/total", "false schema");

f = ex3(); f.manifest_assertion.assertion_type = "third_party_description"; delete f.manifest_assertion.attestation; delete f.manifest_assertion.evidence; writeYaml("schema_23_G04_nondraft_third_party_no_evidence.yaml", f);
addSchemaNeg("schema_23_G04_nondraft_third_party_no_evidence.yaml", "moid", "/manifest_assertion", "required");

// 24–31: rc6 empty disclosed / partial sections (all 6 sections covered)
for (const [num, sec, status] of [
  [24, "licensing", "disclosed"], [25, "data_provenance", "disclosed"],
  [26, "modulus", "partial"], [27, "domain_focus", "partial"],
  [28, "parameters", "partial"], [29, "lineage", "partial"],
  [30, "licensing", "partial"], [31, "data_provenance", "partial"],
]) {
  f = ex3(); f[sec] = { disclosure_status: status };
  const fname = `schema_${num}_empty_${status}_${sec}.yaml`;
  writeYaml(fname, f);
  addSchemaNeg(fname, "moid", `/${sec}`, "anyOf");
}

// 32–36: rebuilt single-defect rc6 publisher schema negatives
p = pub(); p.namespace_claim = { mode: "policy_pinned" }; writeJson("schema_32_pub_policy_pinned_removed.json", p);
addSchemaNeg("schema_32_pub_policy_pinned_removed.json", "publisher", "/namespace_claim/mode", "enum");

p = pub(); p.namespace_claim.platform_proof_uri = "https://evil.example/holosacred"; writeJson("schema_33_pub_platform_evil_host.json", p);
addSchemaNeg("schema_33_pub_platform_evil_host.json", "publisher", "/namespace_claim/platform_proof_uri", "pattern");

p = pub(); delete p.revoked_identities[0].revoked_at; writeJson("schema_34_pub_revoked_missing_revoked_at.json", p);
addSchemaNeg("schema_34_pub_revoked_missing_revoked_at.json", "publisher", "/revoked_identities/0", "required");

p = pub(); p.domain = "not a.domain!"; writeJson("schema_35_pub_bad_hostname.json", p);
addSchemaNeg("schema_35_pub_bad_hostname.json", "publisher", "/domain", "format");

p = pub(); p.domain = "localhost"; writeJson("schema_36_pub_no_dot_hostname.json", p);
addSchemaNeg("schema_36_pub_no_dot_hostname.json", "publisher", "/domain", "pattern");

// CLI / CAT-01 / PUB-01 / NET-05 negatives (each passes schema, fails exact CLI rule)
f = ex1(); f.lineage.derivations[1].produces = ["bf16-primary"]; writeYaml("cli_20_duplicate_checkpoint_producer.yaml", f);
addCliNeg("cli_20_duplicate_checkpoint_producer.yaml", "moid", "FAIL", "cli", "DAG-01", "multiple activities");

f = ex2(); f.lineage.derivations[0].inputs[1].contribution.value = 0.85; f.lineage.derivations[0].inputs[2].contribution.value = 0.30; writeYaml("cli_21_contrib_share_exceeds_one.yaml", f);
addCliNeg("cli_21_contrib_share_exceeds_one.yaml", "moid", "FAIL", "cli", "CONTRIB-01", "sample_share sum");

fs.writeFileSync("conformance/invalid/cli_22_mixed_level_unlinked.jsonl", [
  JSON.stringify({ record_id: "c1", record_level: "corpus", source_category: "public_dataset", modalities: ["text"], license_status: "unknown" }),
  JSON.stringify({ record_id: "s1", record_level: "shard", source_category: "public_dataset", digest: realSha(4), digest_scope: "raw_bytes", modalities: ["text"], license_status: "unknown" })
].join("\n") + "\n");
addCliNeg("cli_22_mixed_level_unlinked.jsonl", "ingestion", "FAIL", "cat", "CAT-01", "Unlinked mixed record_levels");

fs.writeFileSync("conformance/invalid/cli_23_nonleaf_digest.jsonl", [
  JSON.stringify({ record_id: "c1", record_level: "corpus", source_category: "public_dataset", digest: realSha(5), digest_scope: "raw_bytes", modalities: ["text"], license_status: "unknown" }),
  JSON.stringify({ record_id: "s1", parent_record_id: "c1", record_level: "shard", source_category: "public_dataset", digest: realSha(6), digest_scope: "raw_bytes", modalities: ["text"], license_status: "unknown" })
].join("\n") + "\n");
addCliNeg("cli_23_nonleaf_digest.jsonl", "ingestion", "FAIL", "cat", "CAT-01", "Non-leaf parent record");

fs.writeFileSync("conformance/invalid/cli_24_nondraft_leaf_no_digest.jsonl", JSON.stringify({ record_id: "d1", record_level: "dataset", source_category: "public_dataset", modalities: ["text"], license_status: "unknown" }) + "\n");
addCliNeg("cli_24_nondraft_leaf_no_digest.jsonl", "ingestion", "FAIL", "cat", "CAT-01", "requires digest");

f = ex1(); f.licensing.component_licenses.training_code = "Proprietary"; writeYaml("cli_25_osaid_advisory_non_osi_code.yaml", f);
addCliNeg("cli_25_osaid_advisory_non_osi_code.yaml", "moid", "WARN", "cli", "ADVISORY [OPEN-01]", "not in advisory allowlist");

f = ex1(); f.moid = "other/arbiter-nano-hybrid"; writeYaml("cli_26_G05_moid_namespace_mismatch.yaml", f);
addCliNeg("cli_26_G05_moid_namespace_mismatch.yaml", "moid", "FAIL", "cli", "ID-01", "publisher.namespace");

// Isolated G06: valid external base_weights in activity 0 (passes schema!), dangling local_checkpoint_id & produces in activity 1 -> fails specifically on DAG-01
f = ex2();
f.lineage.derivations.push({ id: "act-dangling", activity_type: "quantize", inputs: [{ role: "quantize_source", target_ref: { local_checkpoint_id: "nope" } }], produces: ["ghost"], quantization_spec: { method: "q4" } });
writeYaml("cli_27_G06_isolated_dangling_ids.yaml", f);
addCliNeg("cli_27_G06_isolated_dangling_ids.yaml", "moid", "FAIL", "cli", "DAG-01", "unknown checkpoint");

// Rebuilt B5 + PUB-01 freshness, lifetime, platform_account, domain_exact
p = pub(); p.revoked_identities = [{ identity: p.allowed_identities[0], revoked_at: "2026-11-10T00:00:00Z" }]; writeJson("cli_28_B5_publisher_allowed_and_revoked.json", p);
addCliNeg("cli_28_B5_publisher_allowed_and_revoked.json", "publisher", "FAIL", "pub", "PUB-01", "both allowed_identities and revoked_identities");

p = pub(); p.expires_at = "2026-11-24T12:00:00Z"; writeJson("cli_29_publisher_expired_before_updated.json", p);
addCliNeg("cli_29_publisher_expired_before_updated.json", "publisher", "FAIL", "pub", "PUB-01", "must be strictly after");

p = pub(); p.expires_at = "2999-01-01T00:00:00Z"; writeJson("cli_30_publisher_lifetime_exceeds_365d.json", p);
addCliNeg("cli_30_publisher_lifetime_exceeds_365d.json", "publisher", "FAIL", "pub", "PUB-01", "exceeds maximum 365 days");

p = pub(); p.namespace_claim.platform_proof_uri = "https://github.com/evil-org"; writeJson("cli_31_publisher_platform_account_mismatch.json", p);
addCliNeg("cli_31_publisher_platform_account_mismatch.json", "publisher", "FAIL", "pub", "PUB-01", "does not match platform_account");

p = pub(); p.namespace_claim = { mode: "domain_exact" }; writeJson("cli_32_publisher_domain_exact_mismatch.json", p);
addCliNeg("cli_32_publisher_domain_exact_mismatch.json", "publisher", "FAIL", "pub", "PUB-01", "domain_exact");

fs.writeFileSync("conformance/invalid/cli_33_backlink_missing.html", "<html><body>No domain link here</body></html>\n");

fs.writeFileSync("conformance/manifest.json", JSON.stringify(manifest, null, 2));
console.log(`Generated ${manifest.length} manifest-tracked fixtures (8 valid, 36 schema negatives, 13 CLI/CAT/PUB negatives) + backlink fixture.`);
