import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";

const readYaml = (p) => YAML.parse(fs.readFileSync(p, "utf8"), { schema: "core" });
const writeYaml = (name, obj) =>
  fs.writeFileSync(path.join("conformance/invalid", name), YAML.stringify(obj));

const ex1 = () => readYaml("examples/01_first_party_hybrid_policy.moid.yaml");
const ex2 = () => readYaml("examples/02_third_party_deepseek_distill.moid.yaml");
const ex3 = () => readYaml("examples/03_closed_api_orchestrator.moid.yaml");
const ex4 = () => readYaml("examples/04_third_party_community_gguf.moid.yaml");

const realSha = (n) => `sha256:${String(n).repeat(64).slice(0, 64).replace(/[^0-9a-f]/g, "a")}`;

const allUndisc = ex3();
allUndisc.domain_focus = { disclosure_status: "undisclosed" };
allUndisc.licensing = { disclosure_status: "undisclosed" };
fs.writeFileSync("conformance/valid/07_release_signed_all_undisclosed.moid.yaml", YAML.stringify(allUndisc));

let f;
f = ex1(); f.manifest_status = "release";
writeYaml("schema_01_release_placeholder_digest.yaml", f);

f = ex1(); f.manifest_status = "deprecated";
writeYaml("schema_02_deprecated_placeholder_digest.yaml", f);

f = ex2(); f.manifest_status = "release";
writeYaml("schema_03_release_placeholder_revision.yaml", f);

f = ex2(); f.lineage.derivations[0].inputs[0].target_ref.revision = "unverified-free-text";
writeYaml("schema_04_junk_revision_string.yaml", f);

f = ex3();
f.openness.weights = "public";
f.checkpoints = [{ id: "w1", artifact_kind: "full_weights", format: "safetensors", precision: "bf16", files: [{ path: "w.safetensors" }] }];
writeYaml("schema_05_release_open_weights_no_digest.yaml", f);

f = ex3(); f.manifest_status = "draft";
writeYaml("schema_06_draft_with_attestation.yaml", f);

f = ex1(); f.lineage.derivations[0].inputs = [{ role: "training_data", catalog_record_ids: ["shard-code-01"] }];
writeYaml("schema_07_distill_online_without_teacher.yaml", f);

f = ex2(); f.lineage.derivations[0].inputs.push({ role: "teacher", target_ref: { manifest_digest: realSha(1) } });
writeYaml("schema_08_distill_sequence_sft_with_teacher.yaml", f);

f = ex4(); f.lineage.derivations[0].inputs = [{ role: "calibration_data", undisclosed_summary: "calib only" }];
writeYaml("schema_09_quantize_calibration_only.yaml", f);

f = ex4(); delete f.lineage.derivations[0].quantization_spec;
writeYaml("schema_10_quantize_missing_spec.yaml", f);

f = ex2();
f.lineage.derivations = [{ id: "ft1", activity_type: "fine_tune", inputs: [{ role: "training_data", undisclosed_summary: "sft" }], produces: ["hf-safetensors-primary"] }];
writeYaml("schema_11_fine_tune_without_base.yaml", f);

f = ex2();
f.lineage.derivations = [{ id: "ft2", activity_type: "fine_tune", inputs: [{ role: "base_weights", target_ref: { manifest_digest: realSha(2) } }], produces: ["hf-safetensors-primary"], quantization_spec: { method: "awq" } }];
writeYaml("schema_12_fine_tune_with_quant_spec.yaml", f);

f = ex1(); f.lineage.weight_initialization = "from_model";
f.lineage.derivations = [f.lineage.derivations[0]];
writeYaml("schema_13_from_model_no_parent_weights.yaml", f);

f = ex1();
f.lineage.derivations[0].inputs.push({ role: "base_weights", target_ref: { manifest_digest: realSha(3) } });
writeYaml("schema_14_random_init_external_base.yaml", f);

f = ex2();
delete f.lineage.derivations[0].produces;
f.lineage.derivations[0].produces_endpoint = true;
writeYaml("schema_15_produces_endpoint_no_endpoint.yaml", f);

f = ex2(); f.openness.self_declared_alignment = { osaid_1_0: false };
writeYaml("schema_16_third_party_self_declared.yaml", f);

f = ex1(); f.openness.training_data = "unknown";
writeYaml("schema_17_repro_full_unknown_data.yaml", f);

f = ex3(); f.released_at = "2026-13-45";
writeYaml("schema_18_malformed_released_at.yaml", f);

const rawEx1 = fs.readFileSync("examples/01_first_party_hybrid_policy.moid.yaml", "utf8");
fs.writeFileSync(
  "conformance/invalid/schema_19_yaml11_unquoted_yes.yaml",
  rawEx1.replace("deterministic: true", "deterministic: yes")
);

f = ex1();
f.lineage.derivations[1].produces = ["bf16-primary"];
writeYaml("cli_20_duplicate_checkpoint_producer.yaml", f);

f = ex2();
f.lineage.derivations[0].inputs[1].contribution.value = 0.85;
f.lineage.derivations[0].inputs[2].contribution.value = 0.30;
writeYaml("cli_21_contrib_share_exceeds_one.yaml", f);

fs.writeFileSync(
  "conformance/invalid/cli_22_mixed_level_unlinked.jsonl",
  [
    JSON.stringify({ record_id: "c1", record_level: "corpus", source_category: "public_dataset", modalities: ["text"], license_status: "unknown" }),
    JSON.stringify({ record_id: "s1", record_level: "shard", source_category: "public_dataset", digest: realSha(4), digest_scope: "raw_bytes", modalities: ["text"], license_status: "unknown" })
  ].join("\n") + "\n"
);

fs.writeFileSync(
  "conformance/invalid/cli_23_nonleaf_digest.jsonl",
  [
    JSON.stringify({ record_id: "c1", record_level: "corpus", source_category: "public_dataset", digest: realSha(5), digest_scope: "raw_bytes", modalities: ["text"], license_status: "unknown" }),
    JSON.stringify({ record_id: "s1", parent_record_id: "c1", record_level: "shard", source_category: "public_dataset", digest: realSha(6), digest_scope: "raw_bytes", modalities: ["text"], license_status: "unknown" })
  ].join("\n") + "\n"
);

fs.writeFileSync(
  "conformance/invalid/cli_24_nondraft_leaf_no_digest.jsonl",
  JSON.stringify({ record_id: "d1", record_level: "dataset", source_category: "public_dataset", modalities: ["text"], license_status: "unknown" }) + "\n"
);

f = ex1();
f.licensing.component_licenses.training_code = "Proprietary";
writeYaml("cli_25_osaid_advisory_non_osi_code.yaml", f);

console.log("Generated 19 schema negatives + 6 CLI/catalog negatives.");
