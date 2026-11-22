import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import _Ajv2020 from "ajv/dist/2020.js";
import _addFormats from "ajv-formats";
import YAML from "yaml";

const Ajv2020 = _Ajv2020.default ?? _Ajv2020;
const addFormats = _addFormats.default ?? _addFormats;

const ajv = new Ajv2020({ strict: true, strictTypes: false, strictRequired: false, allErrors: true });
addFormats(ajv);
ajv.addVocabulary(["x-verification"]);

const loadJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
ajv.addSchema(loadJson("schemas/v0.3.0-rc4/common.schema.json"));
const validateMoid = ajv.compile(loadJson("schemas/v0.3.0-rc4/moid.schema.json"));
const validatePub = ajv.compile(loadJson("schemas/v0.3.0-rc4/publisher.schema.json"));
const validateIng = ajv.compile(loadJson("schemas/v0.3.0-rc4/ingestion.schema.json"));

const moidBin = "cli/target/debug/moid";
const runRust = (args) => spawnSync(moidBin, args, { encoding: "utf8" });

let failures = 0;
const rows = [];

const record = (label, exp, ajvRes, rustRes, ok) => {
  if (!ok) failures++;
  rows.push(`| ${label} | ${exp} | ${ajvRes} | ${rustRes} | ${ok ? "OK" : "MISMATCH"} |`);
};

for (const file of fs.readdirSync("conformance/valid").sort()) {
  const full = path.join("conformance/valid", file);
  if (file.endsWith(".yaml")) {
    const ajvOk = validateMoid(YAML.parse(fs.readFileSync(full, "utf8"), { schema: "core" }));
    const rustOk = runRust(["validate", full]).status === 0;
    record(`valid/${file}`, "PASS", ajvOk ? "PASS" : "FAIL", rustOk ? "PASS" : "FAIL", ajvOk && rustOk);
  } else if (file.endsWith(".json")) {
    const ajvOk = validatePub(loadJson(full));
    const rustOk = runRust(["validate-publisher", full]).status === 0;
    record(`valid/${file}`, "PASS", ajvOk ? "PASS" : "FAIL", rustOk ? "PASS" : "FAIL", ajvOk && rustOk);
  } else if (file.endsWith(".jsonl")) {
    const ajvOk = fs.readFileSync(full, "utf8").trim().split("\n").every((l) => validateIng(JSON.parse(l)));
    const rustOk = runRust(["seal", full, "--non-draft"]).status === 0;
    record(`valid/${file}`, "PASS", ajvOk ? "PASS" : "FAIL", rustOk ? "PASS" : "FAIL", ajvOk && rustOk);
  }
}

for (const file of fs.readdirSync("conformance/invalid").sort()) {
  const full = path.join("conformance/invalid", file);
  if (file.startsWith("schema_")) {
    const ajvOk = validateMoid(YAML.parse(fs.readFileSync(full, "utf8"), { schema: "core" }));
    const rustOk = runRust(["validate", "--schema-only", full]).status === 0;
    record(`invalid/${file}`, "FAIL", ajvOk ? "PASS" : "FAIL", rustOk ? "PASS" : "FAIL", !ajvOk && !rustOk);
  } else if (file === "cli_25_osaid_advisory_non_osi_code.yaml") {
    const res = runRust(["validate", full]);
    const warned = res.status === 0 && res.stderr.includes("ADVISORY [OPEN-01]");
    record(`invalid/${file}`, "WARN", "N/A (CLI)", warned ? "WARN" : "FAIL", warned);
  } else if (file.endsWith(".yaml")) {
    const rustOk = runRust(["validate", full]).status === 0;
    record(`invalid/${file}`, "FAIL", "N/A (CLI)", rustOk ? "PASS" : "FAIL", !rustOk);
  } else if (file.endsWith(".jsonl")) {
    const rustOk = runRust(["seal", full, "--non-draft"]).status === 0;
    record(`invalid/${file}`, "FAIL", "N/A (CAT-01)", rustOk ? "PASS" : "FAIL", !rustOk);
  }
}

console.log("| Fixture | Expected | Ajv 2020-12 | Rust jsonschema 0.61 | Parity |");
console.log("| :--- | :---: | :---: | :---: | :--- |");
console.log(rows.join("\n"));
if (failures > 0) process.exit(1);
