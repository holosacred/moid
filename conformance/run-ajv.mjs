import fs from "node:fs";
import { spawnSync } from "node:child_process";
import _Ajv2020 from "ajv/dist/2020.js";
import _addFormats from "ajv-formats";
import YAML from "yaml";

const Ajv2020 = _Ajv2020.default ?? _Ajv2020;
const addFormats = _addFormats.default ?? _addFormats;

const ajv = new Ajv2020({ strict: true, strictRequired: true, allErrors: true });
addFormats(ajv);
ajv.addVocabulary(["x-verification"]);

const loadJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
ajv.addSchema(loadJson("schemas/v0.3.0-rc7/common.schema.json"));
const validators = {
  moid: ajv.compile(loadJson("schemas/v0.3.0-rc7/moid.schema.json")),
  publisher: ajv.compile(loadJson("schemas/v0.3.0-rc7/publisher.schema.json")),
  ingestion: ajv.compile(loadJson("schemas/v0.3.0-rc7/ingestion.schema.json")),
};

const moidBin = "cli/target/debug/moid";
const runRust = (args) => spawnSync(moidBin, args, { encoding: "utf8" });

const cases = loadJson("conformance/manifest.json");
let failures = 0;
const rows = [];

for (const c of cases) {
  const label = c.file.replace("conformance/", "");
  if (c.expect === "PASS") {
    let ajvOk = false, rustRes;
    if (c.schema === "moid") {
      ajvOk = validators.moid(YAML.parse(fs.readFileSync(c.file, "utf8"), { schema: "core" }));
      rustRes = runRust(["validate", c.file]);
    } else if (c.schema === "publisher") {
      ajvOk = validators.publisher(loadJson(c.file));
      rustRes = runRust(["validate-publisher", c.file]);
    } else {
      ajvOk = fs.readFileSync(c.file, "utf8").trim().split("\n").every((l) => validators.ingestion(JSON.parse(l)));
      rustRes = runRust(["seal", c.file, "--non-draft"]);
    }
    const ok = ajvOk && rustRes.status === 0;
    if (!ok) failures++;
    rows.push(`| ${label} | PASS | ${ajvOk ? "PASS" : "FAIL"} | ${rustRes.status === 0 ? "PASS" : "FAIL"} | ${ok ? "OK" : "MISMATCH"} |`);
  } else if (c.layer === "schema") {
    const data = c.file.endsWith(".json") ? loadJson(c.file) : YAML.parse(fs.readFileSync(c.file, "utf8"), { schema: "core" });
    const v = validators[c.schema];
    const ajvOk = v(data);
    const ajvMatched = !ajvOk && (v.errors || []).some((e) => e.instancePath === c.expected_path && e.keyword === c.expected_ajv_keyword);
    const rustArgs = c.schema === "publisher" ? ["validate-publisher", "--schema-only", c.file] : ["validate", "--schema-only", c.file];
    const rustRes = runRust(rustArgs);
    const rustMatched = rustRes.status !== 0 && rustRes.stderr.includes(`path=${c.expected_path} `);
    const ok = ajvMatched && rustMatched;
    if (!ok) {
      failures++;
      console.error(`DETAIL MISMATCH ${label}: expected path=${c.expected_path} kw=${c.expected_ajv_keyword}\n  ajv=${JSON.stringify((v.errors || []).map((e) => [e.instancePath, e.keyword]))}\n  rust=${rustRes.stderr.trim()}`);
    }
    rows.push(`| ${label} | FAIL (${c.expected_path || "<root>"}:${c.expected_ajv_keyword}) | ${ajvMatched ? "MATCH" : "MISS"} | ${rustMatched ? "MATCH" : "MISS"} | ${ok ? "OK" : "MISMATCH"} |`);
  } else {
    let schemaPass = true;
    if (c.schema === "moid") schemaPass = validators.moid(YAML.parse(fs.readFileSync(c.file, "utf8"), { schema: "core" }));
    if (c.schema === "publisher") schemaPass = validators.publisher(loadJson(c.file));
    const rustArgs = c.layer === "cat" ? ["seal", c.file, "--non-draft"] : c.layer === "pub" ? ["validate-publisher", c.file] : ["validate", c.file];
    const rustRes = runRust(rustArgs);
    const statusOk = c.expect === "WARN" ? rustRes.status === 0 : rustRes.status !== 0;
    const msgOk = rustRes.stderr.includes(c.expected_rule) && rustRes.stderr.includes(c.expected_msg);
    const ok = schemaPass && statusOk && msgOk;
    if (!ok) {
      failures++;
      console.error(`CLI MISMATCH ${label}: schemaPass=${schemaPass} status=${rustRes.status} stderr=${rustRes.stderr.trim()}`);
    }
    rows.push(`| ${label} | ${c.expect} (${c.expected_rule}) | ${schemaPass ? "SCHEMA PASS" : "SCHEMA FAIL"} | ${msgOk ? c.expect + " MATCH" : "MISS"} | ${ok ? "OK" : "MISMATCH"} |`);
  }
}

console.log("Ajv 2020-12 compiled OK with { strict: true, strictRequired: true }");
console.log("| Fixture | Expected Assertion | Ajv 2020-12 | Rust jsonschema 0.61 | Status |");
console.log("| :--- | :--- | :---: | :---: | :--- |");
console.log(rows.join("\n"));
console.log(`\nTotal: ${cases.length - failures}/${cases.length} assertions matched.`);
if (failures > 0) process.exit(1);
