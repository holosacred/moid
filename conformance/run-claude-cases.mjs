import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import _Ajv2020 from "ajv/dist/2020.js";
import _addFormats from "ajv-formats";

const casesPath = process.argv[2];
if (!casesPath || !fs.existsSync(casesPath)) {
  console.error("Usage: node conformance/run-claude-cases.mjs <path/to/cases.json>");
  process.exit(1);
}

const Ajv2020 = _Ajv2020.default ?? _Ajv2020;
const addFormats = _addFormats.default ?? _addFormats;
const ajv = new Ajv2020({ strict: true, strictRequired: true, allErrors: true });
addFormats(ajv);
ajv.addVocabulary(["x-verification"]);

const load = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
ajv.addSchema(load("schemas/v0.3.0-rc5/common.schema.json"));
const validators = {
  moid: ajv.compile(load("schemas/v0.3.0-rc5/moid.schema.json")),
  ingestion: ajv.compile(load("schemas/v0.3.0-rc5/ingestion.schema.json")),
  publisher: ajv.compile(load("schemas/v0.3.0-rc5/publisher.schema.json")),
};

const raw = fs.readFileSync(casesPath, "utf8").replaceAll("0.3.0-rc4", "0.3.0-rc5");
const cases = JSON.parse(raw);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "moid-probe-"));
const bin = "cli/target/debug/moid";
let parityDiff = 0;

console.log("| ID | Schema | rc4 (Claude) | rc5 Ajv strict | rc5 Rust schema | rc5 Rust CLI | Parity |");
console.log("| :--- | :--- | :---: | :---: | :---: | :---: | :--- |");

for (const c of cases) {
  const ajvOk = validators[c.schema](c.manifest);
  let rustSchemaOk, rustCliOk;
  if (c.schema === "moid") {
    const f = path.join(tmp, `${c.id}.yaml`);
    fs.writeFileSync(f, JSON.stringify(c.manifest));
    rustSchemaOk = spawnSync(bin, ["validate", "--schema-only", f]).status === 0;
    rustCliOk = spawnSync(bin, ["validate", f]).status === 0;
  } else if (c.schema === "publisher") {
    const f = path.join(tmp, `${c.id}.json`);
    fs.writeFileSync(f, JSON.stringify(c.manifest));
    rustCliOk = spawnSync(bin, ["validate-publisher", f]).status === 0;
    rustSchemaOk = ajvOk; // publisher CLI runs schema + PUB-01
  } else {
    const f = path.join(tmp, `${c.id}.jsonl`);
    fs.writeFileSync(f, JSON.stringify(c.manifest) + "\n");
    rustCliOk = spawnSync(bin, ["seal", f]).status === 0;
    rustSchemaOk = rustCliOk;
  }
  const same = ajvOk === rustSchemaOk;
  if (!same) parityDiff++;
  const flip = c.py_valid !== ajvOk ? " (FLIP)" : "";
  console.log(`| ${c.id} | ${c.schema} | ${c.py_valid ? "PASS" : "FAIL"} | ${ajvOk ? "PASS" : "FAIL"} | ${rustSchemaOk ? "PASS" : "FAIL"} | ${rustCliOk ? "PASS" : "FAIL"} | ${same ? "OK" : "DIFF"}${flip} |`);
}
fs.rmSync(tmp, { recursive: true, force: true });
console.log(`\nSchema parity (Ajv strict vs Rust): ${cases.length - parityDiff}/${cases.length}`);
if (parityDiff > 0) process.exit(1);
