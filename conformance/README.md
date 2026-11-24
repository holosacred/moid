# MoID Dual-Validator Conformance Suite

`conformance/manifest.json` tracks all valid fixtures, schema negatives, and CLI/catalog/publisher semantic negatives.

* **Pinned validator versions:** Expected RFC 6901 `instancePath` and keyword assertions in `manifest.json` are pinned to **Ajv 8 (`Ajv2020`, `strict: true, strictRequired: true`)** and **Rust `jsonschema 0.61`**. Validator upgrades that change error-reporting granularity update `manifest.json` expectations, not the specification.
* **Commands:**
  * `node conformance/gen-fixtures.mjs` — regenerate fixtures and `manifest.json`
  * `cargo test --manifest-path cli/Cargo.toml` — run Rust `jsonschema 0.61` + `PUB-01`/`CAT-01`/`NET-05`/`NET-06` tests
  * `node conformance/run-ajv.mjs` — run Ajv 2020-12 strict vs. Rust parity table
