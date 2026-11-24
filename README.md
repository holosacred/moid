# MoID — Modulus IDentifier Standard (`v0.3.0`)

MoID is a repo-root YAML manifest standard (`*.moid.yaml`), Draft 2020-12 JSON Schema suite, and Rust CLI (`moid-cli`) for AI model architecture, runtime stack topology, PROV-inspired derivation provenance, and cryptographic publisher verification.

## Official Schemas (`v0.3.0`)

Hosted at https://moid.info:

* **Manifest:** `https://moid.info/schemas/v0.3.0/moid.schema.json`
* **Shared Vocabulary:** `https://moid.info/schemas/v0.3.0/common.schema.json`
* **Ingestion Catalog:** `https://moid.info/schemas/v0.3.0/ingestion.schema.json`
* **Publisher Binding:** `https://moid.info/schemas/v0.3.0/publisher.schema.json`

All four schemas compile under Ajv 2020-12 strict mode (`{ strict: true, strictRequired: true }`) with **76/76** dual-validator expected-error parity against Rust `jsonschema 0.61.2`.

## Design Highlights

* **3-Axis Classification:** Separates model architecture (`modulus`), runtime stack topology (`stack_roles` / `stack_spec`), and input/output `modalities` + `domain_focus`.
* **PROV-Inspired N-ary Lineage:** Models `fine_tune`, `distill`, `merge`, `quantize`, `adapter`, `continued_pretrain`, `prune`, and `rl_post_train` activities with strict role constraints and content-addressed digests (`sha256:`, `sha512:`, `blake3:`).
* **Bidirectional Disclosure Semantics:** Across all 6 disclosure-tracked sections (`modulus`, `domain_focus`, `parameters`, `lineage`, `licensing`, `data_provenance`), `disclosed` and `partial` require substantive content, while `undisclosed` and `unknown` forbid substantive data and `x-*` extensions.
* **Hardened Publisher Trust Model:** Tier-1 live HTTPS authority, RFC 8785 JCS canonical signing (`pgp-detached-v1`, `minisign-v1`, `ssh-sig-v1`, `dsse-in-toto-v1`, `sigstore-bundle-v0.3`), key-continuity rotation checks (`CONTINUITY_BREAK`), monotonic serial memory, write-restricted `NET-05` platform proofs, and `NET-06` `_moid.<domain>` DNS TXT anchors. See `TRUST_MODEL.md`.

## CLI Quickstart (`moid-cli 0.3.0`)

~~~bash
cargo install --path cli

# Validate a model manifest (Draft 2020-12 schema + DAG/contribution/identity rules)
moid validate examples/01_first_party_hybrid_policy.moid.yaml

# Inspect disclosure telemetry across all 6 tracked sections
moid inspect examples/01_first_party_hybrid_policy.moid.yaml

# Seal and verify a hierarchical JSONL ingestion catalog (CAT-01)
moid seal conformance/valid/06_hierarchical_ingestion.jsonl --non-draft

# Emit exact RFC 8785 JCS canonical bytes for detached signing (GPG / Minisign)
moid canonicalize moid-publisher.json > moid-publisher.jcs

# Verify a live publisher binding (HTTPS + NET-05 default-branch back-link + NET-06 DNS TXT + SIG-01)
moid validate-publisher --live https://moid.info/.well-known/moid-publisher.json
~~~

## Conformance Testing

~~~bash
cargo test --manifest-path cli/Cargo.toml
node conformance/run-ajv.mjs
~~~

## Publisher Verification (`holosacred`)

The canonical publisher namespace binding for `holosacred` is hosted at https://moid.info/.well-known/moid-publisher.json (anchored via `_moid.moid.info`).
