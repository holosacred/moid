# MoID: Modulus IDentifier Standard

**An identification system for artificial intelligence models and broader AI-related software.**

MoID (`moid`) provides a deterministic, machine-readable manifest (`moid.yaml`) that classifies AI software across three orthogonal axes—computational mechanism (`modulus`), functional stack position (`stack_role`), and domain ontology (`domain_focus`)—paired with cryptographic checkpoint and training-data provenance.

---

## Core Taxonomy

* **Mechanism (`modulus`):** `transformer`, `transformation_model`, `state_space`, `graph_network`, `neural_operator`, or `hybrid`.
* **Stack Role (`stack_role`):** `generator`, `decision_policy`, `router`, `planner`, `verifier`, `critic_reward`, `world_model`, `perception_encoder`, `memory_indexer`, `orchestrator`, or `hybrid` (with optional `stack_spec` upstream/downstream graph links).
* **Domain Focus (`domain_focus`):** Open-ended capability weights (`language`, `math`, `physics`, `code`, `robotics`, `vision`, etc.).
* **Licensing & Access Separation:** Pairs 3-tier licensing (`copycenter`, `copyleft`, `copyright` + SPDX) with explicit availability flags (`open_weights`, `open_code`, `open_data`, `reproducibility`).
* **Tamper-Evident Provenance:** Links `moid.yaml` to an external `ingestion_manifest.jsonl` validated against `ingestion.schema.json` and sealed with a SHA-256 digest.

---

## CLI Installation & Usage

Install `moid` directly from GitHub:

~~~bash
cargo install --git https://github.com/holosacred/moid --path cli
~~~

Common commands:

~~~bash
# Scaffold a manifest for a specific architecture and stack role
moid init --modulus state_space --stack-role decision_policy --id org/policy-v1

# Hash checkpoint shards in parallel and write directly into moid.yaml
moid hash weights/*.safetensors --write moid.yaml

# Generate checkpoints from an existing Hugging Face / Zenodo SHA256SUMS file
moid hash --from-sha256sums SHA256SUMS --write moid.yaml

# Validate and seal ingestion_manifest.jsonl directly into moid.yaml
moid seal ingestion_manifest.jsonl --write moid.yaml

# Validate schema, JSONL catalog, and local checkpoint hashes
moid validate moid.yaml --verify-weights

# Print summary card or diff two manifest versions
moid inspect moid.yaml
moid diff v1/moid.yaml v2/moid.yaml
~~~

---

## Reusable GitHub Action

Validate `moid.yaml` in any repository with two lines of workflow YAML:

~~~yaml
- uses: holosacred/moid@v0.2.0
  with:
    manifest: moid.yaml
~~~
