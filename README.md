# MoID: Modulus IDentifier Standard

**An identification system for artificial intelligence models and broader AI-related software.**

MoID (`moid`) provides a deterministic, machine-readable manifest (`moid.yaml`) to catalog model architectures (`modulus`), licensing tiers, active vs. total parameters, multi-teacher distillation genealogy, and tamper-evident training data provenance.

---

## Key Capabilities

* **Polymorphic `modulus` Classification:** Supports `transformer`, `transformation_model`, `state_space`, `graph_network`, `neural_operator`, and `hybrid` paradigms without forcing transformer-specific assumptions.
* **Sharded Checkpoint & MoE Support:** Tracks multi-file weight checksums (`safetensors`, `gguf`, `onnx`) alongside `total_count` and `active_count` parameters.
* **Cryptographic Data Provenance:** Links `moid.yaml` to an external `ingestion_manifest.jsonl` validated by `ingestion.schema.json` and sealed with a SHA-256 digest.
* **3-Tier Licensing + Openness Separation:** Pairs legal license tiers (`copycenter`, `copyleft`, `copyright`) with explicit availability flags (`open_weights`, `open_code`, `open_data`).

---

## Quick Start

Copy `template.moid.yaml` to the root of your repository as `moid.yaml`:

~~~yaml
$schema: "https://raw.githubusercontent.com/holosacred/moid/main/schema.json"
moid_version: "1.0.0"

modulus: "transformer"
moid: "holosacred/aether-7b-v1"
model_name: "Aether 7B Model"
organization: "Open Nexus Lab"

licensing:
  tier: "copycenter"
  spdx_license: "Apache-2.0"

access_control:
  open_weights: true
  open_code: true
  open_data: true
  reproducibility: "full"

domain_focus:
  primary: "physics"
  focus_weights:
    language: 0.20
    math: 0.30
    physics: 0.50

parameters:
  total_count: 7240000000
  active_count: 7240000000
  base_precision: "bf16"

checkpoints:
  - path: "weights/model-00001-of-00001.safetensors"
    format: "safetensors"
    precision: "bf16"
    quantization: "none"
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

data_provenance:
  total_tokens: 1800000000000
  ingestion_catalog_file: "ingestion_manifest.jsonl"
  ingestion_schema: "https://raw.githubusercontent.com/holosacred/moid/main/ingestion.schema.json"
  catalog_file_hash_sha256: "7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a"
~~~

---

## CLI Installation & Usage

Install the native `moid` binary directly from GitHub:

~~~bash
cargo install --git https://github.com/holosacred/moid --path cli
~~~

Common commands:

~~~bash
moid init --modulus transformer --id org/model-v1
moid hash weights/*.safetensors
moid seal ingestion_manifest.jsonl
moid validate moid.yaml --verify-weights
~~~
