# MoID: Modulus IDentifier Standard

**An identification and manifest specification for artificial intelligence models, transformation paradigms, and AI-related software.**

MoID (`moid`) provides a deterministic, machine-readable standard to catalog AI model lineages, computational mechanics (`modulus`), licensing constraints, distillation genealogies, and training data provenance.

---

## Why MoID?

Modern AI software spans far beyond static Transformer checkpoints—encompassing continuous field operators, state-space models, and tokenless graph architectures. MoID replaces loose Markdown documentation with a structured, verifiable manifest (`moid.yaml`).

* **Paradigm Agnostic:** Uses `modulus` as a polymorphic classifier (`transformer`, `transformation_model`, `state_space`, `graph_network`).
* **Complete Ingestion Lineage:** References external JSONL catalog files itemizing every document, URL, or dataset ingested during training.
* **3-Tier Licensing:** Enforces clear classification across `copycenter` (MIT/Apache), `copyleft` (GPL/CC-BY-SA), and `copyright` (Proprietary).
* **Distillation Genealogy:** Tracks multi-teacher lineage, loss targets, and compression metrics.

---

## Quick Start

Drop a `moid.yaml` file into the root of your model repository:

```yaml
$schema: "[https://raw.githubusercontent.com/holosacred/moid/main/schema.json](https://raw.githubusercontent.com/holosacred/moid/main/schema.json)"
moid_version: "1.0.0"

modulus: "transformer"
moid: "organization-name/model-name-v1"
name: "Aether 7B Model"
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
  total_count: 7000000000
  precision: "bf16"
  sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

data_provenance:
  total_tokens: 1800000000000
  ingestion_catalog_file: "ingestion_manifest.jsonl"
  catalog_file_hash_sha256: "7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a"
