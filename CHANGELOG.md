# Changelog

## v0.3.0 (2026-11-24)
- **Frozen Draft 2020-12 Schema Suite (`https://moid.info/schemas/v0.3.0/`):**
  - `moid.schema.json`, `common.schema.json`, `ingestion.schema.json`, and `publisher.schema.json` compile cleanly under Ajv 2020-12 `{ strict: true, strictRequired: true }` with 100% dual-validator parity against Rust `jsonschema 0.61.2` across **76 manifest-tracked expected-error assertions**.
  - Structured `modulus`, PROV-inspired N-ary `derivations[]`, bidirectional `disclosure_status` completeness across all 6 sections, strict `nonDraftStrict` digest/revision rules, and schema-enforced attestation format $\leftrightarrow$ identity matrix (PGP, SSH, Minisign, Sigstore OIDC/key, DSSE).
- **Hardened Publisher Trust Model (`TRUST_MODEL.md`, `PUB-01`, `NET-05`, `NET-06`, `SIG-01`):**
  - Per-platform `platform_proof_uri` allowlists rejecting dot segments (`.` / `..`), queries, fragments, percent-encoding, `refs/`, and commit SHAs; `NET-05` canonicalize-then-check, exact `<default_branch>/` prefix matching (blocking short SHAs and supporting slash-containing branch names), and strict HTTP redirect refusal.
  - Tier-1 live HTTPS authority, 365-day maximum binding lifetime, monotonic `--serial-state` memory (rollback & equivocation protection), `CONTINUITY_BREAK` warnings, `key_compromise` exclusion, and multi-record `NET-06` `_moid.<domain>` DNS TXT anchors.
- **Native Minisign & JCS Tooling (`moid-cli 0.3.0`):**
  - Added `moid canonicalize` for exact RFC 8785 JCS output, native `minisign-v1` signature verification (`minisign-verify`), `pgp-detached-v1` verification via `gpg`, and `--live` end-to-end URL/API/DNS verification in `moid validate-publisher`.

## v0.3.0-rc4 – v0.3.0-rc8 (2026-11-22 – 2026-11-24)
- Iterative red-team hardening across schema strictness, disclosure completeness, publisher freshness, proof-URI allowlists, and expected-error conformance coverage.
