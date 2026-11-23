# Changelog

## v0.3.0-rc5 (2026-11-22)
- **Full Ajv Strict Compliance:** Added explicit `type` and `required` property stubs across all Draft 2020-12 subschemas so `common`, `moid`, `ingestion`, and `publisher` compile with `strict: true` and `strictRequired: true` enabled (zero relaxed flags).
- **Closed Schema Loopholes (G01–G04):**
  - `weight_initialization: "from_model"` now requires at least one external `externalTargetRef` parent (local-only quantize rejected).
  - Enforced attestation format $\leftrightarrow$ `asserted_by.identity.kind` matrix and added `minisign-v1` format.
  - Non-draft `third_party_description` manifests require `manifest_assertion.evidence` (`minItems: 1`).
  - `disclosure_status: "undisclosed" | "unknown"` now forbids substantive section data fields (only `disclosure_status` and `evidence` allowed).
- **Hardened Publisher Binding (`publisher.schema.json` + `PUB-01`):**
  - Added required `serial`, `expires_at`, `namespace_claim` (`domain_exact | platform_bidirectional | policy_pinned`), hostname validation on `domain`, and structured `revoked_identities[].revoked_at`.
  - Allowed domain-exact namespaces (e.g., `moid.info/model`) in `namespaceSlug` and `moidSlug`.
  - Added CLI rule `PUB-01` rejecting `expires_at <= updated_at`, allowed/revoked identity overlap, and `domain_exact` namespace mismatches.

## v0.3.0-rc4 (2026-11-22)
- Upgraded to Draft 2020-12, `moid.info` `$id` URIs, structured `modulus`, PROV-inspired N-ary `derivations[]`, `x-verification` `{ verifier, assurance }`, prefixed `code_commit`/`revision`/`digest`, and dual Rust + Ajv conformance testing.
