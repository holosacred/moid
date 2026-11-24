# Changelog

## v0.3.0-rc6 (2026-11-24)
- **Publisher Trust Model Hardening (`TRUST_MODEL.md`, `publisher.schema.json`, `PUB-01`, `NET-05`):**
  - Removed publisher-asserted `policy_pinned` mode (pins are strictly verifier-side configuration).
  - Required `platform` (`github | huggingface | gitlab | codeberg`), `platform_account`, and host-matched `platform_proof_uri` for `platform_bidirectional`; added account-path verification in `PUB-01` and offline-testable `NET-05` back-link verification (`--backlink-file`).
  - Added 365-day maximum binding lifetime (`expires_at - updated_at <= 365d`) and monotonic `serial` persistence (`--serial-state`) rejecting rollbacks and equivocation.
  - Specified revocation semantics (trusted log time vs. retroactive invalidation of untimestamped signatures) and `key` identity public-key resolution (`public_key_uri` / `public_key_pem`).
- **Disclosure Completeness:** Enforced non-empty substantive content via `anyOf` across all 6 `disclosure_status` sections whenever status is `disclosed` or `partial` (mirroring `rc5`'s forbid rule for `undisclosed`/`unknown`).
- **Slug Alignment:** Extended `namespaceSlug` to RFC 1035/1123 253-char hostnames (63 chars per label) and aligned `moidSlug` identically.
- **Expected-Error Conformance Suite:** Added `conformance/manifest.json` asserting exact RFC 6901 `instancePath` + Ajv keyword / Rust rule ID on every negative fixture; rebuilt isolated `G06` and `B`-series fixtures on valid `rc6` bases.

## v0.3.0-rc5 (2026-11-22)
- Full Ajv strict mode (`strict: true, strictRequired: true`), closed `G01`–`G04`, publisher freshness fields, and `PUB-01`.
