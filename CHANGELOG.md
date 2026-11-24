# Changelog

## v0.3.0-rc8 (2026-11-24)
- **Per-Platform Proof-URI Allowlists:** Replaced the `rc7` deny-list on `namespace_claim.platform_proof_uri` with strict positive allowlists for `github`, `huggingface`, `gitlab`, and `codeberg` (profile pages or `blob`/`src/branch` file paths only—blocking queries, fragments, `/issues`, `/actions`, `/commit`, `/compare`, `/forks`, and percent-encoded paths) plus schema and CLI rejection of 40/64-hex commit SHAs (closing GitHub fork-network commit serving).
- **Exact Default-Branch Verification (`NET-05`):** Added `--default-branch` enforcement in `moid validate-publisher` rejecting non-default branches and commit SHA refs outright.
- **Continuity & Rotation Semantics (`TRUST_MODEL.md`, `PUB-01`, `NET-06`):**
  - Specified exact `binding_signature` signed bytes (RFC 8785 JCS of full binding including `binding_signature`).
  - Added `WARN [CONTINUITY_BREAK]` reporting (`--continuity-signer`, `--fail-on-continuity-break`) and rejected `key_compromise`-revoked identities as continuity signers.
  - Documented multi-record `v=moid1;` DNS TXT coexistence during rotation, DNSSEC independence bounds, and the `v0.3` limitation for platform accounts with characters outside `namespaceSlug`.

## v0.3.0-rc7 (2026-11-24)
- Write-restricted proofs, live-fetch/continuity trust model, `NET-06` DNS TXT anchor, dotted-namespace `domain_exact` enforcement, case-insensitive `platform_account`, and `FOCUS-01` coverage.
