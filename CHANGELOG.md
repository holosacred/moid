# Changelog

## v0.3.0-rc7 (2026-11-24)
- **Write-Restricted Platform Proof URIs:** Schema `not` pattern rejects user-writable paths (`/discussions/`, `/issues/`, `/pull/`, `/pulls/`, `/merge_requests/`, `/wiki/`, percent-encoded equivalents, `refs/pr`, and `#` fragments); `NET-05` restricts proofs to org/user profiles or default-branch files on owned repositories.
- **Binding Authority, Continuity & DNS Anchor (`TRUST_MODEL.md`, `PUB-01`, `NET-06`):**
  - Specified that Tier 1 requires a live HTTPS fetch from `<domain>/.well-known/moid-publisher.json`, and `binding_signature` provides key continuity across rotations (not domain authority).
  - Specified `dns_txt_anchor` (`^_moid\.<hostname>$`, `PUB-01` enforces `_moid.<domain>`) and added `NET-06` (`--dns-txt-file`) checking `v=moid1; jcs=<jcs_sha256>`.
- **Four Pre-Freeze Fixes:**
  - Dotted namespaces schema-require `namespace_claim.mode == "domain_exact"`.
  - `PUB-01` enforces case-insensitive `platform_account == namespace` (supporting mixed-case platform orgs such as Hugging Face `Qwen`).
  - `key_fingerprint` uses the digest algorithm named in its prefix (`sha256:`, `sha512:`, `blake3:`) over SPKI DER bytes.
  - Forbidden `x-*` extension keys inside `modulus` when `disclosure_status` is `undisclosed` or `unknown`.

## v0.3.0-rc6 (2026-11-24)
- Removed `policy_pinned`, added 365-day cap and monotonic serials, enforced non-empty `disclosed`/`partial` sections, aligned 253-char domain slugs, and added expected-error `manifest.json`.
