# MoID Publisher Trust & Revocation Model (v0.3.0-rc7)

## 1. Authority, Live Fetch & Key Continuity
* **Domain authority comes from HTTPS, not self-signatures:** A self-signed binding proves only possession of a key listed inside itself. **Tier 1** trust MUST originate from a **live HTTPS fetch** of `https://<domain>/.well-known/moid-publisher.json`. Cached, mirrored, or bundled copies cap at **Tier 2** unless their RFC 8785 JCS digest byte-matches a live-fetched binding already recorded in the verifier's local `--serial-state`.
* **`binding_signature` is for key continuity:** When a binding rotates (`serial > prev_serial`), verifying `binding_signature` against an identity in the *previous* binding's `allowed_identities` proves uninterrupted key-holder continuity across rotation. Rotations without a continuity signature MUST re-anchor through a live HTTPS fetch from `<domain>`.

## 2. Namespace Ownership (Tier-1 Qualification)
A live-fetched binding at `<domain>` qualifies for Tier 1 only when `<domain>` is authorized to speak for `namespace` via one of three mechanisms:
1. **`domain_exact`:** `namespace == domain`. **Required** for any namespace containing a dot (`.`); dotted namespaces cannot be claimed via third-party platforms.
2. **`platform_bidirectional` (`PUB-01` + `NET-05`):** The binding declares `platform` (`github | huggingface | gitlab | codeberg`), the platform's canonical `platform_account`, and a host-matched `platform_proof_uri`.
   * **Case normalization (`PUB-01`):** `namespace` is always lowercase, while `platform_account` preserves the platform's canonical casing (e.g., Hugging Face `Qwen` claims `namespace: "qwen"` with `platform_account: "Qwen"` and `platform_proof_uri: "https://huggingface.co/Qwen"`). `PUB-01` enforces `lowercase(platform_account) == namespace` and matches the proof URI account segment case-insensitively.
   * **Write-restricted proofs (Schema + `NET-05`):** `platform_proof_uri` MUST point only to account-owner-controlled content: the org/user profile page or a file on the **default branch** of a repository owned by `platform_account` (verified via platform API under `NET-05`). Paths containing `/discussions/`, `/issues/`, `/pull/`, `/pulls/`, `/merge_requests/`, `/wiki/`, `refs/pr` (including percent-encoded forms), or `#` fragments are hard-rejected.
   * **Back-link (`NET-05`):** The fetched profile or default-branch file MUST contain an explicit link back to `https://<domain>` or `https://<domain>/.well-known/moid-publisher.json`.
3. **Verifier-side local pins:** Consumers may configure local `(namespace, domain)` pins in verifier policy (e.g., `moid-pins.json`). Publishers cannot self-assert pins inside a binding.

## 3. Freshness, Replay Bounding & Monotonic Serials (`PUB-01`)
* **Maximum lifetime:** `0 < (expires_at - updated_at) <= 365 days` (31,536,000 seconds). Combined with the Tier-1 live HTTPS requirement, replaying a pre-revocation binding at Tier 1 requires defeating TLS; the 365-day ceiling bounds cached/Tier-2 staleness.
* **Monotonic serial memory:** Verifiers persist `(namespace -> highest_serial, jcs_digest)` in `--serial-state`, rejecting any `serial < highest_serial` (rollback) or `serial == highest_serial` with a differing digest (equivocation).

## 4. DNS TXT Anchor (`NET-06`)
When `dns_txt_anchor` is present, `PUB-01` requires `dns_txt_anchor == "_moid.<domain>"`. Under **`NET-06`**, the verifier queries DNS TXT records at `_moid.<domain>` and requires a record containing `v=moid1; jcs=<jcs_sha256>` matching the RFC 8785 JCS SHA-256 of the publisher binding (providing an out-of-band DNS anchor independent of the web host).

## 5. Revocation Semantics
* **Timestamped attestations (`sigstore-bundle-v0.3` with Rekor log time, or RFC 3161 TSA):** Signatures from an identity in `revoked_identities[]` remain valid **iff** `log_time < revoked_at`. Self-declared `asserted_at` is never trusted.
* **Untimestamped signatures (`pgp-detached-v1`, `ssh-sig-v1`, `minisign-v1`, raw `dsse-in-toto-v1`):** Revocation **retroactively invalidates all signatures** from that identity unless accompanied by an independent transparency-log or RFC 3161 timestamp proof.

## 6. `key` Identity Public-Key Resolution
For `identity.kind == "key"`, verifiers obtain the public key from inline `public_key_pem`, HTTPS `public_key_uri`, or an out-of-band trust store, and MUST verify `digest_alg(SPKI_DER) == key_fingerprint` using the digest algorithm named in the `key_fingerprint` prefix (`sha256:`, `sha512:`, or `blake3:`).

## 7. Disclosure Coverage Semantics
`disclosure_status` measures whether substantive facts for a section appear in the manifest:
* `disclosed` / `partial`: MUST contain at least one substantive field (extension `x-*` keys never satisfy disclosure).
* `undisclosed` / `unknown`: MUST NOT contain substantive fields or `x-*` extension keys (only `disclosure_status` and optional `evidence` are permitted).
