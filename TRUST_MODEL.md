# MoID Publisher Trust & Revocation Model (v0.3.0-rc6)

## 1. Namespace Ownership (Tier-1 Qualification)
A publisher binding at `https://<domain>/.well-known/moid-publisher.json` proves only that `<domain>` authorizes `allowed_identities` for `namespace`. To qualify for **Tier 1** resolver precedence, a verifier MUST independently establish that `<domain>` is authorized to speak for `namespace` via one of three mechanisms:
1. **`domain_exact` (in binding):** `namespace == domain` (e.g., `moid.info/arbiter-nano-hybrid`). No external platform lookup is required.
2. **`platform_bidirectional` (in binding + `NET-05`):** The binding names `platform` (`github | huggingface | gitlab | codeberg`), `platform_account`, and a host-matched `platform_proof_uri` (`https://<platform-host>/<platform_account>...`). Under **`NET-05`**, the verifier fetches `platform_proof_uri` and confirms an explicit back-link to `https://<domain>` (or `https://<domain>/.well-known/moid-publisher.json`).
3. **Verifier-side local pin (never in publisher file):** A consumer's own local `moid-pins.json` mapping exact `(namespace, domain)` pairs. Publishers cannot self-assert pins.

Bindings that fail ownership verification cap at Tier 2 (authenticated authorship, unverified namespace claim).

## 2. Freshness, Replay Bounding & Monotonic Serials (`PUB-01`)
* **Maximum lifetime:** `0 < (expires_at - updated_at) <= 365 days` (31,536,000 seconds). Expired bindings MUST be rejected.
* **Monotonic serial memory:** Verifiers persist `(namespace -> highest_serial, jcs_digest)` locally (`--serial-state`). Any binding with `serial < highest_serial` is rejected as a replay/rollback. Any binding with `serial == highest_serial` and a different RFC 8785 JCS digest is rejected as equivocation.

## 3. Revocation Semantics
* **Timestamped attestations (`sigstore-bundle-v0.3` with Rekor log time, or RFC 3161 TSA):** A signature from a key listed in `revoked_identities[]` remains valid **if and only if** the trusted log timestamp is strictly earlier than `revoked_at` (`log_time < revoked_at`). Self-declared `asserted_at` is **never** trusted for revocation checks.
* **Untimestamped signatures (`pgp-detached-v1`, `ssh-sig-v1`, `minisign-v1`, raw `dsse-in-toto-v1`):** Because no trusted third-party signing time exists, revocation **retroactively invalidates all signatures** from that identity once published, unless accompanied by an independent RFC 3161 or transparency-log timestamp proof.

## 4. `key` Identity Public Key Resolution
For `identity.kind == "key"`, verifiers obtain the public key from (in order): (a) inline `public_key_pem` in the verified publisher binding, (b) `public_key_uri` over HTTPS, or (c) an out-of-band verifier trust store. In all cases, the verifier MUST confirm `sha256(SPKI_DER) == key_fingerprint` before verifying the signature.

## 5. Disclosure Coverage Semantics
`disclosure_status` measures whether substantive facts for a section appear in the manifest:
* `disclosed` / `partial`: MUST include at least one substantive field for that section.
* `undisclosed` / `unknown`: MUST NOT include any substantive fields (only `disclosure_status` and optional `evidence` documenting the non-disclosure).
