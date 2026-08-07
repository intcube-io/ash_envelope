# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](Https://conventionalcommits.org) for commit guidelines.

<!-- changelog -->

## Unreleased

### Encrypted-blob HTTP serving — upstream proxy contract (SR32):

- `ash_storage`'s `AshStorage.Plug.Proxy` now accepts `:actor_assign` (atom assigns-key or 1-arity function) and `:max_lifetime_seconds` (positive-integer cap on a signed URL's *remaining* lifetime). Together they make the bundled proxy sufficient to drive `AshEnvelope.BlobIO.KeyManagers.KeyGrants` — the actor is threaded onto `bctx.actor` for both the blob-aware (`BlobIO.read/3`) and key-only (`BlobIO.read_key/4`) paths, and signed URLs with too-long remaining lifetimes are refused at the proxy.
- The recommended wiring lives in `documentation/topics/how-envelope-encryption-works.md` under "Serving encrypted blobs over HTTP" and the `KeyGrants` BlobIO manager moduledoc cross-references it. SR32 in the risk assessment is rewritten as a documentation + dep-version requirement (replacing the prior generator-output framing).
- ⚠ `:actor_assign` is load-bearing for the `KeyGrants` manager — without it `bctx.actor` is `nil` and the manager's policy check has no principal. The outer-auth pipeline (`require_authenticated_user`, Guardian, etc.) must run *before* the proxy in the router scope; the bearer alone is not authentication.

### Retired briefly-shipped `mix ash_envelope.gen.proxy_route`:

- An intermediate hand-written-controller generator (`mix ash_envelope.gen.proxy_route`) shipped earlier in this unreleased development cycle to work around `AshStorage.Plug.Proxy`'s lack of actor threading. With the upstream change above the generator is no longer load-bearing — a 6-line `forward "/storage", AshStorage.Plug.Proxy, …` replaces an ~80-line custom controller — so the task and its test are removed in the same pass.
- If you ran the previous version of the generator and committed its output, delete the generated controller and replace your router scope with the upstream-proxy `forward` block per the topic doc. The signing-secret config key is unchanged; the encryption layer's `:proxy_base_url` is unchanged; the 300-second cap is preserved.

### Field encryption with optional AAD binding (`encrypt/3` / `decrypt/3`):

- `AshEnvelope.encrypt/2` and `decrypt/2` are replaced by `encrypt/3` and `decrypt/3` with optional `:context` AAD via the third argument. Existing callers (`encrypt(plaintext, key)`) work unchanged — the `opts` arg defaults to `[]`, and empty AAD matches the historical wire format, so ciphertexts written by previous releases decrypt fine.
- New: passing `:context` (typically `to_string(record.id)`) binds the ciphertext to a row. A DBA who swaps `body_ciphertext` between rows triggers `:decryption_failed` instead of disclosing one row's body under another row's identity — the field-level analogue of `AshEnvelope.SealKey`'s AAD binding for ephemeral worker rows.
- Use-case framing (in the moduledoc and tutorial): these functions are the **symmetric step of the multi-recipient grant pattern** for non-blob fields, not generic field encryption. Encrypt the field once with a per-record DEK, then wrap that DEK into one grant row per recipient via `AshEnvelope.KeyGrants`. For **single-key** field encryption with one app-wide vault key (no per-record DEK, no grants), use [`ash_cloak`](https://hexdocs.pm/ash_cloak) — the two libraries cover different use cases.
- Note: an earlier unreleased iteration removed these functions on the (mistaken) assumption they duplicated cloak's surface. They don't — cloak's vault model doesn't accommodate the per-record DEK pattern. The functions are restored with AAD support and clearer framing.

### Breaking changes (`AshEnvelope.Storage` removed; BlobIO is the new integration point):

- The `AshEnvelope.Storage` Spark extension, `AshEnvelope.Storage.Encrypted` wrapping service, `AshEnvelope.Storage.Plug`, the `encryption do ... end` DSL block, and the `:simple` / `:actor_wrapped` / `:key_grants` mode discriminator are all removed. Replaced by two `AshStorage.Encryption.KeyManager` implementations that plug into the standard `AshStorage.Layer.Encryption`:
  - `AshEnvelope.BlobIO.KeyManagers.Asymmetric` — successor to `:actor_wrapped`. DEK wrapped with the actor's X25519 public key.
  - `AshEnvelope.BlobIO.KeyManagers.KeyGrants` — successor to `:key_grants`. Fan-out into `AshEnvelope.KeyGrants` via BlobIO's `finalize_wrapped_dek` callback (no more process-dictionary handoff).
- The `:simple` mode is gone. The risk-assessment finding T1 (`:simple` mode + DBA → plaintext disclosure, Inacceptable) is resolved by removing the code path; there is no replacement KeyManager in `ash_envelope` for the "DEK alongside ciphertext" pattern. Single-recipient deployments use `Asymmetric`; deployments that want a Cloak vault use the upstream `AshStorage.Encryption.KeyManagers.Cloak`.
- `ash_storage` is now pinned to the `wln/ash_storage` `blobio5/serving-disposition` branch until BlobIO lands on `main`.
- `AshEnvelope.Reconcile` is now the sole source for `domain`, `key_grants_resource`, `actor_public_key_attribute`, `actor_private_key_attribute`, and the related `key_grants_*` field overrides. The compile-time single-source rule and the storage-fallback branch in `Info.context/1` are removed. Migration: move the equivalents from your old `encryption do ... end` block into `reconcile do ... end`.

### Backup-key escrow (opt-in):

- New: `:backup_public_key` configuration. When set, both KeyManagers (`Asymmetric`, `KeyGrants`) additionally wrap each DEK with this X25519 public key and embed the result in encryption-layer metadata under `wrapped_dek["backup"]`. Strict opt-in; default is off.
- The wrap is tagged with a short fingerprint (`key_id`) of the public key, so rotation tooling can find stale blobs without unwrapping anything.
- Recovery: `AshEnvelope.recover_dek/2` and `AshEnvelope.recover_plaintext/3`. Both take the backup private key directly and bypass the configured KeyManager — the recovery path is intentionally narrow.
- Rotation: configure `:backup_public_key_previous` (the outgoing key) alongside the new `:backup_public_key`, then run `mix ash_envelope.rotate_backup_key --domain MyApp.Storage --resources MyApp.Blob --previous-private-key-path /secure/k1.priv`. The CLI exits non-zero if any blob remains wrapped to a non-current key after the pass; `--check-only` provides a pre-flight count.
- ⚠ SECURITY: the backup private key opens every blob ever written. Custody must be at least as strong as plaintext protection — cold storage, KMS / HSM, or split-key only (EA9 in the risk assessment). Storing it in a column or environment variable defeats the purpose.

### Security review

A full SQUARE-based risk assessment of the library was completed on 2026-05-11 and 2026-05-12. It identifies the library's threat model, rates each finding using BSI 200-2 damage potential and ISO/IEC 18045 attack potential, and derives 18 security requirements and 8 environmental assumptions. The full assessment lives in [`documentation/security/risk-assessment/`](https://github.com/intcube-io/ash_envelope/blob/main/documentation/security/risk-assessment/00_overview.md), and the user-facing summary is in [`documentation/topics/how-envelope-encryption-works.md`](documentation/topics/how-envelope-encryption-works.md) under "Security Posture". The next review is due 2027-05.

### Breaking changes (`AshEnvelope.KeyGrants`, `AshEnvelope.GrantRequests`):

- **`authorize?` now defaults to `true`** on `KeyGrants.Config` and `GrantRequests.Config`. Direct calls from application code therefore go through Ash's policy authorizer, and the grants / grant-requests resources must define policies. Migration paths:
  - Run (or re-run) `mix ash_envelope.gen.key_grants` / `gen.grant_requests` — the generator notice now scaffolds a baseline `policies do ... end` block with `Ash.Policy.Authorizer` configured.
  - Add policies to your existing resources manually.
  - Explicitly pass `authorize?: false` on the Config struct while migrating (only for trusted system-side paths).
  - Reconciliation (`AshEnvelope.Reconcile.Runner`) already passes `authorize?: false` internally for the system-side revoke path, so policies do not need to accommodate it.

### Improvements:

- New `AshEnvelope.TestHelpers.assert_policies_defined!/2` — integrator-side assertion that a grants resource has `Ash.Policy.Authorizer` configured, non-empty policies, and (by default) at least one policy that could apply to each of `:read` / `:create` / `:destroy` action types the resource defines. Pass `actions: [:read, :create, :update]` for a `GrantRequests` resource, or `actions: []` to disable the coverage tier. Designed to be called from the integrator's `ExUnit` suite.
- `mix ash_envelope.gen.key_grants` notice now leads with an `AshCloak`-based encrypted-at-rest example for principal private keys, with the plain `:binary` variant demoted to a test-only fallback. The required nature of private-key custody is surfaced as a `⚠ SECURITY` block before the snippet rather than as a footnote.
- `mix ash_envelope.gen.key_grants` and `gen.grant_requests` notices now include `Ash.Policy.Authorizer` and a baseline `policies do ... end` block on the scaffolded resource.
- `AshEnvelope.hkdf_sha256/4` is now public (`@doc false`) so the ≤32-byte length cap can be verified directly. Behaviour is unchanged.
- New module-level documentation table listing the library's cryptographic primitives and their BSI TR-02102 horizon (2030).

### Fixes:

- `ValidateConfig` no longer false-positives by treating DSL defaults as explicitly-set values. The three reconcile fields with defaults (`key_grants_subject_id_attribute`, `key_grants_principal_id_attribute`, `key_grants_dek_attribute`) are `required: false` with no DSL default; `Info.context/1` applies `:blob_id` / `:user_id` / `:wrapped_dek` as fallbacks at use time.

### Breaking changes (`AshEnvelope.Reconcile`):

- Removed `:preview` mode. Hosts that want a preview-then-confirm UX should call `Runner.plan/2` directly and then `Runner.apply_plan!/3` on confirm. The `:ash_envelope_reconcile_plan` metadata key, `Mode.merge_plan_metadata/2`, `Plan.merge/2`, and the `:unfulfillable` field on `Plan` were all part of this path and are now gone.
- Removed the `:any_authorized` granter strategy. Loading a third party's decrypted private key server-side to rewrap from is incompatible with envelope encryption's threat model — fall through to `:request` and have an authorized user fulfill from their session instead.
- Removed `{Mod, :fun}` and `{Mod, :fun, args}` host-callback granter strategies. The `:request` strategy plus the `:when` predicate on tuple-form strategies cover the same extension cases.
- Removed `Runner.run_for_principal/4`. Callers should use `Runner.run/3` directly with a `[{principal_id, subject_id}, ...]` pair list.

## v0.1.0 (2026-03-10)

Initial release.

### Features:

- AES-256-GCM encryption/decryption primitives
- DEK wrapping/unwrapping for envelope encryption
- Key grant management (create, resolve, share, revoke)
- Mix task generator for key grants infrastructure scaffolding
