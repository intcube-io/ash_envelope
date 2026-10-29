# Step 9: Inspection

Self-review of the requirements set against the SQUARE inspection checklist. Performed by the assessor; an independent reviewer (a second maintainer or external auditor) should re-run this checklist before a major release.

## Organization

| Question | Result | Notes |
|---|---|---|
| Are all requirements written at a consistent and appropriate level of detail? | ☑ Pass | SRs state "what", not "how"; CC-class hints anchor terminology. |
| Is the implementation priority of each requirement included? | ☑ Pass | Step 8 assigns P1–P3 to every SR and EA. |
| Do the requirements include all known customer and system needs? | ☑ Pass | Coverage check in step 6 confirms every threat with risk ≥ Tolerable is addressed; T5 and T11 are deliberate retentions. |
| Is any necessary information missing from a requirement? | ☑ Pass | Each SR cites its goal, threat, and CC class. |
| Are there areas not addressed in the document that should be? | ☑ Pass (with note) | The assessment does not cover the `mix.gen.*` task code paths beyond SR5's policy. A future revision could rate the generator code's own attack surface; deferred. |
| Is the document well organized? | ☑ Pass | Numbered files, traceability matrix, overview index. |
| Are there requirements that contain unnecessary design detail? | ☑ Pass (with note) | SR3 names AES-256-GCM and X25519 explicitly. This is intentional (the cryptosystem identity is part of the library's contract), not a leak of design detail into requirements. |

## Correctness

| Question | Result | Notes |
|---|---|---|
| Do any requirements conflict with or duplicate other requirements? | ☑ Pass | The active SRs are non-overlapping (different threats, different layers). |
| Is each requirement written in clear, concise, unambiguous language? | ☑ Pass | Verb tense ("shall"), no vague verbs ("improve", "support"). |
| Is each requirement verifiable by testing, demonstration, review, or analysis? | ☑ Pass | See verification table below. |
| Is each requirement in scope for the project? | ☑ Pass | All SRs are within the library's code, documentation, or maintainer process. EAs are explicitly out-of-library. |
| Is each requirement free from content and grammatical errors? | ☑ Pass | Single-author pass. |
| Can all requirements be implemented within known constraints? | ☑ Pass | Cost analysis in step 8 confirms all P1 items are Low/Medium cost. |

### Verification approach per SR

**CI note (2026-10 review pass).** Many rows below say "CI test". From 2026-06-01 until the merged PR #4, `.github/workflows/elixir.yml` delegated to a reusable workflow that no longer resolved; every run was a startup failure and no check ran, so "verified by CI" claims in that window were backed only by local test runs. PR #4 replaced it with a self-contained workflow (format, `compile --warnings-as-errors`, `credo --strict`, `test`, `sobelow`). PR #14 moves the CI matrix to Elixir 1.20 / OTP 28 (the 1.20 type checker reports warnings 1.18 did not) and adds a dependency-audit step (`mix hex.audit`, `mix deps.audit`). The same PR updates Ash to 3.37.2: Hex flags Ash versions below 3.37 for EEF-CVE-2026-82745, and Ash is the policy engine SR13 and EA3 rely on; the update also clears the two transitive `mix deps.audit` advisories found by the review (`req` < 0.6.0, `decimal` < 3.0.0). The review's own tool run on b799f14 found no DEK, private key or plaintext reaching `Logger` or exception messages in `lib/` (SR10). Dialyzer (four dead-clause warnings, no bugs) is not in CI.


| ID | Verification approach |
|---|---|
| SR2 | Review: documentation completeness checklist (per-KeyManager). |
| SR3 | Test: assert algorithm identity via `:crypto.crypto_one_time_aead` arguments observed in a tracing test; visual review of `lib/ash_envelope.ex`. |
| SR4 | Test: `hkdf_sha256/4` rejects length > 32. |
| SR5 | Test: invoke generator in a test sandbox; assert generated migration / resource uses an encrypted column type. |
| SR6 | Review: documentation completeness checklist. |
| SR7 | Review: documentation completeness checklist. |
| SR8 | Property test: random `(principal, subject)` pairs vs `Ash.can?` ground truth. (d)-(g): `runner_test.exs` describes "policy-protected grants table", "unresolvable policy checks", "expired grants" and the `:actor` fall-through test; `sync_principal_lookup_test.exs` ("scope resolving to an empty list"); `sync_principal_update_scope_test.exs`. |
| SR9 | Test: dispatch async-mode reconciliation; assert `Oban.Job.args` contains only ids (and the serialized tenant, `multitenancy_test.exs` "async job args carry the tenant"). |
| SR10 | Test: log-capture wrapper around public-API exercise (incl. both BlobIO KeyManagers); byte-subsequence scan for key/plaintext bytes. |
| SR13 | Test: confirm public API call sites default to `authorize?: true`. Actor threading: `grants_policies_test.exs` and `blob_io/key_managers/key_grants_policies_test.exs` run `KeyGrants`, `GrantRequests` and the BlobIO manager against scaffold-shaped actor-scoped policies under `authorize?: true`; `grant_requests_test.exs` "fulfill/7 target verification". |
| SR14 | Test: helper raises for fixtures without an authorizer, with an empty `policies do … end`, and with policies that don't cover a required action type (e.g. a `:read`-only policy on a resource that also defines `:create` / `:destroy`); passes for an always-policy fixture; passes when `actions: []` disables the coverage tier; skips action types the resource does not define; raises for a wide-open resource and for a permissive `bypass`, and passes for both with `allow_permissive: true` (describe "permissive-coverage detection"). |
| SR15 | Concurrency test: two concurrent `create/6` invocations produce exactly one row. `share/6` idempotency and expired-row re-issue: `grants_policies_test.exs` ("share succeeds and is idempotent", "share re-issues past an expired row the read policy filters out"). |
| SR16 | Review: documentation completeness checklist. |
| SR17 | Process: annual maintainer review entry in CHANGELOG. |
| SR19 | Test: with `:backup_public_key` configured, both KeyManagers' `wrap_dek` returns a wrapped map with a `"backup"` field tagged with the configured key's fingerprint; `AshEnvelope.recover_dek/2` round-trips; no configured KeyManager unwraps from the backup field. Recovery-path lengths: `backup_integration_test.exs` (truncated tag, wrong IV length, short DEK). |
| SR20 | Test: prepare a stale blob (wrapped to an old key, current config points at a new key), run `BackupRotation.rotate_resource/2` in `check_only: true`, assert `remaining_stale > 0`; assert the Mix task's non-zero exit path is reached for the same inputs. Fresh-row re-wrap, already-rotated no-op and per-reason failures: `backup_integration_test.exs`; strict switches: `test/mix/tasks/ash_envelope_rotate_backup_key_test.exs`. |
| SR21 | Test: `test/ash_envelope/seal_key_test.exs` covers seal/unseal round-trip with and without context, AAD mismatch fails closed (`:decryption_failed`), unsealing without context what was sealed with context fails, single-bit ciphertext tamper fails authentication. |
| SR22 | Test: `test/ash_envelope/seal_key_test.exs` covers rejection of unknown version byte and truncated input (`:unknown_seal_format`). |
| SR23 | Test: `test/ash_envelope/key_grants_ephemeral_test.exs` "renew_ephemeral_with_actor leaves existing row intact when actor has no grant" — `renew_ephemeral_with_actor/5` short-circuits in the `with` chain on resolve failure; the existing ephemeral row remains. Seal-before-destroy: `key_grants_ephemeral_test.exs` ("renew_ephemeral leaves the existing row intact when sealing fails"). |
| SR24 | Test: the v0.3.0 `KeyGrantsTest` suite still passes without setting `:expires_at_attribute`; no rows touch the new schema columns. Combined with the existing log-safety / Oban-args / reconcile-invariant tests, the non-users-retain-v0.3.0 property holds. |
| SR25 | Code review: no `:update :extend_expiry` or equivalent action exists on `KeyGrants` or its config. `renew_ephemeral/5` always invokes `destroy_for_subject` + `create_ephemeral`. |
| SR26 | Review: `documentation/topics/expiring-grants.md` "Rotating the seal key" section documents the drain-only runbook; no `mix ash_envelope.rotate_seal_key` task exists. |
| SR27 | Review: `documentation/topics/expiring-grants.md` "Interaction with reconcile" subsection and the `AshEnvelope.KeyGrants` moduledoc both state the policy-vs-`expires_at` invariant explicitly. |
| SR28 | Contract test: invoke `AshStorage.Layer.Encryption.direct_upload/2` against an encrypted-attachment context and assert the return is `{:error, _}`. Test must fail if a future ash_storage relaxes the rejection. |
| SR29 | Test: configure a variant with a transform that raises mid-call; trigger generation; assert the source temp file (resolved from the variant generator's temp_dir) is absent after the crash. |
| SR30 | Review: storage-services topic and getting-started tutorial both state the credential-custody invariant. |
| SR31 | Review: `expiring-grants` topic, storage-services topic, and `KeyGrants` BlobIO manager moduledoc all reference the integrator's proxy-auth responsibility. |
| SR32 | Review: `mix.exs` pins an `ash_storage` version that includes the `:actor_assign` + `:max_lifetime_seconds` options on `AshStorage.Plug.Proxy`; `how-envelope-encryption-works` topic contains the "Serving encrypted blobs over HTTP" section showing the canonical `forward` configuration with both options set, the outer-auth-pipeline-comes-first instruction, and the rotation cadence; `AshEnvelope.BlobIO.KeyManagers.KeyGrants` moduledoc cross-references that section. Upstream contract is locked by `ash_storage`'s own `test/ash_storage/plug/proxy_test.exs` `:actor_assign` and `:max_lifetime_seconds` describe blocks (7 tests) — when ash_envelope pins a new ash_storage version, smoke that those tests still pass under the new pin. |
| SR33 | Review: the `how-envelope-encryption-works` topic contains a "Storage-service redundancy (Mirror)" subsection covering all four required points (fan-out semantics, AEAD-bounded read fall-through, orphans-as-Av-not-C framing, monitor + reconciliation recommendation) and the T23 row in `04_risk_assessment.md` cross-references it by name. |
| SR34 | Test: `test/ash_envelope/reconcile/validate_config_test.exs` exercises both a valid config (compiles cleanly) and known-bad configs (missing required fields, mismatched grant-resource shape) and asserts `Spark.Error.DslError`. New transformer/verifier modules added to `lib/ash_envelope/**/transformers/` must arrive with equivalent test files; review-time check. Granter-chain and `grant_requests_resource` checks: `validate_config_test.exs` (three tests added in PR #14); the async-without-Oban check is not exercised by a test (Oban is always compiled in the test environment). |
| SR35 | Review (per `mix ash_envelope.gen.*` task source under `lib/mix/tasks/`): the task's `igniter/1` callback issues only `Igniter.add_notice/2`, never `File.write/2`, `File.cp/2`, or `System.cmd/3`. The `rotate_backup_key` task is the documented exception that reads (not writes) an integrator-supplied path. |
| SR36 | Test: `test/ash_envelope/reconcile/multitenancy_test.exs` (sync fan-out tenant-scoped, issuance and revocation stay in the triggering tenant, job args carry the tenant, worker restores it, `Ash.can?` evaluated under the job's tenant). |
| SR37 | Test: `runner_test.exs` failure-injection tests (grant failure, revoke failure, plan errors surface; exhausted chain is not a failure); `async_test.exs` ("returns {:error, aggregate} when a pair fails, so Oban retries"). In-transaction async insert: code review of `SyncPrincipal.change/3`. |
| SR38 | Test: `ash_envelope_test.exs` ("fetch_actor_key/2", inner ciphertext not 32 bytes); `blob_io/key_managers/asymmetric_test.exs` (degenerate keys return `:invalid_actor_key`); `blob_io/key_managers/key_grants_test.exs` ("wrap_dek/3 validates the manager options up front"); `grant_requests_test.exs` (keyless target counted as an error; `revoke_pending_for` halts on first failure). |
| SR39 | Test: `test/mix/tasks/ash_envelope_gen_key_grants_test.exs` and `ash_envelope_gen_grant_requests_test.exs` (layer entity with `metadata_key`, blob-id FK and migration reference, `subject_id_for` mapping, actor-threaded revoke handler, `primary? true` create). Gap: no runtime round-trip of `subject_id_for` / `subject_load` through an attachment. |

## Traceability

| Question | Result | Notes |
|---|---|---|
| Is each requirement uniquely and correctly identified? | ☑ Pass | SR2–SR17, SR19, SR20, SR21–SR31 (active subset; SR1, SR11, SR12, SR18 retired in v0.3.0) and EA1–EA11 minus EA7 are unique. The v0.4-dev pass added SR32-SR35; the 2026-10 review pass adds SR36-SR39 and controls C30-C39. |
| Does each requirement trace to at least one security goal? | ☑ Pass | Every SR row in step 6 cites a goal. |
| Does each requirement trace to at least one threat (or is it justified as defence in depth)? | ☑ Pass | SR4 is explicit defence-in-depth, justified. |
| Is every Inacceptable / Undesirable threat addressed by at least one requirement or accepted explicitly? | ☑ Pass | Coverage check in step 6 confirms this. T5, T9, and T11 are explicitly retained / out of scope. |

## Findings & actions

| Finding | Severity | Action | Status |
|---|---|---|---|
| SR2's "documentation shall live alongside the user-facing tutorials" is verifiable but coarse — the next revision should specify which moduledoc sections must be cross-referenced. | Minor | Per-mode threat-model section drafted in `documentation/topics/how-envelope-encryption-works.md` under "Security Posture"; rewritten to per-KeyManager framing in v0.3.0. | ✅ Resolved (v0.3.0) |
| SR7 documents the envelope-substitution bound but does not commit to a specific phrasing in the moduledoc. | Minor | "Envelope integrity bound" section drafted in `documentation/topics/how-envelope-encryption-works.md`. | ✅ Resolved (v0.2.0) |
| SR17's "annual review cadence" is process-oriented; verification depends on the project consistently producing a changelog entry. | Minor | `CHANGELOG.md` now has a `## Security review` section anchoring the 2026-05 assessment and naming the next review (2027-05). | ✅ Resolved (v0.2.0) |
| T1 (`:simple`-mode DBA disclosure) and T9 (Plug bypass) were Inacceptable / Undesirable findings driven by code paths (the `:simple` storage mode and `AshEnvelope.Storage.Plug`) that v0.3.0 removed. | Major | Code paths removed; T1 / T9 retired from the risk matrix. SR1, SR11, SR12, SR18, and EA7 retired with them. | ✅ Resolved (v0.3.0) |
| The assessment does not rate the integrity / availability of the Spark DSL transformers themselves (e.g. could a malformed DSL load lead to a runtime crash that fails open). | Minor | Rated as T25 (Undesirable; mitigated by SR34's transformer test-coverage obligation, which the existing reconcile test suite already satisfies). | ✅ Resolved (v0.4-dev) |
| The `mix ash_envelope.gen.*` task code paths have not been reviewed for their own attack surface (e.g. argument injection into file paths). | Minor | Rated as T26 (Tolerable). The generator pattern in this library is notice-only — `Igniter.add_notice/2` emits guidance text rather than writing files — which structurally avoids the argument-injection-into-file-paths surface. SR35 locks the invariant per task. | ✅ Resolved (v0.4-dev) |
| Scope expansion in v0.4-dev brings T9 (proxy bypass) back into scope. The encryption layer forces proxy URLs, but the proxy *route* and its auth middleware remain integrator-side surface — SR31 documents the responsibility but does not provide a generator/template. `AshStorage.Plug.Proxy` did not thread an actor through `BlobIO.read/3`, so it could not drive the `KeyGrants` manager's policy check. | Minor | Upstreamed into `ash_storage`: `AshStorage.Plug.Proxy` now accepts `:actor_assign` (atom assigns-key or 1-arity function) and `:max_lifetime_seconds` (positive-integer cap on the bearer's *remaining* lifetime). The KeyGrants manager's policy check now drives from `bctx.actor` populated by the proxy. SR32 is rewritten as a documentation + dep-version requirement; `mix ash_envelope.gen.proxy_route` (an intermediate hand-written-controller workaround introduced earlier in this branch) was retired in the same pass. Upstream contract is locked by ash_storage's own proxy tests. | ✅ Resolved (v0.4-dev, via upstream) |
| Scope expansion brings the variant generation pipeline (T21) under SR29. The contract test for crash-injected temp-file cleanup is not yet implemented in this project — the SR was added before the test. | Minor | `test/ash_envelope/blob_io/variant_temp_cleanup_test.exs` invokes `AshStorage.VariantGenerator.generate/4` with a transform that writes a partial destination file and then raises; asserts both the generator-written source temp file and the transform-written destination temp file are absent after the crash propagates. Test uses a dedicated unencrypted resource (`AshEnvelope.Test.Storage.PlainPost`) because the variant generator does not currently pass an actor through to `BlobIO.read/3`, so the cleanup mechanism — which is layer-independent — is what's locked. | ✅ Resolved (v0.4-dev) |
| Scope expansion brings T22 (direct-upload bypass) under SR28. The contract test for `AshStorage.Layer.Encryption.direct_upload/2` rejection is not yet implemented in this project. | Minor | `test/ash_envelope/blob_io/encryption_layer_contract_test.exs` asserts `AshStorage.Layer.Encryption.direct_upload/2` returns `{:error, :encryption_layer_does_not_support_direct_upload}` both with empty opts and with proxy / key-manager opts configured. | ✅ Resolved (v0.4-dev) |
| Scope expansion brings T9 under SR31 / C28. The contract test for the encryption layer's `serving/2` forcing a proxy URL is not yet implemented. | Minor | `test/ash_envelope/blob_io/encryption_layer_contract_test.exs` asserts `AshStorage.Layer.Encryption.serving/2` forces `:serve, :proxy` in `call_opts` when `:proxy_base_url` is configured (layer- or call-side), and marks the blob `:not_servable` when `:proxy_base_url` is absent or non-binary. Together the cases lock the contract that the layer never emits a `{:service_url, _}` strategy for an encrypted blob. | ✅ Resolved (v0.4-dev) |

No major or critical findings outstanding. Four minor findings were resolved by the v0.2.0–v0.3.0 implementation pass; the four v0.4-dev scope-expansion findings (SR28 / SR29 / SR31 contract tests; SR32 proxy-route generator) are now locked in this project's CI; the two earlier deferred minor findings (Spark DSL transformer rating, generator attack surface) are resolved by T25 / SR34 and T26 / SR35 respectively in this same v0.4-dev pass. No deferred findings remain. (This paragraph records the v0.4-dev state; the 2026-10 review pass below reopens deferred findings.)

## Findings & actions (2026-10 review pass)

Source: the October 2026 code review of `main` at b799f14 (four parallel reviewers covering the crypto core, key grants and grant requests, reconcile, and generators / helpers / docs / tooling), plus fixes carried by the open PRs and the PRs merged to `main` after the v0.4-dev assessment. Review severity is given in brackets; the Severity column maps High to Major and Medium / Low to Minor. "Fixed in PR #14" means fixed on the PR #14 branch with a regression test; it is not on `main` until that PR merges.

### New findings

| Finding | Severity | Threat / SR | Action | Status |
|---|---|---|---|---|
| N1 [High]: `recover_plaintext/3` accepted truncated GCM tags and odd IV lengths from metadata (forgery acceptance 2^-8 with a one-byte tag). | Major | T4 / SR19, SR3 | Exact-length decode of IV (12) and tag (16), 32-byte DEK check (C36). | ✅ Fixed in PR #14 |
| N2 [High]: an update that changes the scope input never revoked grants on the subjects the principal used to match. | Major | T6 / SR8 (f) | Reconcile the union of pre- and post-change scope; async enqueues both (C31). | ✅ Fixed in PR #14 |
| N3 [Medium]: `unwrap_dek/2` returned a non-32-byte "DEK" for a crafted wrap, crashing the BlobIO read path. | Minor | T12 / SR3, SR38 | Match a 32-byte inner ciphertext; otherwise `:malformed_blob` (C35). | ✅ Fixed in PR #14 |
| N4 [Medium]: backup rotation re-wrapped the DEK from a stale stream snapshot, leaving a current-tagged wrap of the wrong DEK. | Minor | T16 / SR20 | Re-fetch first; take wrap, `key_id` and metadata from the fresh row (C19). | ✅ Fixed in PR #14 |
| N5 [Medium]: rotation dropped per-blob failure reasons; the task reported them as stale. | Minor | T16 / SR20 | `failed: %{reason => count}`, printed by the task; `:domain` default for per-blob calls (C19). | ✅ Fixed in PR #14. Residual: task cannot pass `actor` / `authorize?` / `tenant` (open, P3). |
| N6 [Medium]: `:actor` granter error when the actor cannot open its own grant stopped the chain before `:request`. | Minor | T6 (SG8) / SR8 (g) | Resolve own grant first; skip with warning on `:not_found`, `:decryption_failed`, `:corrupted_dek` (C37). | ✅ Fixed in PR #14 |
| N7 [Medium]: scope larger than `:reconcile_max_subjects` drops the whole reconciliation with only a warning. | Minor | T6 / SR8 | Needs a design decision (chunked async streaming; raise or batch in `:sync`). | ⏳ Open (deferred, P1) |
| N8 [High]: ephemeral worker create and resolve ran under `config.authorize?` with no actor; every attach failed under scaffolded policies. | Major | T10, T19 / SR13 | Run those two manager paths system-side (C34). | ✅ Fixed in PR #14. Residual: `renew_ephemeral_with_actor/5` under actor-scoped policies (open, P3). |
| N9 [Medium]: actor without a usable key raised out of `KeyGrants`, aborting batch fulfilment and the granter chain. | Minor | T12 / SR38 | `fetch_actor_key/2` error tuples without key bytes (C35). | ✅ Fixed in PR #14 |
| N10 [Low]: `Asymmetric` manager raised for a degenerate actor public key. | Minor | T12 / SR38 | Rescue to `:invalid_actor_key` (C35). | ✅ Fixed in PR #14. Residual: same raise in `KeyGrants.create_for_actor/6` / `share/6` (open, P3). |
| N11 [Low]: ECIES KDF does not bind the recipient public key; wrap blob has no version byte. | Minor | T14 / SR3 | Wire-format change with dual-read; needs a migration decision. | ⏳ Open (deferred, P3) |
| N12 [Low]: destroyed principal is a plan error; their grants are never revoked. | Minor | T6 / SR8 | Treat as revoke, or document DB-level cascade (preferred). | ⏳ Open (deferred, P2) |
| N13 [Low]: `affects` entries never validated against the affecting resource. | Minor | T25 / SR34 | Runtime error log plus a cross-check task; compile-time check blocked by the compile cycle. | ⏳ Open (deferred, P2) |
| N14 [Low]: `KeyGrants` manager validated options only at finalize, after upload and blob create. | Minor | T12 / SR38 | Validate in `wrap_dek/3` (C35). | ✅ Fixed in PR #14 |
| N15 [Low]: non-injective `subject_id_resolver` binds later blobs to the first blob's DEK. | Minor | T6 (SG5) / SR39 | Document injectivity; optionally refuse finalize on a DEK mismatch. | ⏳ Open (deferred, P2) |
| N16 [Low]: `list_fulfillable_for` treats expired actor grants as fulfillable. | Minor | T12 / SR15 | Expiry filter when configured. | ⏳ Open (deferred, P3) |
| N17 [Low]: `create_ephemeral/5` accepts `expires_at: nil`, minting a permanent worker row. | Minor | T18 / SR25 | Require a `DateTime` or fall back to the default TTL. | ⏳ Open (deferred, P2) |
| N18 [High]: scaffolded and documented `storage do` block did not compile against the pinned `ash_storage`. | Major | T6, T10 / SR39 | `layer` entity form with `metadata_key`, `blob_resource`, `attachment_resource` (C38). | ✅ Fixed in PR #14 |
| N19 [High]: generators keyed grants and requests by record id while the `KeyGrants` manager keys them by blob id. | Major | T6 / SR39 | Blob-id FK, `subject_id_for` / `subject_load` mapping (C38). | ✅ Fixed in PR #14 (generator tests only; no runtime round-trip) |
| N20 [Medium]: LiveView `share` scaffold loads the target's private key and reads the user without actor. | Minor | T3, T10 / SR39, SR5 | Select only id and public key; pass actor. Unblocked by C34. | ⏳ Open (deferred, P2) |
| N21 [Low]: scaffold comment overstates reconcile's policy bypass. | Minor | T10 / SR39 | Comment: revoke paths only. | ⏳ Open (deferred, P3) |
| N22 [Low]: stale "sealed keypair" wording in docs, `SealKey` moduledoc and generator notice. | Minor | T18 / SR21, SR26 | Text aligned with the sealed-DEK design. | ✅ Fixed in PR #14 |
| N23 [Low]: `user-driven-fulfillment.md` concurrency claim. | Minor | T12 / SR15 | Reword to "`:ok` or `:skipped`, exactly one grant". | ⏳ Open (deferred, P3) |

### Findings fixed by PRs consolidated into PR #14

| Finding | Severity | Threat / SR | Action | Status |
|---|---|---|---|---|
| [High] Planner grant-existence read honoured `config.authorize?` with nil actor: stale grants never planned for revocation (fail-open). | Major | T6 / SR8 (d) | System-side, expiry-aware `grant_status/3` (C30). | ✅ Fixed in PR #14 (from PR #10) |
| [High] `Ash.can?` with `maybe_is: true` authorized grants on `:maybe`. | Major | T6 / SR8 (e) | `maybe_is: false` (C30). | ✅ Fixed in PR #14 (from PR #10) |
| [Medium] Planner ignored `expires_at`; pending-request cleanup with nil actor matched nothing. | Minor | T6 / SR8 (d) | Expired = absent for issue, present for revoke; `revoke_pending_for` with `authorize?: false` from the runner (C30, C12). | ✅ Fixed in PR #14 (from PR #10) |
| [High] Scope resolving to `[]` matched the entire table. | Major | T6 / SR8 (f) | `[]` means no subjects (C31). | ✅ Fixed in PR #14 (from PR #9) |
| [Medium] Async job args built with `Map.get(subject, :id)` on bare ids; Oban insert after commit could lose the job. | Minor | T6 / SR37, SR8 | Bare-id args; insert in `after_action`; `oban_name` option (C31, C33). | ✅ Fixed in PR #14 (from PR #9) |
| [Medium] No compile-time error for default chain without `grant_requests_resource`, unknown granter shapes, `:async` without Oban. | Minor | T25 / SR34 | `ValidateConfig` checks (C39). | ✅ Fixed in PR #14 (from PR #9) |
| [High] Reconcile ran every Ash call without a tenant; cross-tenant issuance and revocation. | Major | T6 / SR36 | Tenant threaded end to end (C32). | ✅ Fixed in PR #14 (from PR #11) |
| [High] All `KeyGrants` / `GrantRequests` calls ran with `actor: nil` under `authorize?: true`. | Major | T10 / SR13 | Actor threading (C34). | ✅ Fixed in PR #14 (from PR #7) |
| [High] `GrantRequests.fulfill` did not check that `target_actor` is the request's target. | Major | T10 / SR13 | `{:error, :target_mismatch}` (C34). | ✅ Fixed in PR #14 (from PR #7) |
| [Medium] `share` idempotency check needed the target's private key; expired rows collided with the unique index. | Minor | T10, T12 / SR13, SR15 | Existence read as target; purge expired target rows; race recovery (C34). | ✅ Fixed in PR #14 (from PR #7) |
| [Medium] `renew_ephemeral/5` destroyed the old row before sealing. | Minor | T19 / SR23 | Seal first, restore on failed insert (C22). | ✅ Fixed in PR #14 (from PR #7) |
| [Medium] `revoke_pending_for` raised on the first destroy error. | Minor | T12 / SR38 | `reduce_while`, returns the error (C35). | ✅ Fixed in PR #14 (from PR #7) |
| [Medium] `assert_policies_defined!/2` passed for `authorize_if always()`. | Minor | T10 / SR14 | Vacuous-coverage detection, `allow_permissive` (C14). | ✅ Fixed in PR #14 (from PR #6) |

### Findings fixed by PRs merged to `main` after the v0.4-dev assessment

| Finding | Severity | Threat / SR | Action | Status |
|---|---|---|---|---|
| [High] Generated LiveView revoke handler let any authenticated user revoke any grant by id. | Major | T10 (MC8) / SR39 | Fetch and revoke as the current actor with authorization (C38). | ✅ Fixed (merged PR #5) |
| [High] `rotate_backup_key` accepted misspelled switches and proceeded to destructive writes. | Major | T16 / SR20 | `OptionParser` strict mode (C19). | ✅ Fixed (merged PR #5) |
| [Medium] Generated `create` lacked `primary? true`; `belongs_to` lacked `source_attribute`; migration hardcoded `users`. | Minor | T6 / SR39 | Scaffold corrections (C38). | ✅ Fixed (merged PR #5) |
| [High] `Runner.run/3` returned `:ok` unconditionally; failed revocations only logged. Oban worker returned `:ok` on failure. | Major | T6 / SR37 | Error aggregate; worker returns it (C33). | ✅ Fixed (merged PR #8) |
| [Medium] `unwrap_dek/2` crashed on low-order X25519 points; `Asymmetric` manager raised on nil actor; rotation used a stale snapshot for the metadata write. | Minor | T12, T16 / SR38, SR20 | Error tuples; re-fetch before write (C35, C19). | ✅ Fixed (merged PR #3) |
| [Medium] CI had not run any check since 2026-06-01. | Minor | all "CI test" verifications | Self-contained workflow (see CI note above). | ✅ Fixed (merged PR #4) |

### Tooling findings (PR #14)

| Finding | Severity | Threat / SR | Action | Status |
|---|---|---|---|---|
| `mix deps.audit` reported two transitive advisories and was not run in CI; Ash below 3.37 is flagged by Hex. | Minor | T10 (via EA3) / SR13; review-cadence trigger | Ash 3.37.2 update; `mix hex.audit` and `mix deps.audit` in CI. | ✅ Fixed in PR #14 |
| CI ran Elixir 1.18, which misses warnings the 1.20 type checker reports. | Minor | verification of all SRs | CI matrix on Elixir 1.20 / OTP 28; warnings fixed. | ✅ Fixed in PR #14 |

Outstanding after this pass: one deferred finding at P1 (N7), five at P2 (N12, N13, N15, N17, N20) and the P3 items listed in `08_prioritization.md`. None is retained without a next step.

## Sign-off

| Role | Name | Date | Signature |
|---|---|---|---|
| Author | Marc Nickert | 2026-05-12 | — |
| Author (2026-10 review pass) | Marc Nickert | 2026-10-29 | |
| Reviewer | *(pending independent review)* | | |
| Stakeholder rep | *(pending; downstream-integrator viewpoint represented vicariously through this document)* | | |

## Review cadence

This assessment shall be re-run, at minimum, on the following triggers:

- **Annual review** (per SR17), covering BSI TR-02102 horizon updates and equivalent crypto-policy publications.
- **Material change** in the library's public API or DSL surface (e.g. a new BlobIO KeyManager, a new granter strategy, a new escrow / backup mechanism).
- **Confirmed CVE** in `ash_envelope` or any of its direct cryptographic dependencies (`:crypto`, `plug_crypto`).
- **Significant change** in the Ash framework's authorization model that the library relies on.
- **Dependency advisory** reported by the CI dependency-audit step (`mix hex.audit`, `mix deps.audit`) against Ash, `ash_storage`, or another dependency on an authorization or cryptographic path.
