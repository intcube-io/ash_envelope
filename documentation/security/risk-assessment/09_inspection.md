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

| ID | Verification approach |
|---|---|
| SR2 | Review: documentation completeness checklist (per-KeyManager). |
| SR3 | Test: assert algorithm identity via `:crypto.crypto_one_time_aead` arguments observed in a tracing test; visual review of `lib/ash_envelope.ex`. |
| SR4 | Test: `hkdf_sha256/4` rejects length > 32. |
| SR5 | Test: invoke generator in a test sandbox; assert generated migration / resource uses an encrypted column type. |
| SR6 | Review: documentation completeness checklist. |
| SR7 | Review: documentation completeness checklist. |
| SR8 | Property test: random `(principal, subject)` pairs vs `Ash.can?` ground truth. |
| SR9 | Test: dispatch async-mode reconciliation; assert `Oban.Job.args` contains only ids. |
| SR10 | Test: log-capture wrapper around public-API exercise (incl. both BlobIO KeyManagers); byte-subsequence scan for key/plaintext bytes. |
| SR13 | Test: confirm public API call sites default to `authorize?: true`. |
| SR14 | Test: helper raises for fixtures without an authorizer, with an empty `policies do … end`, and with policies that don't cover a required action type (e.g. a `:read`-only policy on a resource that also defines `:create` / `:destroy`); passes for an always-policy fixture; passes when `actions: []` disables the coverage tier; skips action types the resource does not define. |
| SR15 | Concurrency test: two concurrent `create/6` invocations produce exactly one row. |
| SR16 | Review: documentation completeness checklist. |
| SR17 | Process: annual maintainer review entry in CHANGELOG. |
| SR19 | Test: with `:backup_public_key` configured, both KeyManagers' `wrap_dek` returns a wrapped map with a `"backup"` field tagged with the configured key's fingerprint; `AshEnvelope.recover_dek/2` round-trips; no configured KeyManager unwraps from the backup field. |
| SR20 | Test: prepare a stale blob (wrapped to an old key, current config points at a new key), run `BackupRotation.rotate_resource/2` in `check_only: true`, assert `remaining_stale > 0`; assert the Mix task's non-zero exit path is reached for the same inputs. |
| SR21 | Test: `test/ash_envelope/seal_key_test.exs` covers seal/unseal round-trip with and without context, AAD mismatch fails closed (`:decryption_failed`), unsealing without context what was sealed with context fails, single-bit ciphertext tamper fails authentication. |
| SR22 | Test: `test/ash_envelope/seal_key_test.exs` covers rejection of unknown version byte and truncated input (`:unknown_seal_format`). |
| SR23 | Test: `test/ash_envelope/key_grants_test.exs` "leaves the existing row intact when actor has no grant" / "when the actor has the wrong private key" — `renew_ephemeral_with_actor/5` short-circuits in the `with` chain on resolve failure; the existing ephemeral row remains. |
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
| SR34 | Test: `test/ash_envelope/reconcile/validate_config_test.exs` exercises both a valid config (compiles cleanly) and known-bad configs (missing required fields, mismatched grant-resource shape) and asserts `Spark.Error.DslError`. New transformer/verifier modules added to `lib/ash_envelope/**/transformers/` must arrive with equivalent test files; review-time check. |
| SR35 | Review (per `mix ash_envelope.gen.*` task source under `lib/mix/tasks/`): the task's `igniter/1` callback issues only `Igniter.add_notice/2`, never `File.write/2`, `File.cp/2`, or `System.cmd/3`. The `rotate_backup_key` task is the documented exception that reads (not writes) an integrator-supplied path. |

## Traceability

| Question | Result | Notes |
|---|---|---|
| Is each requirement uniquely and correctly identified? | ☑ Pass | SR2–SR17, SR19, SR20, SR21–SR31 (active subset; SR1, SR11, SR12, SR18 retired in v0.3.0) and EA1–EA11 minus EA7 are unique. |
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

No major or critical findings outstanding. Four minor findings were resolved by the v0.2.0–v0.3.0 implementation pass; the four v0.4-dev scope-expansion findings (SR28 / SR29 / SR31 contract tests; SR32 proxy-route generator) are now locked in this project's CI; the two earlier deferred minor findings (Spark DSL transformer rating, generator attack surface) are resolved by T25 / SR34 and T26 / SR35 respectively in this same v0.4-dev pass. No deferred findings remain.

## Sign-off

| Role | Name | Date | Signature |
|---|---|---|---|
| Author | Marc Nickert | 2026-05-12 | — |
| Reviewer | *(pending independent review)* | | |
| Stakeholder rep | *(pending; downstream-integrator viewpoint represented vicariously through this document)* | | |

## Review cadence

This assessment shall be re-run, at minimum, on the following triggers:

- **Annual review** (per SR17), covering BSI TR-02102 horizon updates and equivalent crypto-policy publications.
- **Material change** in the library's public API or DSL surface (e.g. a new BlobIO KeyManager, a new granter strategy, a new escrow / backup mechanism).
- **Confirmed CVE** in `ash_envelope` or any of its direct cryptographic dependencies (`:crypto`, `plug_crypto`).
- **Significant change** in the Ash framework's authorization model that the library relies on.
