# Step 8: Prioritization

## Priority scheme

- **P1 — Must have.** Treats an Inacceptable risk, or is essential and treats an Undesirable risk, or is foundational to the cryptosystem.
- **P2 — Should have.** Treats an Undesirable risk but with a non-essential or partial role.
- **P3 — Could have.** Treats a Tolerable risk, or provides defence in depth on top of a P1.
- **P4 — Won't have (this round).** Documented but deferred. Not used in this assessment.

## Prioritized requirements

| ID | Requirement (short) | Treats | Damage | RAP | Risk | Priority | Notes |
|---|---|---|---|---|---|---|---|
| SR2 | Per-KeyManager threat-model documentation | T2 | High | High (n.p.) | Tolerable | **P1** | Pure documentation; high leverage. |
| SR3 | AES-256-GCM + X25519 ECIES with fresh ephemeral | T2, T14 (foundation for T4 partial) | High | High (n.p.) | Tolerable | **P1** | Foundational. Already implemented; lock via tests. |
| SR4 | HKDF output capped at 32 bytes | T2 (defence in depth), T14 | High | High (n.p.) | Tolerable | **P3** | Already implemented; defence in depth only. |
| SR5 | Generators scaffold encrypted private-key columns | T3 | High | No rating | **Inacceptable** | **P1** | Steers integrators away from EA2 violations. |
| SR6 | Document EA2 (private-key custody) | T3 | High | No rating | **Inacceptable** | **P1** | Pairs with SR5. |
| SR7 | Document envelope integrity bound | T4 | High | No rating | **Inacceptable** | **P1** | Per user decision: documentation-only response. |
| SR8 | Reconciliation invariant tests | T6 | High | Low | **Undesirable** | **P1** | Essential — bug here is silent authorization leak. 2026-10 pass: invariants (d)-(g) added after the planner fail-open finding; T6 was Inacceptable on the pre-fix code. |
| SR9 | CI test: no key material in async Oban args | T7 | High | Low | **Undesirable** | **P1** | Essential — locks an existing invariant. |
| SR10 | CI test: no plaintext/keys in logs | T8 | High | Low | **Undesirable** | **P1** | Essential — locks an existing invariant. |
| SR13 | `authorize?: true` default on grant-mutating APIs, with a real actor on every call | T10 | High | No rating | **Inacceptable** | **P1** | Already implemented; lock via test. 2026-10 pass: the default was ineffective while calls ran with `actor: nil`; actor threading added (C34). |
| SR14 | `assert_policies_defined!/2` test helper (authorizer + non-empty policies + action coverage) | T10 | High | No rating | Inacceptable (residual) | **P2** | Reduces *integrator* residual; non-essential helper. Action-coverage tier catches the common "scaffold's `:create` policy left commented out" footgun. 2026-10 pass: vacuous `authorize_if always()` coverage now rejected by default. |
| SR15 | `GrantRequests.create/6` idempotency + concurrency test | T12 | Normal | No rating | **Undesirable** | **P2** | Already implemented; lock via test. |
| SR16 | Document grant-relationship metadata exposure | T13 | Normal | No rating | **Undesirable** | **P2** | Pure documentation; inherent design limitation. |
| SR17 | Crypto-horizon annotations + annual review cadence | T14 | High | High (n.p.) | **Tolerable** | **P2** | Closes the only credible long-term degradation path. |
| SR19 | Backup wrap embedded + narrow recovery API | T15 | High | Low (under EA9) | **Undesirable** | **P1** | Conditional — only relevant when integrator opts into `:backup_public_key`. |
| SR20 | Rotation CLI fails on incomplete pass | T16 | High (Av) | No rating | **Undesirable** | **P1** | Locks rotation runbook against operator error. |
| SR21 | `SealKey` AES-256-GCM + AAD | T17, T18 | High | Low | **Undesirable** | **P1** (when in use) | Foundational for the worker pathway; already implemented. |
| SR22 | Sealed format version byte | T17, T18 (forward-compat) | High | Low | n/a | **P3** | Cheap forward-compat hatch; not load-bearing. |
| SR23 | `renew_ephemeral_with_actor/5` validates authority first | T19 | Normal | No rating | **Tolerable** | **P1** (when in use) | Removes a footgun by API shape; already implemented. |
| SR24 | Expiring-grants opt-in via `:expires_at_attribute` | T17, T18 | High | Low | **Undesirable** | **P1** (when in use) | Locks the "non-users retain v0.3.0 profile" property. Already implemented. |
| SR25 | No `expires_at` refresh API | T18 | High | Low | **Undesirable** | **P1** (when in use) | Caps blast radius; already implemented (by omission). |
| SR26 | Drain-only seal-key rotation runbook | T17, T18 | High | Low | **Undesirable** | **P1** (when in use) | Documentation only. |
| SR27 | Policy-vs-`expires_at` invariant documented + generator default | T20 | High | No rating | **Inacceptable** (downstream of EA3) | **P1** (when in use) | Documentation + generator scaffold (parent-resource time-bound `:read` templates + grants-resource expiry filter); counters the most likely integrator misunderstanding. |
| SR28 | Test: encryption layer rejects `direct_upload/2` | T22 | Normal (DoS) | No rating | **Tolerable** | **P1** | Load-bearing contract for confidentiality of encrypted attachments; cheap CI test. |
| SR29 | Test: variant gen cleans up temp file on crash | T21 | High | Low | **Undesirable** | **P1** (when variants in use) | Bounds plaintext-on-disk window. |
| SR30 | Document storage-credential custody (EA11) | T24 | High (write) | Low | **Undesirable** | **P1** | Documentation only; pairs with EA11. |
| SR31 | Document proxy-auth integrator responsibility | T9 | High | No rating | **Inacceptable** → **Undesirable** with auth | **P1** | Documentation; pairs with C28 (encryption layer forces proxy URL). |
| SR32 | Require + document `AshStorage.Plug.Proxy` `:actor_assign` / `:max_lifetime_seconds: 300` wiring | T9 | High | No rating | **Inacceptable** → **Undesirable** with the documented config | **P1** | Documentation + upstream-dep requirement; the heavy lifting now lives in `AshStorage.Plug.Proxy` itself (committed upstream). Pairs with SR31 (responsibility framing) + C28 (layer forces proxy URL) + C29 (upstream contract). |
| SR33 | Document Mirror partial-write semantics | T23 | Normal | No rating | **Tolerable** | **P2** | Documentation; pairs with the existing T23 framing (orphans = Av/storage-cost, not C). Replaces the prior "no library SR" treatment. |
| SR34 | Test coverage for Spark DSL transformers (happy + known-bad) | T25 | High | Low | **Undesirable** | **P1** | Already-implemented test suite formalized as a library obligation; cheap to maintain. |
| SR35 | Generators emit notices only — no auto-file-writes | T26 | Normal | No rating | **Tolerable** | **P2** | Architectural constraint; existing tasks already comply. SR locks the invariant per task. |
| SR36 | Tenant-scoped reconciliation and grant APIs | T6 | High | Low | **Undesirable** (Inacceptable pre-fix) | **P1** (when multitenancy in use) | Implemented in PR #14; locked by the multitenancy suite. |
| SR37 | Reconcile failures surfaced and retried; atomic async enqueue | T6 | High | Low | **Undesirable** (Inacceptable pre-fix) | **P1** | Implemented (merged PR #8, PR #14). `:sync` mode remains best-effort after commit. |
| SR38 | Error tuples for malformed per-request key material and wraps | T12, T8 | Normal | No rating | **Undesirable** | **P2** | Availability hardening for batch paths; mostly implemented, one residual (degenerate key in `KeyGrants`). |
| SR39 | Generator scaffolds consistent with runtime contracts | T6, T10 | High | Low / No rating | **Undesirable** / **Inacceptable** | **P1** | Scaffolds are what most integrators deploy; locked by generator tests. |

## Open items (2026-10 review pass)

Findings from the October 2026 review that PR #14 does not fix. Each is recorded against the SR whose obligation it leaves unmet. Priorities use the scheme above; none is assigned P4, since each has a concrete next step.

| Finding | SR / threat | Priority | Rationale |
|---|---|---|---|
| N7: scope larger than `:reconcile_max_subjects` drops the whole reconciliation with a warning | SR8 / T6 | **P1** | A demoted principal keeps every grant on an oversized scope, a confidentiality failure. Needs a design decision (stream into async jobs without a global cap; raise or batch in `:sync`). Conditional on scope size, and logged. |
| N12: destroyed principal is a plan error; their grants are never revoked | SR8 / T6 | **P2** | The orphaned rows open only with the deleted principal's private key, which normally goes with the principal row. Preferred route is documentation (cascade grant rows on principal deletion at the DB level), since a wrong-tenant lookup could otherwise look like a deletion. |
| N13: `affects` entries not validated (`principal`, `actions`, `encrypts` target) | SR34 / T25 | **P2** | Integrator typo makes revocation a silent no-op. Compile-time check blocked by the compile cycle; runtime error log plus a cross-check task proposed. |
| N15: non-injective `subject_id_resolver` binds a later blob to an earlier blob's DEK | SR39 / T6 (SG5) | **P2** | Availability failure (decrypt fails) and an SG5 violation, reachable only with a non-default resolver. Documentation, optionally a finalize-time refusal. Finalize is also not idempotent under at-least-once delivery. |
| N17: `create_ephemeral/5` accepts `expires_at: nil` | SR25 / T18 | **P2** | Direct callers can mint a permanent worker row outside the TTL bound; the manager path is unaffected. Cheap fix. |
| N20: LiveView `share` scaffold loads the target's private key and calls `Ash.get` without actor | SR39, SR5 / T3, T10 | **P2** | Holds a third party's private key in memory for no cryptographic reason. Unblocked now that `share/6` needs only the public key (C34). |
| N11: ECIES KDF does not bind the recipient public key; wrap blob has no version byte | SR3 / T14 | **P3** | Hardening, no concrete exploit. Wire-format change with dual-read of the current format; needs a migration decision. |
| N16: `list_fulfillable_for` ignores grant expiry | SR15 / T12 | **P3** | Surfaces requests the actor cannot fulfil; they fail with `:not_found`. Availability only. |
| N21: scaffold comment says reconcile rewraps run with `authorize?: false` | SR39 / T10 | **P3** | Only the revoke paths bypass policies; the `:actor` granter's share honours `key_grants_authorize?`. One-line comment. |
| N23: `user-driven-fulfillment.md` says concurrent duplicates collapse to `:skipped` | SR15 / T12 | **P3** | Documentation accuracy; outcome is `:ok` or `:skipped` with exactly one grant. |
| N8 residual: `renew_ephemeral_with_actor/5` runs the ephemeral destroy/create under `config.authorize?` with the renewing actor | SR13, SR23 / T19 | **P3** | Recorded as not fixed by the review; actor-scoped policies on a principal-less row are not expected to admit the renewing actor, and no test covers renewal under such policies. Worker-pathway availability only. |
| N10 residual: `KeyGrants.create_for_actor/6` and `share/6` raise for a degenerate (low-order) recipient public key | SR38 / T12 | **P3** | Same class as the fixed `Asymmetric` case; fail-stop, no confidentiality impact. |
| N5 residual: `rotate_backup_key` cannot pass `actor`, `authorize?` or `tenant` | SR20 / T16 | **P3** | Policy-protected or multitenant blob resources fail per blob, now reported by reason. |
| Rotation clobber window: metadata read-modify-write without optimistic locking | SR20 / T16 | **P3** | Narrowed to milliseconds (merged PR #3, PR #14); full fix needs optimistic locking upstream in `ash_storage`. |

## EAs (priority = enablers)

| ID | Assumption (short) | Owner | Priority | Notes |
|---|---|---|---|---|
| EA1 | Integrator authenticates actor | Integrator | **P1** | Enables SG4, SG7. |
| EA2 | Private-key custody ≥ plaintext protection | Integrator | **P1** | Load-bearing for T2/T3. |
| EA3 | Policies on grants/requests/encrypted resources | Integrator | **P1** | Enables SG4. |
| EA4 | TLS on transport boundaries | Integrator / operator | **P1** | Enables SG1. |
| EA5 | Host OS / BEAM node integrity | Operator | **P1** | Enables SG3. |
| EA6 | Oban DB trust ≥ main DB | Integrator / operator | **P1** | Enables SR9. |
| EA8 | BSI TR-02102 horizon 2030 | Maintainer / cryptographic-policy stakeholder | **P1** | Frames T2 / T14. |
| EA9 | Backup private key custody ≥ plaintext protection (when opted in) | Integrator | **P1** (when in use) | Load-bearing for T15 only when `:backup_public_key` is configured. |
| EA10 | Env seal key custody (when expiring-grants opted in) | Integrator / operator | **P1** (when in use) | Load-bearing for T18 only when `:expires_at_attribute` is configured. |
| EA11 | Storage-service credential custody | Integrator / operator | **P1** | Load-bearing for T24 and (when writable) T4. Always applies because storage is always used. |

## Cost-benefit notes

Most P1 requirements are either documentation or tests that lock in an already-implemented invariant. Their implementation cost is **low** and their risk-reduction benefit is **high**, so the ranking is straightforward.

| ID | Implementation cost | Benefit (risk reduction) | Recommendation |
|---|---|---|---|
| SR2 | Low (markdown) | T2 / KeyManager-choice clarity for integrators | Implement before 1.0 |
| SR5 | Medium (generator templates + igniter patches) | T3 Inacceptable → Undesirable when scaffolds are used | Implement before 1.0 |
| SR8 | Medium (property tests for `Runner.plan` / `apply_plan!`) | T6 Undesirable → Tolerable | Implement before 1.0 |
| SR9 | Low (one assertion on Oban.Job.args) | T7 Undesirable → Tolerable | Implement immediately; cheap and high-leverage |
| SR10 | Medium (log-capture + byte-subsequence scan across API) | T8 Undesirable → Tolerable | Implement before 1.0 |
| SR14 | Low (helper module) | T10 Inacceptable residual → Undesirable | Implement when convenient |
| SR17 | Low (changelog entry per year) | T14 stays Tolerable; prevents drift | Begin immediately |
| SR19 | Medium (KeyManager wiring + recovery API + tests) | T15 Undesirable; narrows the surface that can reach the backup wrap | Ship together with `:backup_public_key` |
| SR20 | Low (final pass + non-zero exit + a test) | T16 Undesirable; locks rotation runbook | Ship together with `mix ash_envelope.rotate_backup_key` |
| SR21–SR27 | Low–Medium (mostly already implemented + doc) | T17–T20 covered; the new Undesirable T18 is opt-in and TTL-bounded | Ship together with the expiring-grants feature |
| SR28–SR31 | Low (3 contract tests + 2 doc sections) | T9 returns to scope with auth-side mitigation; T21/T22 locked by contract tests; T24 documented | Ship as part of the v0.4-dev scope expansion |
| SR36-SR39 | Medium (tenant threading, failure aggregation, error contracts, generator rewrites; all implemented with tests in PR #14 or merged PRs) | T6 back from Inacceptable (pre-fix) to Undesirable; T10 controls effective; T12 batch DoS removed | Land with PR #14; follow up the P1 / P2 open items above before the next release |
