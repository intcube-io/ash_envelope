# Security Risk Assessment: AshEnvelope

**Methodology:** SQUARE (Mead et al. 2005) with BSI 200-2 damage potential and ISO/IEC 18045 attack potential rating.

| Field | Value |
|---|---|
| System under assessment | `ash_envelope` — Elixir library providing envelope-encryption primitives and key-grant management for the Ash framework. |
| Version / scope | v0.4-dev. Scope expanded from "ash_envelope library as a component" to "ash_envelope + the `ash_storage` surface it integrates with" — see "Scope expansion" below. |
| Assessment date | 2026-05-11 / 2026-05-12 / 2026-06-02 / 2026-06-05 |
| Assessor | Marc Nickert (maintainer) |
| Stakeholders consulted | Maintainer (direct). Integrators and data subjects represented vicariously through the regulatory regime in the damage-potential premise. |
| Depth | Standard (all 9 SQUARE steps, single pass) |

## Business context

`ash_envelope` is consumed by Ash applications that need to encrypt selected fields or attachments at rest, with per-principal access controlled via X25519-wrapped DEKs in a grants table. Its primary value proposition is "correct, ergonomic envelope encryption for Ash without requiring integrators to roll their own crypto" — so its security posture *is* its product. The purpose of this assessment is to document that posture for downstream integrators.

## Scope and assumptions

**In scope:**

- Core crypto primitives (`AshEnvelope.encrypt/3`, `decrypt/3`, `wrap_dek/unwrap_dek`, `generate_dek/generate_key_pair`, `resolve_actor_key`, `AshEnvelope.SealKey`). `encrypt/3` and `decrypt/3` are the symmetric step of the multi-recipient grant pattern for non-blob fields; they accept optional `:context` AAD for binding ciphertext to a row. For single-key field encryption with a vault-managed key, use [`ash_cloak`](https://hexdocs.pm/ash_cloak) instead — the two libraries cover different use cases.
- Key-grant management (`AshEnvelope.KeyGrants`, `AshEnvelope.GrantRequests`).
- BlobIO key managers (`AshEnvelope.BlobIO.KeyManagers.Asymmetric`, `AshEnvelope.BlobIO.KeyManagers.KeyGrants`) plugged into `AshStorage.Layer.Encryption`.
- Reconciliation engine (`AshEnvelope.Reconcile.*`), including granter strategies and `:sync` / `:async` modes.
- **Integrated `ash_storage` surface (v0.4-dev scope expansion).** Service adapters (S3, Disk, Azure Blob, Mirror, Test) at the boundary level; the BlobIO encryption layer's contract; variant generation pipeline; the analyzer pathway; direct-upload rejection by the encryption layer; proxy-serving requirements imposed by the encryption layer. The library-level details of `ash_storage` (its own DSL, generator templates, internal modules) remain upstream's concern; this assessment covers the surface that affects ash_envelope's confidentiality / integrity claims.

**Out of scope:**

- `ash_storage` features that don't affect ash_envelope's at-rest crypto: its DSL transformer internals; its generator templates; the variant transform modules themselves (which are integrator-supplied); attachment-row lifecycle policies (dependent: purge / detach / no-op). The threat model assumes ash_storage's *contracts* (encryption layer rejects direct upload; layer-metadata key check fails closed on unknown key) hold — see the corresponding SRs.
- Mix-task generators (`mix ash_envelope.gen.*`) as a standalone attack surface (deferred per step 9 findings).
- Spark DSL transformers as targets in themselves (deferred).
- Host OS / BEAM node integrity, side-channel adversaries (EA5).
- Quantum-capable adversaries (EA8, BSI horizon 2030).
- Threats requiring host-code execution by a malicious integrator (out of trust model — the integrator is trusted by definition).
- Denial-of-service caused by an adversary with full database write access (DBA `DROP TABLE` is intrinsic to the DBA class; rated as out of scope at the class level).

**Analysis premises:**

- The library is used to encrypt **PII or comparable regulated data (GDPR / similar) and/or business secrets**. Catastrophic-tier data (health, identity, life-safety) would shift several risk ratings up by one level.
- BSI TR-02102 horizon 2030 is treated as authoritative for cryptographic-algorithm acceptability.
- The integrator is trusted to authenticate actors, configure Ash policies, and protect principal private keys outside the application database (per EA1, EA2, EA3, EA7).

## Methodology

This assessment uses:

- **SQUARE** (Mead et al. 2005) as the overall process framework.
- **BSI 200-2** damage scenarios for protection-needs / damage-potential rating.
- **ISO/IEC 18045** required-attack-potential scoring (Identification + Exploitation, max-of-columns mapping) for likelihood / feasibility.
- **4-level risk matrix** (Negligible / Tolerable / Undesirable / Inacceptable) combining the two.
- **STRIDE** as a checklist for threat identification.

## Document index

1. [Definitions](01_definitions.md) — glossary.
2. [Security goals](02_security_goals.md) — assets, CIA+ properties, security goals, stakeholders, threat-actor classes.
3. [Artifacts](03_artifacts.md) — architecture diagram, data flows, trust boundaries, use/misuse cases, environmental assumptions.
4. [Risk assessment](04_risk_assessment.md) — damage potential per asset, RAP per threat, risk matrix.
5. [Elicitation technique](05_elicitation.md) — threat-driven derivation, rationale.
6. [Security requirements](06_security_requirements.md) — SR1–SR18, EA1–EA8, controls, coverage check.
7. [Categorization](07_categorization.md) — system / software / architectural; essential vs not.
8. [Prioritization](08_prioritization.md) — P1–P3 derived from risk × category, cost-benefit notes.
9. [Inspection](09_inspection.md) — verification per SR, traceability, findings, sign-off.
10. [Traceability matrix](traceability_matrix.md) — asset ↔ goal ↔ threat ↔ requirement.

## Summary of key findings

- **Four Inacceptable findings:**
  - **T3** — EA2 violation (principal private keys stored plaintext in the DB) → plaintext disclosure for that principal's grants. Addressed by SR5 (generator scaffolds use encrypted-at-rest columns), SR6 (documentation), and EA2 as a load-bearing assumption.
  - **T4** — DBA forges entire envelope (ciphertext + every wrap row) → integrity / authenticity breach but **not** confidentiality. Per maintainer decision, response is documentation-only (SR7).
  - **T10** — Authorization bypass via integrator policy gap on the grants resource. Substantially mitigated by `authorize?: true` defaults (SR13). Residual is integrator policy correctness (EA3, SR14).
  - **T20** — Time-bounded user grant outlives the policy intent (the integrator-side misunderstanding "expires_at = access ends" when actually the read policy is the access-control truth). Response: documentation + generator scaffold (SR27, C25) — `mix ash_envelope.gen.key_grants` emits a parent-resource `:read` policy section with three labeled time-bound patterns and a grants-resource expiry filter. Downstream of EA3.
- **Confidentiality holds against DBA-class adversaries** under the load-bearing assumption EA2 (private keys protected outside the DB). Row-shuffling attacks degrade to AEAD-fail / DoS — no plaintext recovery.
- **Cryptographic primitives** (AES-256-GCM with random 12-byte IV; X25519 ECIES with fresh ephemeral key per call; HKDF-SHA256 capped at 32 bytes) align with BSI TR-02102 horizon 2030. The single tracking obligation is SR17's annual review of the horizon.
- **Async-mode reconciliation** is designed so that Oban job args carry only `subject_ids + principal_id + actor_id` — never key material. SR9 locks this invariant via a CI test.
- **Eight Undesirable risks** (T6, T7, T8, T12, T13, T15, T16, T18) drive concrete library SRs.
- **Backup-key escrow** (opt-in via `:backup_public_key`) is rated Undesirable under load-bearing EA9 (private key in cold storage / KMS / split). SR19, SR20, EA9 bound the surface and lock the rotation runbook.
- **Expiring grants** (opt-in via `:expires_at_attribute` on `KeyGrants.Config`) cover both time-bounded user grants and per-attach ephemeral worker grants. Ephemeral rows seal the DEK directly under the env seal key (A10) with AAD = subject id — no intermediate keypair. T17 / T18 / T19 / T20 are the new threats; SR21–SR27 and EA10 cover them. T18 is Undesirable, bounded by `TTL × write_rate`; T17 is Negligible (the seal key alone unlocks nothing without DB read); T19 is Tolerable (mitigated by the `renew_ephemeral_with_actor/5` API shape). Deployments that don't enable the feature retain the v0.3.0 risk profile exactly (SR24 / C23).
- **No risk is retained without an explicit rationale.** The three retentions (T5, T9, T11) cover threat classes that are intrinsic to the framing or upstream of `ash_envelope`: total DB destruction by a DBA, the HTTP serving surface for encrypted blobs (now an `ash_storage` proxy concern), and host-OS / BEAM-node compromise.

## Scope expansion (v0.4-dev)

Prior versions of this assessment scoped only `ash_envelope` itself, treating `ash_storage` as a trusted upstream and explicitly excluding the encrypted-blob HTTP serving surface (T9 was retired as "upstream concern"). v0.4-dev expands scope to cover the **ash_storage features that ash_envelope's confidentiality and integrity claims depend on**:

- **Service adapters** (S3, Disk, Azure Blob, Mirror, Test) — at the boundary level, via new EA11 (service-credential custody) and the existing TB2.
- **Variant generation** — the source-decrypt → transform-in-temp → re-encrypt path widens the DEK exposure window across a multi-step transform call. New T21, new SR29.
- **Direct uploads** — the encryption layer **rejects** them. This is a load-bearing contract: encrypted attachments cannot be uploaded out-of-band with attacker-chosen plaintext. New T22 documents the attack attempt and SR28 locks the rejection.
- **Proxy serving** — T9 returns to scope. The encryption layer forces a proxy URL (rejects direct service-URL serving), so encrypted reads must traverse application-controlled auth. New SR31 documents the integrator-side responsibility; new SR32 ties the library to the upstream `AshStorage.Plug.Proxy` `:actor_assign` + `:max_lifetime_seconds` options (upstreamed in this same v0.4-dev pass) and documents the canonical configuration. An intermediate hand-written-controller generator (`mix ash_envelope.gen.proxy_route`) shipped briefly inside this branch before being retired in favour of the upstream contract — the trade study lives in the inspection-table row for that finding.
- **Mirror service partial-write orphans** — when a multi-backend write succeeds in the primary but fails in secondaries, orphaned files remain. Integrity / availability concern, surfaced as T23.

Six new threats (T9 re-rated, T21–T24), one new asset (A11 storage-service credentials), one new EA (EA11), five new SRs (SR28–SR32), four new controls (C26–C29). Net: +1 Inacceptable and +3 Undesirable in the matrix, all conditional on the corresponding ash_storage features being used; SR32 collapses T9's default from Inacceptable to Undesirable for integrators who configure `AshStorage.Plug.Proxy` with `:actor_assign` and `:max_lifetime_seconds: 300` per the documented pattern.

The v0.4-dev pass also closes the two **previously-deferred minor findings** from the v0.3.0 inspection:

- **Spark DSL transformer surface** — rated as T25 (Undesirable). SR34 formalizes the test-coverage obligation for `AshEnvelope.Reconcile`'s transformers; the existing reconcile test suite already satisfies it.
- **`mix ash_envelope.gen.*` attack surface** — rated as T26 (Tolerable). The library's generators are notice-only (`Igniter.add_notice/2`), which structurally avoids the argument-injection-into-file-paths surface the deferred finding raised. SR35 locks the invariant per task.

Plus SR33 — documentation commitment for `AshStorage.Service.Mirror` partial-write semantics — supersedes the prior "no library SR" treatment of T23. Helper-strengthening: `AshEnvelope.TestHelpers.assert_policies_defined!/2` now checks per-action-type policy coverage by default, catching the common scaffold mistake of leaving the `:create` sharing-model branch commented out.

After the v0.4-dev pass, no deferred minor findings remain in the inspection table.

## Implementation status (v0.4-dev)

The v0.4-dev pass introduces opt-in **expiring grants** on `AshEnvelope.KeyGrants`:

- **Time-bounded user grants** — `create_for_actor/6` accepts `:expires_at`; `resolve_for_actor/4` treats expired rows as `:not_found`.
- **Ephemeral worker grants** — `create_ephemeral/5` writes a row with `principal_id IS NULL` whose `dek_attribute` carries the DEK sealed directly under a new `AshEnvelope.SealKey` (AES-256-GCM, AAD = subject id, version-byte format). `resolve_ephemeral/3` is the read counterpart. Enables deferred Oban analyzers to decrypt without a user actor.
- **Same `expires_at` column drives both**, and one TTL purge cron handles both. The `KeyGrants` BlobIO manager adds a positive discriminator (`operation == :analyze` + `analyzer` set + `actor == nil` + `:expires_at_attribute` configured) that routes through `resolve_ephemeral/3`. Bare `actor: nil` from non-analyzer contexts still fails with `:missing_principal`.
- **No intermediate keypair on the ephemeral row.** The seal key is symmetric and the worker pathway is fully inside the trust domain; an X25519 wrap (sealed under the same env key) would offer no defense in depth.
- New SRs **SR21–SR27**, new EA **EA10**, new threats **T17–T20**. SR24 / C23 lock the "non-users retain v0.3.0 profile" property.
- `mix ash_envelope.gen.key_grants` extended: one new nullable column (`expires_at`), `user_id` becomes nullable, two partial unique indexes, optional manager opts, and a TTL purge Oban worker skeleton.

## Implementation status (v0.3.0)

The v0.2.0 implementation pass (per-mode warnings, plug hardening, pdict cleanup, generator/policy scaffolds, log-safety tests) landed earlier this review window. v0.3.0 then refactored the storage integration onto `AshStorage.BlobIO`:

- **`AshEnvelope.Storage` extension, `AshEnvelope.Storage.Encrypted` wrapping service, and `AshEnvelope.Storage.Plug` are removed.** Replaced by two `AshStorage.Encryption.KeyManager` implementations: `AshEnvelope.BlobIO.KeyManagers.Asymmetric` and `AshEnvelope.BlobIO.KeyManagers.KeyGrants`.
- **`:simple` storage mode is removed.** No `ash_envelope` code path stores a DEK alongside its ciphertext. T1 (`:simple`-mode DBA disclosure) is retired from the risk matrix.
- **No more process-dictionary DEK handoff.** The `KeyGrants` manager carries the DEK through the typed `Writer.Operation.write_finalizations` field within a single `BlobIO.write` call and inserts the grant row in `finalize_wrapped_dek/3` after blob creation. T11's pdict-survival vector and SR18's regression test for it are obsolete.
- **`AshEnvelope.Storage.Plug` is removed.** The HTTP surface for serving encrypted blobs is an integrator-owned route over `AshStorage.BlobIO.read/3` or the upstream `ash_storage` proxy. T9 is retired from the risk matrix as out of `ash_envelope` scope; the path-traversal / signed-URL / disposition hardening that lived in SR11/SR12 is now upstream's responsibility.
- **Backup-key escrow (opt-in).** `:backup_public_key` plus `:backup_public_key_previous` add an X25519 ECIES wrap of every blob's DEK under `wrapped_dek["backup"]` in encryption-layer metadata. Recovery is via the dedicated `AshEnvelope.recover_dek/2` / `recover_plaintext/3` entry points — never through a configured KeyManager. `mix ash_envelope.rotate_backup_key` rewrites stale wraps and exits non-zero if any blob remains stale after the pass. New SRs SR19 / SR20 and EA9 bound the surface; new threats T15 (compromise) and T16 (rotation incomplete) are both Undesirable under EA9.
- **Carry-over from v0.2.0:** `authorize?: true` defaults on `KeyGrants.Config` / `GrantRequests.Config`; generator scaffolds for `Ash.Policy.Authorizer` and `AshCloak`-encrypted private-key columns; `AshEnvelope.TestHelpers.assert_policies_defined!/2` (strengthened in v0.4-dev to also check per-action-type policy coverage); cross-API log-safety audit test.
- **`CHANGELOG.md`** anchors the review cadence (next due 2027-05).

T3, T4, and T10 remain rated **Inacceptable** because the risk ratings are about *exposure*, not mitigation coverage — the rated damage and required attack potential are unchanged by the implementation. What changed is that every Inacceptable finding has a concrete, traceable response in the codebase or the documentation. The next review (2027-05) should confirm those responses are still in place and re-evaluate against the BSI TR-02102 horizon at that time.
