# Step 7: Categorization

Each SR is classified by the level at which it is enforced and whether it is essential to meeting a security goal.

**Definitions:**

- **System level** — enforced by the overall system, including its environment, processes, and people (in this library-as-component framing: maintainer process, integrator behaviour, regulatory environment).
- **Software level** — implemented by the library's own code (including its tests and documentation files that ship with the package).
- **Architectural constraint** — restricts the library's design (e.g. "all DEKs are AEAD-encrypted before any persistence").
- **Essential** — without this requirement, a security goal fails. Non-essential requirements are defence-in-depth or convenience hardening.

## SRs

| ID | Title (short) | System | Software | Architectural | Essential? |
|---|---|---|---|---|---|
| SR2 | Per-KeyManager threat-model documentation | | ✓ | | Yes |
| SR3 | AES-256-GCM + X25519 ECIES with fresh ephemeral | | | ✓ | Yes |
| SR4 | HKDF-SHA256 output capped at 32 bytes | | | ✓ | No (defence in depth; already implemented) |
| SR5 | Generators scaffold private-key columns encrypted-at-rest | | ✓ | | Yes |
| SR6 | Document EA2 (private-key custody) | | ✓ | | Yes |
| SR7 | Document envelope integrity bound | | ✓ | | Yes |
| SR8 | Reconciliation invariant tests | | ✓ | | Yes |
| SR9 | CI test: no key material in async Oban args | | ✓ | | Yes |
| SR10 | CI test: no plaintext/keys in logs | | ✓ | | Yes |
| SR13 | `authorize?: true` default on grant-mutating APIs | | | ✓ | Yes |
| SR14 | `assert_policies_defined!/2` test helper (authorizer + non-empty policies + action coverage) | | ✓ | | No (helper; reduces residual T10) |
| SR32 | Pin + document `AshStorage.Plug.Proxy` `:actor_assign` + `:max_lifetime_seconds` wiring | | ✓ | | Yes (when encryption-layer proxying is in use) |
| SR33 | Document Mirror partial-write semantics + interim mitigation | | ✓ | | No (documentation; T23 is Tolerable) |
| SR34 | Test coverage for Spark DSL transformers / verifiers (happy + known-bad) | | ✓ | | Yes — locks reconciliation correctness vs. malformed DSL |
| SR35 | Generators are notice-only; never write integrator files directly | | | ✓ | Yes — bounds the generator attack surface |
| SR15 | `GrantRequests.create/6` idempotency + concurrency test | | ✓ | | Yes |
| SR16 | Document grant-relationship metadata exposure | | ✓ | | Yes |
| SR17 | Annotate crypto with BSI horizon + annual review cadence | ✓ | | | Yes |
| SR19 | Backup wrap embedded under `wrapped_dek["backup"]`; recovery via dedicated API | | ✓ | ✓ | Yes (when backup escrow is in use) |
| SR20 | Rotation CLI fails non-zero if any blob is still on a non-current backup key | | ✓ | | Yes (when backup escrow is in use) |
| SR21 | `SealKey` uses AES-256-GCM + per-call AAD | | | ✓ | Yes (when expiring-grants in use) |
| SR22 | Sealed format carries a version byte | | | ✓ | No (forward-compat hatch) |
| SR23 | `renew_ephemeral_with_actor/5` validates authority before destroying | | | ✓ | Yes (when expiring-grants in use) |
| SR24 | Expiring-grants are opt-in via `:expires_at_attribute` | | | ✓ | Yes — locks the "non-users retain v0.3.0 profile" property |
| SR25 | No API to refresh `expires_at` (destroy-and-recreate only) | | | ✓ | Yes (caps TTL blast radius) |
| SR26 | Seal-key rotation runbook documented; no in-place rotation tool | ✓ | | | Yes (when expiring-grants in use) |
| SR27 | Document policy-vs-`expires_at` invariant | | ✓ | | Yes — counters T20 misunderstanding |
| SR28 | Test: encryption layer rejects direct_upload | | ✓ | ✓ | Yes — load-bearing contract for confidentiality |
| SR29 | Test: variant gen cleans up temp file on crash | | ✓ | | Yes (when variants in use) |
| SR30 | Document storage-credential custody (EA11) | | ✓ | | Yes |
| SR31 | Document proxy-auth integrator responsibility | | ✓ | | Yes (when encryption in use) |
| SR36 | Reconciliation, `KeyGrants`, `GrantRequests` are tenant-scoped | | ✓ | ✓ | Yes (when multitenancy is in use) |
| SR37 | Reconciliation failures surfaced and retried; async enqueue inside the triggering transaction | | ✓ | | Yes: a dropped revocation is a silent authorization leak |
| SR38 | Error tuples, not exceptions, for malformed per-request key material and wraps | | ✓ | | No (availability hardening; T12) |
| SR39 | Generator scaffolds consistent with runtime contracts (compiling DSL, blob-id subject, actor-threaded handlers) | | ✓ | | Yes: scaffolds are the default integrator configuration |

SR1, SR11, SR12, SR18 retired with the v0.3.0 removal of `:simple` storage mode, `AshEnvelope.Storage.Plug`, and the process-dictionary DEK handoff.

## EAs

All environmental assumptions are **system-level** by definition (enforced outside the library) and **essential** (without them, the library's threat model collapses).

| ID | Title (short) | System | Essential? |
|---|---|---|---|
| EA1 | Integrator authenticates the `actor` before passing in | ✓ | Yes |
| EA2 | Private-key custody at ≥ plaintext protection level | ✓ | Yes — **load-bearing for T2/T3** |
| EA3 | Policies defined on grants / requests / encrypted resources | ✓ | Yes |
| EA4 | TLS on transport boundaries | ✓ | Yes |
| EA5 | Host OS / BEAM node integrity (no side-channel) | ✓ | Yes |
| EA6 | Oban queue persistence trust ≥ main DB | ✓ | Yes |
| EA8 | BSI TR-02102 horizon 2030; no quantum adversary | ✓ | Yes |
| EA9 | Backup private key custody at ≥ plaintext protection, outside DB | ✓ | Yes — **load-bearing for T15** (only when backup escrow is opted into) |
| EA10 | Env seal key custody (operator-managed secret, not in image / logs / source) | ✓ | Yes — **load-bearing for T18** (only when expiring-grants is opted into) |
| EA11 | Storage-service credential custody (operator-managed, scoped IAM) | ✓ | Yes — **load-bearing for T24** (and for T4 when credentials are writable) |

EA7 retired alongside the `:simple` code path.
