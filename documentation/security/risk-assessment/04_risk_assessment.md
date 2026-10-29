# Step 4: Risk Assessment

Combines BSI 200-2 damage potential with ISO/IEC 18045 required attack potential (RAP) per the project's risk matrix (Negligible / Tolerable / Undesirable / Inacceptable).

## Damage-potential premise

The library has no plaintext of its own; damage falls on the integrator's data. This assessment is rated against the worst credible class the library is intended to protect:

> **The library is used to encrypt PII or comparable regulated data (GDPR / similar) and/or business secrets.** Catastrophic-tier data (health, identity, life-safety) is *not* in the premise; an integrator with such data should dial damage from **High → Very High** on confidentiality and integrity threats, which moves several Undesirable rows to Inacceptable.

## 4a. Damage potential per asset

Scoring per BSI 200-2 damage scenarios. Aggregation uses the maximum principle.

### A1 plaintext — Confidentiality

| Damage scenario | Normal | High | Very High | Selected | Rationale |
|---|---|---|---|---|---|
| Violation of laws / regulations / contracts | | ✓ | | **High** | GDPR Art. 32 violations carry substantial fines (up to 4% of global turnover); comparable sectoral regulation similar. |
| Privacy (informational self-determination) | | ✓ | | **High** | Disclosure of PII seriously affects social standing of data subjects. |
| Physical injury | ✓ | | | Normal | Not credible for the premise data class. |
| Impaired ability to perform tasks | ✓ | | | Normal | Disclosure does not by itself stop the integrator's ops. |
| Negative internal / external effects | | ✓ | | High | Public breach disclosure required under GDPR Art. 33/34. |
| Financial consequences | | ✓ | | High | Penalties, breach-response costs, litigation. |
| **Aggregation** | | | | **High** | Maximum across legal/privacy/reputational/financial. |

### A1 plaintext — Integrity (incl. envelope forgery)

| Damage scenario | Selected | Rationale |
|---|---|---|
| Violation of laws / regulations / contracts | High | Falsified records can constitute regulatory non-compliance and fraud. |
| Privacy | Normal | Forgery typically doesn't directly disclose existing PII. |
| Physical injury | Normal | Out of premise. |
| Impaired ability to perform tasks | Normal | Forged records may corrupt isolated workflows. |
| Negative internal / external effects | High | Loss of trust in record authenticity is reputationally serious. |
| Financial consequences | High | Forged records can drive incorrect billing, contracts, legal decisions. |
| **Aggregation** | **High** | |

### A1 plaintext — Availability

| Damage scenario | Selected | Rationale |
|---|---|---|
| Impaired ability to perform tasks | Normal | 1–24h tolerable for typical integrator workloads; backups exist. |
| Financial consequences | Normal | Recoverable. |
| **Aggregation** | **Normal** | |

### A2 DEK — Confidentiality

Inherits A1 confidentiality per leak. **Aggregation: High.** Per-record blast radius.

### A3 principal private key — Confidentiality

Inherits A1 confidentiality, scaled by how many grants the principal holds. **Aggregation: High** (single principal compromise bounded by their access scope).

### A4 wrap row — Integrity

Inherits A1 integrity (feeds into substitution / forgery flows). **Aggregation: High.**

### A5 ciphertext — Integrity

Inherits A1 integrity. **Aggregation: High.**

### A6 grant-relationship metadata — Privacy

| Damage scenario | Selected | Rationale |
|---|---|---|
| Privacy | Normal | "X has access to Y" is sensitive but rarely catastrophic; metadata not content. |
| Negative effects | Normal | |
| **Aggregation** | **Normal** | Bump to High for premium-sensitive deployments (e.g. journalism, whistleblowing). |

### A7 grant-request records — Privacy

Same shape as A6. **Aggregation: Normal.**

### A8 library reputation — Integrity

| Damage scenario | Selected | Rationale |
|---|---|---|
| Negative internal / external effects | High | A CVE in a crypto-handling library damages maintainer reputation broadly. |
| **Aggregation** | **High** | |

### A9 ephemeral grant row — Confidentiality / Integrity / Availability

Confidentiality inherits A1 **per row**, bounded by TTL × in-flight write rate. Integrity tampering breaks the worker pathway for the affected blob; user reads via grants are unaffected. Availability loss is worker-pathway only.

**Aggregations: C-High, I-High, Av-Medium.**

### A10 env seal key — Confidentiality

Compromise unlocks every currently live A9 row. Per-blob blast radius multiplied by the in-flight row count (`TTL × write_rate`), not unbounded like the backup private key would be. Lives in app-process memory by design, so it's strictly easier to reach than the backup key (EA9, cold storage). The TTL is the compensating control.

**Aggregation: C-High.**

### A11 storage-service credentials — Confidentiality / Availability

Confidentiality compromise yields full read on the storage backend (every ciphertext blob). Under EA2 + the encryption layer, ciphertext read **does not break A1 confidentiality** (wraps still hold) but enables T24's secondary effects. **Write**-capable credential leak enables T4 (envelope substitution) and T23 (mirror tampering). Availability: an attacker with write can purge or corrupt the bucket.

**Aggregations: C-High (under the EA2-holds caveat); Av-Medium** (bucket deletion is a recoverable Av event with proper IAM separation and bucket versioning, both integrator-side controls).

## 4b. Required attack potential per threat

Scoring per ISO/IEC 18045. The required attack potential is determined by the **higher** of the Identification and Exploitation column sums.

### T2: DB-read plaintext disclosure with `Asymmetric`/`KeyGrants` KeyManager, EA2 holds (MC4)

Affected: A1 (C). DBA must break AES-256-GCM or X25519 ECIES to recover the plaintext from ciphertext alone (no private key access).

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | > 1 month (5) | Not practical (\*) |
| Expertise | Expert (5) | Expert (4) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 1 day (2) | < 1 day (4) |
| Equipment | Bespoke (5) | Bespoke (6) |
| **Sum** | **19** | **\*** |

**RAP: High (not practical).** Cryptographic infeasibility per BSI TR-02102 horizon 2030.

### T3: EA2 violation — principal private keys in DB plaintext (MC4')

Affected: A1 (C). DBA reads `users.private_key` directly and unwraps DEKs for all that principal's grants.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 day (2) | < 0.5 hour (0) |
| Expertise | Layman (0) | Proficient (2) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **4** | **6** |

**RAP: No rating** (max = 6). Trivial once the integrator's misconfiguration is in place.

### T4: Envelope substitution by DBA (MC3b)

Affected: A1 (I), A4 (I), A5 (I). DBA replaces ciphertext for record R with attacker-chosen plaintext encrypted under a fresh DEK, and replaces every grant row for R with wraps of that DEK to each principal's (public) key. Principals decrypt successfully and see attacker content.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 day (2) | < 1 day (3) |
| Expertise | Proficient (2) | Proficient (2) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | Standard (1) | Standard (2) |
| **Sum** | **7** | **9** |

**RAP: No rating** (max = 9).

**2026-10 review pass (recovery path).** `AshEnvelope.recover_plaintext/3` passed the `"iv"` and `"tag"` from blob metadata to the AEAD without length checks. AES-GCM verifies a shortened tag as a shortened tag, so a metadata writer could truncate the tag to one byte and get a tampered ciphertext accepted on the recovery path with probability 2^-8 instead of 2^-128 (N1). This is a cheaper variant of the integrity attack T4 already rates (the same adversary can substitute the whole envelope, including the backup wrap, using public keys only), so the T4 rating is unchanged; it did, however, violate SG2 ("AEAD verification must fail closed"). PR #14 enforces 12-byte IV, 16-byte tag and 32-byte DEK on the recovery path (C36, SR19).

### T5: DBA row-shuffling (MC2/MC3)

Affected: A1 (Av). DBA swaps wrap blobs between rows; decryption returns `:decryption_failed` for affected records.

**Not rated.** DBA-induced denial-of-service is intrinsic to the threat class (the DBA can also `DROP TABLE` or delete rows) and is acknowledged as out of scope at the class level. Documented as a verified non-confidentiality outcome: under EA2 the row shuffle does not leak plaintext.

### T6: Reconciliation bug — wrong-principal grant (MC12)

Affected: A1 (C), A4 (I), A6 (I). A defect in granter-chain logic or `Ash.can?` interpretation issues a grant to a principal whose policy does not authorize read.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 month (3) | < 1 day (3) |
| Expertise | Expert (5) | Expert (4) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 1 day (2) | < 1 day (4) |
| Equipment | Standard (1) | Standard (2) |
| **Sum** | **13** | **15** |

**RAP: Low** (max = 15).

**Scope note (2026-10 review pass).** T6 covers every way the persisted grant state can diverge from the read policy: a grant issued to a principal the policy does not authorize, a grant that is not revoked after the policy stops authorizing (SR8 (b)), and a legitimate principal left without grant or pending request (SG8). The October 2026 review findings below all land here.

**Re-rating (2026-10 review pass).** The Undesirable rating above rested on a false premise: that the planner and the apply side behave as SR8 states and C12 claims. The review showed that, on `main` at b799f14 and before, they did not:

- The planner's grant-existence read honoured `config.authorize?` (default `true`) with no actor, so on a policy-protected grants table every existence check came back empty and stale grants were never planned for revocation (fail-open). C12 assumed the planner saw the grants.
- `Ash.can?` ran with the default `maybe_is: true`, so an unresolvable `:maybe` policy result authorized issuing a grant.
- A scope function returning `[]` was treated as an empty keyword filter and matched the whole encrypted table.
- No tenant was threaded through the planner, apply side, scope streams or async job args; on attribute-multitenant resources `scope :all` and `SyncSubject` issued and revoked grants across tenants.
- An update that changed the scope input (a membership moved from record A to record B) never reconciled A, so the principal kept the wrapped DEK for A (review finding N2).
- `mix ash_envelope.gen.key_grants` keyed scaffolded grants by the owning record id while the `KeyGrants` BlobIO manager keys them by blob id, so reconcile never found (and never revoked) the manager's rows (N19).
- `Runner.run/3` returned `:ok` unconditionally and the async worker returned `:ok` on failure, so a failed revocation was logged and never retried (fixed by the merged PR #8).

None of these needs attacker skill: a de-authorized principal keeps a working grant through ordinary use of an integrator configuration the library documents or scaffolds. Corrected rating for the pre-fix code:

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 day (2) | < 0.5 hour (0) |
| Expertise | Layman (0) | Layman (0) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **4** | **4** |

**RAP (pre-fix, corrected): No rating** (max = 4). Damage High → **Inacceptable**.

After PR #14 (planner reads system-side and expiry-aware, `maybe_is: false`, empty scope means no subjects, pre- and post-change scope reconciled on update, tenant propagated end to end, scaffolds keyed by blob id) together with the merged PR #8 (failures surfaced, async jobs retried), the defects above are fixed and regression-tested (C30-C33, C37, C38). Finding a further defect again requires the analysis effort of the original table, so the RAP returns to **Low** and the risk to **Undesirable**. This is a reduction, not a closure: three reconcile findings remain open (N7 oversized scope drops the whole reconciliation, N12 deleted principal keeps grants, N13 unvalidated `affects` entries; see `09_inspection.md`), plus N15 (non-injective `subject_id_resolver` binds a later blob to an earlier blob's DEK, an SG5 violation outside reconcile).

### T7: Key material leaked via async Oban job args (MC13)

Affected: A2 (C), A3 (C). A regression that serializes a DEK or private key into `oban_jobs.args`, where any DB reader can recover it.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 month (3) | < 0.5 hour (0) |
| Expertise | Expert (5) | Layman (0) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **10** | **4** |

**RAP: Low** (max = 10). Currently no key material crosses to Oban — finding the regression takes effort; exploiting it is trivial.

### T8: Key material / plaintext leaked via logs (MC6)

Affected: A1 (C), A2 (C), A3 (C). A regression that logs an actor struct verbatim or includes plaintext in an error message.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 month (3) | < 0.5 hour (0) |
| Expertise | Expert (5) | Layman (0) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **10** | **4** |

**RAP: Low** (max = 10).

### T9: Encrypted-blob proxy bypass — out of `ash_envelope` scope

**Excluded.** With `AshEnvelope.Storage.Plug` removed, the HTTP surface that serves encrypted blobs is provided by the upstream `ash_storage` proxy (or an integrator route that calls `AshStorage.BlobIO.read/3`). Path-traversal, signed-URL handling, and disposition encoding are the proxy's responsibility. `ash_envelope` provides the bytes-level confidentiality via the `Encryption` layer and the DEK custody via its KeyManagers; bypasses of the host's HTTP surface are out of this library's threat model.

### T10: Authorization bypass on share/revoke — integrator policy gap (MC11)

Affected: A1 (C), A4 (I). Library accepts `share`/`revoke` calls and Ash policies on the grants resource are either missing or permissive.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 day (2) | < 0.5 hour (0) |
| Expertise | Proficient (2) | Layman (0) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **6** | **4** |

**RAP: No rating** (max = 6). The library defends partially via `authorize?: true` defaults; residual risk is the integrator's policy definitions.

**Control-effectiveness correction (2026-10 review pass).** The rating stays **Inacceptable** (it is already the matrix maximum), but two control claims behind the "partially mitigated" wording were false on `main` at b799f14:

- **C4.** Every `KeyGrants` and `GrantRequests` Ash call ran with `actor: nil` under `authorize?: true`. Actor-scoped policies such as the scaffolded `user_id == ^actor(:id)` could never match, so the default either refused every call or pushed integrators to `authorize?: false`, which removes the policy layer altogether. The ephemeral worker path of the `KeyGrants` BlobIO manager had the same shape (N8). `GrantRequests.fulfill/6` also did not check that `target_actor` was the request's target, so a grant could be issued to whichever principal the caller's loader returned.
- **C14.** `assert_policies_defined!/2` accepted `policy always() do authorize_if always() end` as coverage, so the helper passed for a wide-open grants resource while its documentation claimed it caught authorization bypasses.

PR #14 threads a real actor through every call (C34), makes the ephemeral and reconcile bookkeeping paths explicitly system-side, rejects a mismatched fulfil target with `{:error, :target_mismatch}`, and extends the helper to reject vacuous permissive coverage (C14). The merged PR #5 removed a scaffolded LiveView revoke handler that let any authenticated user revoke any grant by id (MC8). With these, the "partially mitigated" statement holds for the first time; the residual is still integrator policy correctness (EA3).

### T11: BEAM host side-channel (MC5)

**Excluded** per EA5 (host OS / BEAM node integrity not in scope). The DEK lives in heap memory only for the duration of the encryption/decryption call; no process-dictionary handoff is used (BlobIO carries the DEK through a typed `Writer.Operation`).

### T12: DoS via mass revoke / pending-request flooding (MC8/MC9)

Affected: A6 (Av). Authenticated user calls `revoke` repeatedly or triggers `GrantRequests.create` flooding.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 0.5 hour (0) | < 0.5 hour (0) |
| Expertise | Layman (0) | Layman (0) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **2** | **4** |

**RAP: No rating** (max = 4). Library defends partially via `authorize?: true` and request idempotency; integrator-side rate-limiting handles the rest.

**2026-10 review pass.** A second DoS vector of the same class: a principal whose key attribute is missing, malformed or a degenerate X25519 point made `KeyGrants.create_for_actor`, `resolve_for_actor` and the `Asymmetric` manager raise instead of returning an error tuple (N9, N10, merged PR #3), and a crafted wrap with a short inner ciphertext made `unwrap_dek/2` return a non-32-byte "DEK" that crashed the read pipeline (N3). In batch paths (`GrantRequests.fulfill_outstanding/5`, the reconcile granter chain) one such principal aborted the run for everyone else. PR #14 converts these to error tuples (SR38, C35). Rating unchanged. Residual: `KeyGrants.create_for_actor/6` and `share/6` still call `wrap_dek/2` unguarded for a degenerate public key (open, see `09_inspection.md`).

### T13: Grant-relationship metadata disclosure (MC7)

Affected: A6 (C, P). DBA reads `key_grants` and infers who has access to which subject.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 0.5 hour (0) | < 0.5 hour (0) |
| Expertise | Layman (0) | Layman (0) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **2** | **4** |

**RAP: No rating** (max = 4). Inherent to the design.

### T15: Backup-key compromise → mass plaintext disclosure (MC17)

Affected: A1 (C), A2 (C). The `:backup_public_key` feature embeds an X25519 ECIES wrap of every blob's DEK in layer metadata. An attacker who obtains the corresponding *private* key can recover the DEK and plaintext for every blob written while that public key was current.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 day (2) | < 0.5 hour (0) |
| Expertise | Layman (0) | Proficient (2) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 1 day (2) | < 1 day (4) |
| Equipment | Standard (1) | Standard (2) |
| **Sum** | **7** | **10** |

**RAP: Low** (max = 10) **under EA9 custody assumptions** (cold-storage / KMS / split-key). RAP collapses to "No rating" if the integrator stores the backup private key online next to the wraps — equivalent to the EA2 violation pattern, but with a broader blast radius because one key covers every blob.

### T16: Backup-key rotation incomplete → mass availability loss for backup-recovery path (MC18)

Affected: A1 (Av), specifically the backup-recovery path. If the integrator rotates `:backup_public_key` and retires the previous private key before every blob's `"backup"` wrap has been re-wrapped, blobs that still carry the old `key_id` become unrecoverable through the backup path. Per-principal grants are unaffected — this is an availability loss only for the escrow / disaster-recovery path.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 0.5 hour (0) | < 0.5 hour (0) |
| Expertise | Layman (0) | Layman (0) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **2** | **4** |

**RAP: No rating** (max = 4). Operationally trivial — a single CLI mis-step. Mitigation: `mix ash_envelope.rotate_backup_key` exits non-zero if any blob remains wrapped to a non-current key after the pass, and supports `--check-only` for a no-write pre-flight.

**2026-10 review pass.** The C19 claim (T16 drops to Tolerable once the CLI is part of the runbook) rested on the premise that "`key_id` equals the current fingerprint" implies "backup wrap opens to the blob's DEK". That premise was false: rotation unwrapped the DEK from the streamed snapshot and wrote it into a re-fetched row, so a blob whose envelope changed in between ended up with a backup wrap of the old DEK tagged as current, which the final check can never flag (N4). Per-blob failure reasons were also dropped, so a wrong previous key looked like ordinary staleness (N5), and before the merged PR #5 a misspelled switch (e.g. a typo of `--check-only`) was silently discarded and the task proceeded to writes. PR #14 rotates from the freshly read row, treats an already-current fresh row as a no-op, and reports failures by reason (C19). The 4c rating (Undesirable) is unchanged; the Tolerable-with-runbook claim holds again for the tool itself. Residual: the read-modify-write on blob metadata still has a millisecond clobber window against concurrent metadata writers (needs optimistic locking upstream), and the task cannot pass `actor`, `authorize?` or `tenant`, so policy-protected or multitenant blob resources fail per blob (now visibly).

### T9: Encrypted-blob proxy bypass (returned to scope in v0.4-dev)

Affected: A1 (C), A5 (C).

The encryption layer **forces a proxy URL** for encrypted blobs (rejects `service_url` strategies), so reads must traverse the integrator's proxy route. Bypass requires either: forging a signed-token bearer; replaying a stale/long-lived token; or sidestepping the proxy authentication entirely (route is public). All three are integrator-side surface.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 day (2) | < 1 day (3) |
| Expertise | Proficient (2) | Proficient (2) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **6** | **9** |

**RAP: No rating** (max = 9).

**Damage potential: High.** Plaintext disclosure for any blob the attacker can resolve.

**Risk: Inacceptable** under default integrator behavior, becoming **Undesirable** when the proxy has working signed-token bearer with sensible expiry (which is what the encryption layer sets up by default via `access: {:signed, secret: …}`). Library response: SR31 documents the integrator responsibility; the encryption layer's `serving/2` callback already forces the proxy strategy and emits the access spec.

### T17: Env seal key disclosure (A10 alone)

Affected: A10 (C).

A regression or operator mistake exposes A10 without simultaneously granting DB read on the grants table. Vectors: a log line including `Application.get_env(:ash_envelope, :seal_key)`; an error report capturing `:erlang.system_info(:env)`; a crash dump containing the binary; a misconfigured `/health` endpoint dumping config.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 month (3) | < 0.5 hour (0) |
| Expertise | Expert (5) | Layman (0) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **10** | **4** |

**RAP: Low** (max = 10).

**Damage potential alone: Negligible.** Without DB read of the grants table, A10 decrypts nothing — this is the layered-defence property the feature is built on.

### T18: Env seal key + DB read → mass disclosure of in-flight plaintext

Affected: A1 (C), A2 (C), A9 (C), A10 (C).

Attacker holds both A10 and read on the grants table. They walk rows with `principal_id IS NULL`, unseal each row's `dek_attribute` under A10, decrypt the corresponding ciphertext.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 day (2) | < 0.5 hour (0) |
| Expertise | Layman (0) | Proficient (2) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 1 day (2) | < 1 day (4) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **6** | **10** |

**RAP: Low** (max = 10) **under EA10**.

**Damage potential: High.** Mass plaintext disclosure (legal / privacy / financial all High per BSI 200-2). **Bounded by TTL × write rate** — only blobs whose ephemeral row is currently live. With a default 24h TTL and 1000 writes/day, blast radius is ~1000 blobs at any moment.

Comparison with T15 (backup-key compromise):

| | T15 | T18 |
|---|---|---|
| Key custody | EA9 — cold / KMS / split | EA10 — app-process memory |
| Difficulty of obtaining key | High (custody is hardened) | Lower (in-process, more reachable) |
| Additional access needed | DB read or none | DB read of grants table |
| Blast radius | Every blob ever written | Only blobs with live ephemeral rows |
| Time-bounded? | No (until backup key rotated) | Yes (TTL) |

**2026-10 review pass.** The TTL bound holds on the library's own path (the `KeyGrants` BlobIO manager never passes `:expires_at`), but `KeyGrants.create_ephemeral/5` accepts an explicit `expires_at: nil` from a direct caller and writes a row that is never purged and resolves indefinitely (N17, open). The rating stays Undesirable because the default path is bounded; SR25's "respected unconditionally" wording is not yet met for direct callers.

### T19: `renew_ephemeral/5` misuse → worker-pathway DoS

Affected: A9 (Av), analyzer pipeline availability only.

A caller invokes the lower-level `renew_ephemeral/5` with a DEK that doesn't match the blob's actual DEK — developer error, not an attack. The legitimate row is destroyed and replaced with one that decrypts to garbage. User reads via grants are unaffected throughout.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 0.5 hour (0) | < 0.5 hour (0) |
| Expertise | Layman (0) | Layman (0) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **2** | **4** |

**RAP: No rating** (max = 4).

**Damage potential: Normal.** Worker-pathway availability only. Recovery: call `renew_ephemeral_with_actor/5` with the correct authority. Mitigated by API shape (the `_with_actor` variant is documented as the primary admin path; the bare `renew_ephemeral/5` is reserved for backup-escrow flows).

**2026-10 review pass.** `renew_ephemeral/5` destroyed the live row before sealing the replacement, so a missing or invalid seal key turned a renewal into a revocation of the worker pathway. PR #14 seals first and restores the previous row best-effort if the insert fails (C22, SR23). Rating unchanged (Tolerable). Separately, the ephemeral create and resolve inside the `KeyGrants` BlobIO manager ran under `config.authorize?` with no actor and no principal, so under scaffold-shaped policies every attach with expiring grants configured failed (N8); PR #14 runs those two paths system-side (C34). `renew_ephemeral_with_actor/5` still runs its destroy and create under `config.authorize?` with the renewing actor, which an actor-scoped policy on a principal-less row will not admit; this residual of N8 is open.

### T20: Time-bounded user grant outlives the policy intent

Affected: A1 (C). Integrator semantics confusion.

Integrator issues a grant with `expires_at = trial_end` expecting "user loses access after the trial." The cron purges the row at `trial_end`, but the next reconcile pass sees no grant and the read policy (which doesn't encode `expr(now() < trial_end)`) still authorizes the user — reconcile issues a **new permanent grant**.

Not a library bug. The documented "policy is access-control truth; `expires_at` is grant-lifecycle convenience" invariant. But it's the most likely way a misunderstanding causes a confidentiality intent mismatch.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 0.5 hour (0) | < 0.5 hour (0) |
| Expertise | Layman (0) | Layman (0) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **2** | **4** |

**RAP: No rating** (max = 4).

**Damage potential: High** (the unintended confidentiality grant is on regulated data).

Downstream of EA3 (integrator policy correctness). Library response (SR27, C25):

1. **Documentation** — the `expiring-grants` topic and the `KeyGrants` moduledoc make the policy-vs-expiry invariant explicit.
2. **Generator scaffold** — `mix ash_envelope.gen.key_grants` emits a new "4b. Policies on the encrypted resource" section in its notice, with three labeled, commented-out time-bound `:read` policy patterns (trial / subscription / membership) that integrators can adapt to their schema. The generator also extends the grants-resource `:read` policy with `is_nil(expires_at) or expires_at > now()` as defense in depth against direct reads that bypass `KeyGrants.resolve_for_actor/4`.

The matrix label stays **Inacceptable** because the rated damage and required attack potential are unchanged by the scaffold (consistent with how T3 and T10 remain Inacceptable despite SR5/SR13). What changes is that the response now has a structural support layer rather than relying on the integrator reading the topic doc.

### T21: Variant generation widens the DEK exposure window

Affected: A2 (C, transient), A1 (C, transient on disk via temp file).

The `ash_storage` variant generator decrypts the source via `BlobIO.read/3` (holding the DEK in process memory), writes the plaintext to a process-owned temp file, invokes an integrator-supplied transform module, reads the result, and re-encrypts via `BlobIO.write/3`. The DEK is transient (process memory only); the plaintext-on-disk window is the duration of `transform/3`. Compared to a regular read/write, this widens the in-process DEK lifetime across a multi-step pipeline.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 day (2) | < 1 day (3) |
| Expertise | Expert (5) | Expert (4) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 1 day (2) | < 1 day (4) |
| Equipment | Standard (1) | Standard (2) |
| **Sum** | **12** | **15** |

**RAP: Low** (max = 15) **under EA5** (host trust).

**Damage potential: High** (per-blob plaintext) but bounded to the blobs being processed at attack time.

**Risk: Undesirable** (EA5 holds firmly) → **Tolerable** when the variant generator's `try/finally` temp-file cleanup is verified (SR29). The DEK exposure is not different in kind from any other BlobIO read; the variant pipeline just makes the window longer.

### T22: Direct-upload bypass attempt against an encrypted attachment

Affected: A5 (I) — only via integrity, not confidentiality.

The encryption layer's `direct_upload/2` returns `{:error, …}`, so `prepare_direct_upload/3` cannot issue a presigned URL for an encrypted attachment. An attacker who has obtained a presigned URL must therefore be using one issued for an unencrypted attachment, or one issued by sidestepping the layer chain (integrator-side misconfiguration). If they upload bytes anyway under a key that maps to an encrypted attachment, the downstream `BlobIO.read/3` AEAD verification **fails closed** (`:decryption_failed`).

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 0.5 hour (0) | < 0.5 hour (0) |
| Expertise | Proficient (2) | Proficient (2) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | Standard (1) | Standard (2) |
| **Sum** | **5** | **6** |

**RAP: No rating** (max = 6).

**Damage potential: Normal** — DoS only (the blob can't be read after; reattach required). No confidentiality breach; AEAD prevents plaintext recovery from the poisoned bytes.

**Risk: Tolerable.** SR28 locks the encryption layer's direct-upload refusal as a load-bearing contract.

### T23: Mirror service partial-write orphans

Affected: A5 (I, Av), A11 (Av).

The `AshStorage.Service.Mirror` adapter fans writes to N backends. The library halts when the *primary* fails, but partial failures in *secondaries* (after the primary succeeded) report asynchronously and leave orphaned files. Operationally, the orphans are an Av / I concern: subsequent reads still succeed against the primary, but the at-rest state diverges across backends, and replication-guaranteed read paths may pick up the inconsistent secondary.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 0.5 hour (0) | < 0.5 hour (0) |
| Expertise | Layman (0) | Layman (0) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **2** | **4** |

**RAP: No rating** (max = 4).

**Damage potential: Normal** — Av / I only. AEAD on the ciphertext prevents tamper-without-detection (an attacker who corrupts a secondary file will trigger `:decryption_failed` on read against that backend; primary-elected read fallthrough degrades to DoS).

**Risk: Tolerable.** Integrator-owned: monitor mirror partial-failure events; reconcile orphans on a schedule. **SR33** locks the library's documentation commitment for the integrator-side semantics + recommended mitigation (`how-envelope-encryption-works` topic, "Storage-service redundancy (Mirror)" section).

### T24: Storage-service credential leak

Affected: A11 (C); secondarily A1 (I) via T4, A5 (I), A1 (Av).

An attacker exfiltrates the storage-service credentials (S3 access keys, Azure SAS, disk HMAC signing secret) via process env dump, build-image inspection, log entry, or container metadata. Read alone yields every ciphertext but does not break A1 confidentiality (AES-256-GCM + X25519 wraps still hold under EA2). Write enables T4 (envelope substitution requires no key material to forge) and T23 (mirror tampering).

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 month (3) | < 0.5 hour (0) |
| Expertise | Expert (5) | Layman (0) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 1 day (2) | < 1 day (4) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **12** | **8** |

**RAP: Low** (max = 12).

**Damage potential: High** (writable credentials → T4 envelope substitution; readable-only is bounded by EA2 holding).

**Risk: Undesirable** under EA11. The library's defense surface is documentation (EA11 + SR30): credential custody is exclusively the integrator's responsibility, the library never persists or logs credentials, and credentials are not passed through the BlobIO operation structs (they live in service-context config).

### T25: Spark DSL transformer / verifier silently accepts a misconfiguration

Affected: A4 (I), A6 (I) — indirectly, via the reconcile DSL state.

Scope: `AshEnvelope.Reconcile.Transformers.ValidateConfig` and
`AshEnvelope.Reconcile.Affecting.Transformers.InjectSyncPrincipal`. (Out of
scope: `ash_storage`'s transformers, which are upstream's concern.)

Vector: a bug in `ValidateConfig` accepts a misconfigured reconcile block
(e.g. mismatched attribute names between the encrypted resource and the
grants resource); the planner then operates on inconsistent state and either
crashes or — worse — issues grants under the assumed-but-wrong shape.
"Crashes" is the fail-closed direction; the fail-open direction is the
threat.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 1 month (3) | < 1 day (3) |
| Expertise | Expert (5) | Expert (4) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 1 day (2) | < 1 day (4) |
| Equipment | Standard (1) | Standard (2) |
| **Sum** | **13** | **15** |

**RAP: Low** (max = 15).

**Damage potential: High** (could weaken T6's reconciliation-correctness
controls if the bug routes a grant to the wrong principal).

**Risk: Undesirable.** Mitigated by `validate_config_test.exs`,
`affecting_extension_test.exs`, and the fixture-driven reconcile suite,
which between them cover transformer happy + sad paths. **SR34** locks the
test-coverage obligation so the suite cannot quietly regress.

**2026-10 review pass.** `ValidateConfig` accepted the default granter
chain (`[:actor, :request]`) without `grant_requests_resource`, unknown
granter strategy shapes, and `mode :async` without Oban compiled; all three
failed only at runtime. PR #14 turns them into compile-time `DslError`s
(C39). The `affects` side is still unvalidated: a typo in `principal` or in
`actions` compiles and makes the entry a silent no-op, so destroys may never
revoke (N13, open; a compile-time check is blocked by the compile cycle).
Rating unchanged (Undesirable).

### T26: Generator argument abuse — `mix ash_envelope.gen.*`

Affected: A8 (library reputation). No other asset because the generators
**emit notices only** (`Igniter.add_notice/2`); none of them write files
directly to the integrator's working tree. The integrator copy-pastes
snippets from the notice into their own editor, so even crafted module-name
arguments cannot path-traverse a write.

Vector: a malicious / mis-typed `--grants-resource "Foo/../etc/passwd"`-
shaped argument is parsed by `Igniter.Project.Module.parse/1` (rejects most
non-module shapes) or interpolated via `inspect/1` into the notice text
(escapes properly into Elixir source). `Mix.Tasks.AshEnvelope.RotateBackupKey`
takes a `--previous-private-key-path` argument that flows into `File.read/1`;
the integrator running the task supplies their own machine's path, so the
"attacker" would be the integrator themselves — out of trust model (EA1).

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | < 0.5 hour (0) | < 0.5 hour (0) |
| Expertise | Layman (0) | Layman (0) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 0.5 hour (0) | < 0.5 hour (0) |
| Equipment | None (0) | Standard (2) |
| **Sum** | **2** | **4** |

**RAP: No rating** (max = 4). But there is nothing useful to do once you
have it — the worst case is a confusing notice the integrator decides not to
paste.

**Damage potential: Normal** (no security boundary crossed; no file written;
no code executed beyond the Mix task itself).

**Risk: Tolerable.** **SR35** locks the "notices-only, never writes files
directly" invariant per task — a regression that switched a generator to
auto-file-write would trigger SR35 review.

### T14: Cryptographic primitive deprecation before update (EA8)

Affected: A1 (C), A2 (C), A8 (I). BSI horizon shifts or a primitive break is announced before the library updates.

| Factor | Identification | Exploitation |
|---|---|---|
| Elapsed Time | > 1 month (5) | Not practical (\*) |
| Expertise | Expert (5) | Expert (4) |
| Knowledge of target | Public (2) | Public (2) |
| Access to target | < 1 day (2) | > 1 month (9) |
| Equipment | Standard (1) | Bespoke (6) |
| **Sum** | **15** | **\*** |

**RAP: High (not practical)** under BSI horizon 2030. Quantum-capable adversaries out of scope per EA8.

**2026-10 review pass.** The ECIES KDF uses the ephemeral public key as HKDF salt and a fixed info label; the recipient public key is not part of the KDF transcript (HPKE binds both), and the raw `wrap_dek/2` output carries no version byte, unlike the `SealKey` format (SR22). No concrete exploit was found; this is hardening and an algorithm-agility gap that would make a future primitive change (the T14 scenario) a dual-read migration (N11, open). Rating unchanged.

## 4c. Risk rating

| # | Threat | Damage | RAP | **Risk** | Notes |
|---|---|---|---|---|---|
| T2 | `Asymmetric` / `KeyGrants` KeyManager + DBA, EA2 holds | High | High (not practical) | **Tolerable** | Cryptographic infeasibility. Monitor BSI horizon. |
| **T3** | EA2 violation: priv keys in DB plaintext | High | No rating | **Inacceptable** | Integrator-side anti-pattern; library cannot enforce. Response: documentation + generator scaffolds that KEK-encrypt private-key columns by default. |
| **T4** | DBA forges entire envelope | High | No rating | **Inacceptable** | Library does not cryptographically prevent. Response: document the integrity bound; integrators with DBA-class threats requiring forgery resistance layer signed audit / append-only / WORM atop the library. |
| T6 | Reconciliation bug → wrong-principal grant | High | Low | **Undesirable** | Response: reconciliation invariant tests + property tests for `Runner.plan`/`apply_plan!`. 2026-10 pass: was Inacceptable on the pre-fix code (planner fail-open, `maybe_is: true`, empty-scope and cross-tenant fan-out, moved-scope stale grants); reduced back to Undesirable by PR #14 and the merged PR #8 (SR8, SR36, SR37, SR39). Open: N7, N12, N13, N15. |
| T7 | Key material in async job args (regression) | High | Low | **Undesirable** | Response: CI test asserting no key material in `Oban.Job.args` for async-mode dispatch. |
| T8 | Plaintext / keys in logs (regression) | High | Low | **Undesirable** | Response: CI test scanning log output across the public API for entropy-suggestive byte sequences. |
| **T10** | Authorization bypass via integrator policy gap | High | No rating | **Inacceptable** | Library defends via defaults (`authorize?: true`). Residual risk is downstream. Response: documentation, test helper, generator-scaffolded policies. 2026-10 pass: C4 and C14 did not work as claimed before PR #14 (nil actor on every grant call; helper accepted vacuous policies); now actor-threaded (SR13) and vacuous coverage rejected (SR14). |
| T12 | DoS via revoke / request flooding | Normal | No rating | **Undesirable** | Library partial defence (idempotency, `authorize?`). Documented as integrator-side concern. 2026-10 pass: malformed or degenerate principal keys no longer abort batch paths (SR38). |
| **T13** | Grant-relationship metadata disclosure to DBA | Normal | No rating | **Undesirable** | Inherent to design. Documented limitation; possible bump to Inacceptable for premium-sensitive deployments (then design pivots, e.g. encrypted-index schemes — out of v1 scope). |
| T14 | Crypto primitive deprecation | High | High (not practical) | **Tolerable** | Monitor BSI TR-02102 horizon; rotate algorithms before deprecation. |
| T15 | Backup-key compromise → mass disclosure | High | Low (under EA9) | **Undesirable** (Tolerable when EA9 holds firmly) | Backup escrow is opt-in (`:backup_public_key` unset by default). Custody is integrator-side (EA9); blast radius is broad by design. |
| T16 | Backup-key rotation incomplete → backup-path availability loss | High (Av-only) | No rating | **Undesirable** | Mitigated by `mix ash_envelope.rotate_backup_key` (SR19) — fails non-zero if any blob remains stale; `--check-only` for pre-flight. 2026-10 pass: rotation now re-wraps from the stored row and reports failure reasons; strict switch parsing (SR20). |
| T17 | Env seal key disclosure alone (A10 leak without DB read) | Negligible | Low | **Negligible** | Layered-defence property: the seal key alone unlocks nothing without the corresponding rows. |
| T18 | Env seal key + DB read → mass disclosure of in-flight plaintext | High | Low (under EA10) | **Undesirable** | Opt-in via SR24; bounded by TTL × write rate; AAD on the seal prevents row-shuffling. |
| T19 | `renew_ephemeral/5` misuse → worker-pathway DoS | Normal | No rating | **Tolerable** | Mitigated by API shape (SR23): `renew_ephemeral_with_actor/5` is the primary admin path. |
| T20 | Time-bounded user grant outlives policy intent | High | No rating | **Inacceptable** (downstream of EA3) | Documentation + generator scaffold (SR27, C25): policy is access-control truth; `expires_at` is grant-lifecycle convenience. Generator emits parent-resource time-bound `:read` policy templates and a grants-resource expiry filter. |
| **T9** | Encrypted-blob proxy bypass | High | No rating | **Inacceptable** (downstream of EA3) → **Undesirable** with proper signed-token auth | Encryption layer forces proxy URL + signed access. Integrator-side: token expiry / rotation / auth middleware. SR31 documents responsibility. |
| T21 | Variant gen widens DEK exposure window | High | Low (under EA5) | **Undesirable** → **Tolerable** with verified temp-file cleanup | SR29 locks the variant generator's `try/finally` cleanup. |
| T22 | Direct-upload bypass attempt vs encrypted attachment | Normal (DoS) | No rating | **Tolerable** | Encryption layer rejects direct uploads (`AshStorage.Layer.Encryption.direct_upload/2` returns error). SR28 locks the rejection. |
| T23 | Mirror service partial-write orphans | Normal (Av/I) | No rating | **Tolerable** | Integrator-owned: monitor partial failures, reconcile orphans. AEAD prevents tamper-without-detection. |
| T24 | Storage-service credential leak | High (under writable) | Low | **Undesirable** | EA11 (credential custody) + SR30 (documented). Read-only credentials don't break A1 confidentiality; write-capable enables T4. |
| T25 | Spark DSL transformer / verifier silently accepts misconfig | High | Low | **Undesirable** | SR34 locks transformer happy + sad path test coverage. Existing test suite (`validate_config_test.exs`, `affecting_extension_test.exs`) already covers the surface; SR formalizes the obligation. 2026-10 pass: granter-chain, `grant_requests_resource` and async-without-Oban checks added; `affects` validation open (N13). |
| T26 | Generator argument abuse (`mix ash_envelope.gen.*`) | Normal | No rating | **Tolerable** | Generators emit notices only — no auto-file-writes. SR35 locks the invariant. |

Out-of-scope (not in matrix): T5 (DBA DoS, intrinsic class), T11 (host side-channel, EA5). T9 returns to scope in v0.4-dev (see scope expansion in `00_overview.md`).

## 4d. Threat / control trees

Not used. The threat space is mostly single-step; the only naturally compound flow is T4 (substitute ciphertext **AND** substitute every wrap row), which is captured in the T4 row description.

## 4e. Summary

**Inacceptable findings (5):** T3, T4, T9, T10, T20 *(T9's response is documentation-only; T20's response is documentation + generator scaffold; both are downstream of EA3)*.
**Undesirable findings (11):** T6, T7, T8, T12, T13, T15, T16, T18, T21, T24, and T9 (when integrator-side auth is in place).
**Tolerable findings (5):** T2, T14, T19, T22, T23.
**Negligible findings (1):** T17.
**Out of scope:** T5, T11.

The Inacceptable findings each have a documented response (above) and drive the highest-priority security requirements in step 6. The Undesirable findings drive concrete library SRs (regression tests, property tests, generator hardening, rotation-CLI fail-on-incomplete check, opt-in expiring-grants surface, ash_storage contract locks). The Tolerable findings carry forward as monitoring obligations.

**Conditional on opt-in:**
- T17/T18 are conditional on expiring-grants being configured (SR24 / C23).
- T21 is conditional on the variant generation pipeline being used.
- T22/T23 are conditional on the corresponding ash_storage features (direct uploads / mirror service) being configured.
- T24 always applies when storage is used (any service adapter requires credentials).

Deployments that don't enable a given feature retain the corresponding pre-feature risk profile exactly.

### What changed in the 2026-10 review pass

No threat is added or retired and the matrix counts above are unchanged. One threat was re-rated because its earlier rating rested on a control that did not work:

- **T6**: Undesirable (as assessed in v0.4-dev) → **Inacceptable** (corrected, for the code on `main` up to b799f14) → **Undesirable** (after PR #14 and the merged PR #8). The planner could not see grants on a policy-protected grants table, so the SR8 (b) revocation invariant and C12 did not hold; empty-scope, cross-tenant and moved-scope fan-out defects made stale or foreign grants reachable without attacker effort.

Two threats keep their rating but had control claims corrected:

- **T10** (Inacceptable): C4 (`authorize?: true` defaults) and C14 (policy-coverage helper) were ineffective before PR #14; see the T10 section.
- **T16** (Undesirable): C19's "Tolerable when the CLI is in the runbook" rested on the rotation tool re-wrapping the right DEK, which it did not; see the T16 section.

Notes on T4 (recovery-path tag truncation), T12 (malformed-key DoS), T14 (ECIES KDF binding), T18 (`expires_at: nil`), T19 (renew ordering) and T25 (`ValidateConfig` gaps) record findings that did not change a rating. Open findings are listed in `09_inspection.md`.

### What changed since v0.2.0

Two earlier Inacceptable findings were retired by removing the affected code paths:

- **T1** (`:simple`-mode DBA → plaintext disclosure). Resolved structurally: the `:simple` storage mode is gone. `ash_envelope` no longer ships a code path that persists a DEK alongside its ciphertext. Single-recipient deployments use the `Asymmetric` KeyManager; Cloak-vault deployments use the upstream `KeyManagers.Cloak`.
- **T9** (Plug bypass). `AshEnvelope.Storage.Plug` is removed. The HTTP serving surface for encrypted blobs is now an integrator-owned route over `AshStorage.BlobIO.read/3`, or the upstream `ash_storage` proxy. Path-traversal, signed-URL handling, and disposition encoding are upstream concerns.
