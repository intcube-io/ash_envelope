# Step 2: Security Goals

## Business goal

> Provide Ash applications with a correct, ergonomic envelope-encryption primitive and multi-recipient key-grant mechanism, so integrators can protect sensitive fields at rest and selectively share or revoke per-user access without re-encrypting data.

## Assets

| ID | Asset | Description | Owner / Stakeholder |
|---|---|---|---|
| A1 | **Plaintext field values** | The integrator's sensitive data on either side of the library's crypto boundary (PII, secrets, business data). | Data subject / Integrator |
| A2 | **DEKs (raw, unwrapped)** | Per-record 32-byte AES-256-GCM keys held only in memory during encrypt/decrypt/wrap/unwrap operations. | AshEnvelope (transient) |
| A3 | **Principal private keys (X25519)** | Per-principal unwrapping keys. Custody is integrator-defined (pluggable). | Principal; custody = Integrator |
| A4 | **Wrapped DEK blobs (key-grant rows)** | Persisted `(principal, record) → wrap(DEK)` rows in the integrator's database. | Integrator DB |
| A5 | **Encrypted ciphertext** | The at-rest output of `encrypt/2`, including IV and GCM tag. | Integrator DB |
| A6 | **Grant-relationship metadata** | The fact that principal X has a grant for record Y (independent of the wrapped blob's contents). | Integrator DB |
| A7 | **Grant-request records** | Pending/approved requests in the `AshEnvelope.GrantRequests` workflow. | Integrator DB |
| A8 | **Library reputation / trustworthiness** | Soundness of crypto choices, defaults, and incident response history. | Maintainer |
| A9 | **Ephemeral worker grant row** | A row in the grants table with `principal_id IS NULL` whose `dek_attribute` carries the DEK sealed directly under A10 (AES-GCM, AAD = subject id), plus `expires_at`. Lives only for the configured TTL. Present only when expiring-grants are configured on the `KeyGrants.Config`. | Integrator DB |
| A10 | **Env seal key** | Operator-managed 32-byte AES-256 key wired via `Application.get_env(:ash_envelope, :seal_key)` (typically backed by env var or secrets store). Resides in app-process memory after boot. Used only to seal/unseal A9's DEK column. Present only when expiring-grants are configured. | Integrator / operator |
| A11 | **Storage-service credentials** | Credentials the integrator's BEAM node uses to authenticate to the storage adapter: AWS access key + secret (S3 / S3-compatible), Azure SAS keys (Azure Blob), HMAC signing secret (disk service signed URLs). Persisted in operator-managed config or fetched at boot from IAM / secrets store. Resides in app-process memory after boot. | Integrator / operator |

## Security properties of assets

C = Confidentiality · I = Integrity · Av = Availability · Au = Authenticity · NR = Non-repudiation · P = Privacy.

| Asset | C | I | Av | Au | NR | P | Notes |
|---|---|---|---|---|---|---|---|
| A1 Plaintext | H | H | M | H | — | H | The crown jewel. AEAD must cover both C and I+Au. |
| A2 DEK | H | H | — | — | — | — | Leak of a single DEK exposes one record. Must never be persisted or logged. |
| A3 Principal priv key | H | H | — | — | — | — | Leak exposes all that principal's grants. Library treats them as opaque parameters; custody is integrator's problem. |
| A4 Wrapped DEK row | L | H | M | H | — | L | Wrap is opaque, so C low; tampering must be detected (ECIES tag); deletion must be the effective revocation. |
| A5 Ciphertext blob | L | H | M | H | — | — | C is already provided by A1 protections; GCM tag covers I+Au. |
| A6 Grant metadata | M | M | L | — | — | M | "Who has access" is itself sensitive; library cannot fully hide it, but should not amplify the leak. |
| A7 Grant requests | M | M | L | — | — | M | Pending requests reveal intent (who wants access to what). |
| A8 Reputation | — | H | — | — | — | — | Reputational integrity. |
| A9 Ephemeral grant row | H | H | M | — | — | L | Confidentiality inherits A1 per row; bounded by TTL × write rate. Av impact is worker-pathway only (user reads via grants unaffected). |
| A10 Env seal key | H | M | — | — | — | — | Compromise unlocks every live A9 row's DEK. Lives in app-process memory by design — stronger protection-needs than A4 but weaker than the backup private key (cold-storage). |
| A11 Storage-service credentials | H | — | M | — | — | — | Compromise yields full read on the storage backend (i.e. all ciphertext blobs), and write on whatever the credentials authorize. Read alone does not break A1 confidentiality (ciphertext still AEAD-protected); write enables T4 / T23. |

## Security goals

| ID | Security goal | Assets | Properties |
|---|---|---|---|
| **SG1** | Maintain confidentiality of plaintext field values against an attacker with read access to the integrator's database (no DEK, no principal private key in their possession). | A1 (via A2, A5) | C |
| **SG2** | Detect any tampering of encrypted ciphertext and wrapped-DEK blobs; AEAD verification must fail closed. | A1, A4, A5 | I, Au |
| **SG3** | Treat DEKs and principal private keys as transient, never-persisted, never-logged values within the library's own boundaries. | A2, A3 | C |
| **SG4** | Enforce authorization soundness: only principals with a valid, current grant for a record can derive that record's DEK; deletion of a grant row is the effective revocation. | A1, A4, A6 | C, I |
| **SG5** | Guarantee grant correctness: reconciliation never wraps a DEK under principal A and persists it as a grant for principal B; never assigns one record's DEK to another record's grant row. | A4, A6 | I, Au |
| **SG6** | Provide safe defaults across the public API and Ash DSL: fresh random IVs, AEAD, X25519 ECIES, no insecure mode reachable without deliberate, explicit opt-in. | A1, A2, A8 | I, C |
| **SG7** | Bound blast radius: compromise of one principal's private key exposes only that principal's grants, not other principals' grants nor the underlying records' integrity for other principals. | A1, A3, A4 | C |
| **SG8** | Preserve availability of legitimate access: reconciliation, share, and revoke operations do not strand legitimate principals or corrupt other principals' grants. | A1, A6 | Av |
| **SG9** | Sustain library reputation through alignment with current cryptographic best practice (BSI TR-02102 horizon 2030) and a documented response to soundness issues. | A8 | I |

## Stakeholders

| Role | Interest |
|---|---|
| Maintainer (Marc Nickert) | Library quality, reputation, response to issues. |
| Integrator | Host-application developer; trusted; configures DSL and provides KEK / private-key custody. |
| End user / data subject | Owner of the plaintext. |
| Principal / actor | Holds an X25519 key pair; receives grants. |
| Auditor / regulator (downstream) | Relies on the library's claims to assess integrator compliance (GDPR, sectoral regulation). |
| DB / storage operator | Adversary class in this framing, not a stakeholder. |

## Threat actor classes (in scope)

1. **Network attacker** between integrator services and storage.
2. **Honest-but-curious DBA / storage operator** with read (or read/write) access to encrypted tables.
3. **Malicious external user** of the integrating application, without a legitimate grant.
4. **Compromised principal** — one principal's private key leaks (blast radius bounded to their grants).

## Threat actor classes (out of scope)

- Malicious integrator / supply-chain attacker on the library itself (host code execution defeats any library-level defence).
- Side-channel attackers on the BEAM host (timing, memory dump). Captured as Environmental Assumption.
- Quantum-capable adversaries (anchored to BSI TR-02102 horizon 2030).

> **Note.** Security goals are *not* requirements. They state what must be true; requirements (step 6) state what the library must do to make it true.
