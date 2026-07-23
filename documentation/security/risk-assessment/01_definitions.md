# Step 1: Definitions

Shared vocabulary used throughout this assessment of `ash_envelope` (library-as-component framing).

## General terms

| Term | Definition |
|---|---|
| **Asset** | Something that needs protection regarding security (data, function, reputation). |
| **Threat** | Potential source of a violation of a security property. |
| **Vulnerability** | System property that enables a successful attack. |
| **Risk** | Effect of uncertainty on objectives, expressed as a combination of consequence (damage) and likelihood (here: required attack potential). |
| **Damage potential / Protection need** | Qualitative rating (Normal / High / Very High) of the consequences of a successful attack, per BSI 200-2. |
| **Required attack potential** | Qualitative rating (No rating / Low / Moderate / High) of the minimum effort an attacker needs, per ISO/IEC 18045. |
| **Security property** | An attribute of an asset that must be preserved (commonly: confidentiality, integrity, availability; also: authenticity, non-repudiation, privacy). |
| **Security goal** | A high-level statement that a security property must be preserved against a class of threats. |
| **Security requirement** | A concrete, verifiable statement of *what* the system must do (not *how*). |
| **Environmental assumption** | A security need satisfied by the operating environment (here: the integrating application), not the library itself. |
| **Control / Safeguard** | A measure that reduces risk by lowering damage, raising required attack potential, or both. |
| **Stakeholder** | Person or role with an interest in the system's security (user, operator, owner, regulator, …). |

## AshEnvelope-specific terms

| Term | Definition |
|---|---|
| **DEK** (Data Encryption Key) | A random 32-byte symmetric key generated per record. Used with AES-256-GCM to encrypt the record's plaintext. |
| **KEK / Wrapping key pair** | A per-principal X25519 key pair. The public key wraps DEKs (ECIES); the matching private key unwraps them. |
| **Key grant** | A persisted row holding a DEK that has been wrapped for a specific principal. Deleting the row revokes that principal's access to the underlying record. |
| **Principal / Actor** | The Ash subject (typically a user or service identity) that owns a wrapping key pair and can hold key grants. |
| **Reconciliation** | The library-internal process that creates, updates, or removes key grants when affecting resources (principals, subjects, encrypted records) change. |
| **Integrator** | A downstream Elixir application that depends on `ash_envelope` and configures it via Ash DSL. The integrator is **trusted**: they own host code execution. |
| **Wrapped DEK blob** | The output of `wrap_dek/2`: `ephemeral_public ‖ IV ‖ TAG ‖ ciphertext`. Stored Base64-encoded in grant rows. |
| **Encrypted ciphertext** | The output of `encrypt/2`: a binary containing IV, ciphertext, and the GCM authentication tag. |
