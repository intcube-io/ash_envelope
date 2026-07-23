# How Envelope Encryption Works

## The Problem

Encrypting data with a single key works, but creates challenges when multiple users need access to the same encrypted data, or when you need to revoke a single user's access without re-encrypting everything.

## Envelope Encryption

Envelope encryption solves this with two layers of keys:

1. **Data Encryption Key (DEK)** — a random symmetric key generated per
   record. Used to encrypt the actual data with AES-256-GCM.
2. **Per-user X25519 key pair** — the recipient's **public** key wraps
   the DEK; only the matching **private** key can unwrap it.

Each user who needs access gets their own wrapped copy of the DEK. To
read the data, a user unwraps the DEK with their private key, then
decrypts the data with the DEK.

```
┌─────────────────────────────────────────────────┐
│                  Encrypted Data                  │
│            (encrypted with DEK)                  │
└─────────────────────────────────────────────────┘
                        │
                    DEK (raw)
                        │
         ┌──────────────┼──────────────┐
         │              │              │
  ┌──────┴──────┐ ┌─────┴──────┐ ┌────┴───────┐
  │ Wrapped DEK │ │ Wrapped DEK│ │ Wrapped DEK│
  │ (User A)    │ │ (User B)   │ │ (User C)   │
  └──────┬──────┘ └─────┬──────┘ └────┬───────┘
         │              │              │
   priv key A     priv key B     priv key C
```

## Key Operations

### Sharing

Asymmetric wrapping makes sharing cheap: the granter only needs the
**target's public key**, never their secret. To share access, the
granting user:

1. Unwraps the DEK with their own X25519 private key
2. Re-wraps the DEK with the target user's X25519 public key
3. Stores the new wrapped DEK as a grant row

This is why an admin can hand someone access without ever holding
their decryption secret.

### Revoking

To revoke access, simply delete the target user's grant row. The DEK itself doesn't change, and all other users' wrapped copies remain valid.

## AshEnvelope Implementation

AshEnvelope implements envelope encryption with two distinct primitives:

- **`encrypt/2` / `decrypt/2`** — AES-256-GCM over arbitrary data with a
  32-byte key (the DEK). Each call uses a fresh random 12-byte IV, so
  identical plaintexts produce different ciphertexts even under the
  same key.
- **`wrap_dek/2` / `unwrap_dek/2`** — X25519 ECIES. `wrap_dek/2` takes
  the recipient's 32-byte public key and returns a raw binary blob
  (`ephemeral_public ‖ IV ‖ TAG ‖ ciphertext`). `unwrap_dek/2` takes
  the recipient's 32-byte private key and returns `{:ok, dek}`.
  Wrapping the same DEK twice produces different blobs (fresh ephemeral
  key each time).
- **`AshEnvelope.KeyGrants`** — manages the grant rows in an Ash
  resource table. Base64-encodes the wrapped blob for storage and
  exposes `create_for_actor/5`, `resolve_for_actor/4`, `share/5`, and
  `revoke/3`.

## Security Posture

The sections below summarise the security properties the library does
and does not guarantee. They derive from a full SQUARE risk assessment
in `documentation/security/risk-assessment/00_overview.md`, where each
finding is rated against BSI 200-2 damage potential and ISO/IEC 18045
attack potential. Read the rest of this section before deploying
`ash_envelope` in any setting where the encrypted data is regulated
(GDPR / equivalent) or otherwise high-value.

### Per-KeyManager threat model

For attachments, `AshEnvelope` ships two `AshStorage.Encryption.KeyManager`
implementations. Both compose with `AshStorage.Layer.Encryption`,
which owns the bytes (AES-256-GCM) and delegates DEK custody to the
configured manager:

| KeyManager | DEK custody | Defends against | Does NOT defend against |
|---|---|---|---|
| `AshEnvelope.BlobIO.KeyManagers.Asymmetric` | DEK wrapped with the actor's X25519 public key, persisted in blob layer metadata | DBA-class threats + storage-backend disclosure (under the private-key custody assumption below). Single recipient | Multiple recipients sharing one blob |
| `AshEnvelope.BlobIO.KeyManagers.KeyGrants` | DEK fanned out per-principal into the `AshEnvelope.KeyGrants` resource; blob metadata holds only a pointer at the grants table | DBA-class threats + storage-backend disclosure (under the private-key custody assumption below). Multi-recipient sharing and revocation, reconciliation against the read policy | — |

The bundled `AshStorage.Encryption.KeyManagers.Cloak` is also
available for single-tenant, no-multi-recipient deployments where a
Cloak vault holds the wrapping key. `ash_envelope` does not ship this
manager itself — it lives in `ash_storage`.

### Private-key custody (required for production)

`ash_envelope`'s confidentiality guarantee for both KeyManagers
rests on one load-bearing assumption: **the
principal's X25519 private key is protected at rest at least as well
as the encrypted plaintext**. Storing the private key in a plain
column on the same database that holds the encrypted records defeats
envelope encryption entirely — a database reader can unwrap the DEK
and decrypt.

Acceptable patterns:

- A KEK (Key Encryption Key) held by a KMS or HSM, used to encrypt
  each principal's private key before persistence. The KEK is then
  the load-bearing secret, not the database.
- Application-layer column encryption via `AshCloak` (or `cloak`),
  with the master key held outside the application database (env var,
  secrets manager, etc.).

The generator (`mix ash_envelope.gen.key_grants`) scaffolds the
`AshCloak`-encrypted form as the primary example, with the plain
`:binary` form labelled as test-only.

### Envelope integrity bound

`ash_envelope` uses AES-256-GCM and X25519 ECIES for confidentiality
and detects byte-level tampering of ciphertext or wraps via the AEAD
tag. It **does not** cryptographically prevent a different attack: an
adversary with write access to both the ciphertext store and the grant
rows can substitute the whole envelope (fresh ciphertext under a
fresh DEK, plus a wrap of that DEK to each principal's public key —
public keys are sufficient). The legitimate principals would then
decrypt and see attacker-chosen content under the original record's
identity.

This is an integrity/authenticity attack, not a confidentiality
breach — the attacker does not learn the original plaintext. Mitigation
must be layered on top of the library by the integrator: signed audit
logs, append-only / WORM storage, or per-record signatures over the
envelope under a key the DBA cannot forge with.

### Authorization defaults

`AshEnvelope.KeyGrants.Config` and `AshEnvelope.GrantRequests.Config`
default to `authorize?: true`. Direct calls from your application
code therefore go through Ash's policy authorizer, and the grants /
grant-requests resources MUST define policies. The generators
scaffold a baseline policy block — see the comments in the generator
output for the typical "self-read, integrator-customisable create,
self-destroy" pattern.

Reconciliation (`AshEnvelope.Reconcile.Runner`) bypasses policies for
its system-side revoke path via `authorize?: false`. The decision of
*whether* to revoke is made by the planner via
`Ash.can?({subject, :read}, principal)`, so the encrypted resource's
read policy is the single source of truth for authorization.

Use `AshEnvelope.TestHelpers.assert_policies_defined!/2` in your
integrator test suite to catch the common mistakes of declaring a
grants resource without policies AND of declaring policies that
don't cover every grant-mutating action type. The helper checks
`:read`, `:create`, and `:destroy` coverage by default; pass
`actions: [:read, :create, :update]` for a `GrantRequests` resource,
or `actions: []` to fall back to the legacy "any policy defined"
check.

### Backup-key escrow (opt-in)

Setting `:backup_public_key` in `config :ash_envelope, ...` makes both
KeyManagers embed an additional X25519 ECIES wrap of every DEK under
`wrapped_dek["backup"]` in encryption-layer metadata. This lets the
operator recover plaintext if every authorized principal loses their
private key. Recovery goes through `AshEnvelope.recover_dek/2` /
`AshEnvelope.recover_plaintext/3`; no configured KeyManager touches the
backup field.

The matching private key opens every blob ever written while the public
key was current. Custody must be at least as strong as plaintext
protection (EA9):

- Cold storage (offline media, sealed envelope, etc.) — preferred.
- KMS / HSM-protected unwrap — the unwrap operation is authenticated
  and audit-logged.
- Split-key custody (Shamir / threshold) — no single operator can
  recover unilaterally.

Storage in a database column or in an environment variable accessible
to ordinary application processes defeats the purpose. The library
cannot enforce this; the integrator's runbook must.

#### Rotating the backup key

Each blob's backup wrap is tagged with a short fingerprint of the
public key it was wrapped to (`key_id`), so the rotation tooling can
find stale blobs without unwrapping anything. The recommended sequence:

1. Configure both keys side by side. New writes wrap to the new key;
   old blobs still carry the old wrap.

       config :ash_envelope,
         backup_public_key: <NEW_PUBLIC_KEY>,
         backup_public_key_previous: <OLD_PUBLIC_KEY>

2. Deploy.

3. Pre-flight — count stale blobs without writing:

       mix ash_envelope.rotate_backup_key \
         --domain MyApp.Storage \
         --resources MyApp.Blob,MyApp.Photo.Blob \
         --check-only

4. Perform the rewrites (loads the previous private key from a file
   path, not argv, to keep it out of shell history):

       mix ash_envelope.rotate_backup_key \
         --domain MyApp.Storage \
         --resources MyApp.Blob,MyApp.Photo.Blob \
         --previous-private-key-path /secure/k1.priv

5. Re-run with `--check-only` and confirm zero stale blobs remain.
   The task **exits non-zero** if any blob in the named resources
   still carries the old `key_id` — that's the gate that lets you run
   it as a precondition before retiring the old key.

6. Remove `:backup_public_key_previous` from config. Retire the
   previous key's private half from cold storage.

The CLI streams blobs through `Ash.stream!` and writes via each blob's
`:update_metadata` action, so it works with any resource that uses
`AshStorage.BlobResource`.

#### Recovery procedure

Recovery is rare and deliberate — it requires bringing the backup
private key online. The shape of the call:

    {:ok, blob} = Ash.get(MyApp.Blob, blob_id, domain: MyApp.Storage)
    {:ok, ciphertext} = AshStorage.Service.S3.download(blob.key, ctx)
    {:ok, plaintext} = AshEnvelope.recover_plaintext(blob, ciphertext, backup_private_key)

`AshEnvelope.recover_dek/2` returns just the DEK if you only need to
inspect it. Both functions bypass every configured KeyManager and read
the backup wrap directly from blob metadata.

### Storage-service redundancy (Mirror)

`AshStorage.Service.Mirror` fans writes to N backends in declaration
order. The contract is **fail-fast on the primary, best-effort on
secondaries**: the first error from any child halts the write, but
bytes already written to earlier children are *not* rolled back.
After a partial failure, you'll have a blob row referencing a key
that exists on the primary and (some of) the secondaries but not all
of them. ash_storage logs a `Logger.warning/1` from the mirror when a
secondary returns non-matching extra attrs; ash_storage's roadmap
includes a dedicated orphan-cleanup task, but it isn't shipping yet.

Two security observations for ash_envelope integrators using Mirror:

1. **AEAD prevents tamper-without-detection on a divergent
   secondary.** If a write succeeded on the primary but failed on a
   secondary, then later a read fell through to that secondary (e.g.
   primary returned `:not_found` due to a separate outage), the
   secondary's bytes — whether absent, partial, or stale-from-an-
   earlier-write — fail `BlobIO.read/3`'s AEAD verification with
   `:decryption_failed`. The failure mode degrades to DoS, not
   plaintext-of-the-wrong-blob.

2. **Orphans are an availability concern, not a confidentiality
   one.** A leftover blob on a secondary after the row was destroyed
   in your DB is unreachable through the application path (no row to
   load) and AEAD-unreadable to a direct-storage attacker who doesn't
   hold the wrapping key. The risk is storage-cost drift and IAM
   surface, not data leak.

**Recommended integrator actions** until ash_storage ships orphan
cleanup:

- Monitor `Logger.warning/1` output from the Mirror service, route
  it to your incident-response channel. The current log emission is
  per-write; structured telemetry is on ash_storage's roadmap.
- If you cannot tolerate orphan drift, run a periodic reconciliation
  cron that lists keys on each backend (S3 `ListObjects`, disk
  traversal, etc.) and compares against `your_blob_resource`'s
  `:key` column. Anything in storage with no matching row is an
  orphan candidate; anything in your DB but missing from some
  backend is an inconsistency that may need a re-write.
- Right-size your IAM grants per-backend so a leaked secondary
  credential doesn't authorize unlimited orphan creation.

This is T23 in the risk assessment. It is rated Tolerable because
AEAD bounds the integrity exposure and the residual is availability
+ storage cost; SR33 locks the documentation commitment above.

### Serving encrypted blobs over HTTP

The encryption layer forces a `proxy_url` strategy for encrypted
blobs (`AshStorage.Layer.Encryption.serving/2` rejects direct
`service_url` serving). HTTP reads therefore traverse an application-
controlled proxy route, which has two non-negotiable responsibilities:

1. Authenticate the request against the **outer-auth pipeline** (your
   existing `require_authenticated_user` / Guardian / Pow plug),
   *before* the proxy runs. The signed bearer in the URL is not
   authentication — it certifies the URL was minted by an authorized
   server, not that the bearer is the authorized recipient.
2. Thread the resolved principal into `BlobIO.read/3` so the
   `KeyGrants` manager has a real actor to authorize against. Without
   this, `bctx.actor` is `nil` and the unwrap path either fails or
   (depending on the manager) silently degrades.

`AshStorage.Plug.Proxy` covers both, given the right configuration:

```elixir
# router
scope "/storage", MyAppWeb do
  pipe_through [:browser, :require_authenticated_user]  # ⚠ outer auth
  forward "/", AshStorage.Plug.Proxy,
    resource: MyApp.Document,
    attachment: :file,
    access: {:signed, secret: Application.compile_env(:my_app, :proxy_signing_secret)},
    actor_assign: :current_user,
    max_lifetime_seconds: 300
end
```

The two load-bearing options:

- **`:actor_assign`** — atom (`conn.assigns[atom]` lookup) or
  `fn conn -> actor end`. The proxy puts the resolved actor on
  `BlobContext.actor` for both the blob-aware (`BlobIO.read/3`) and
  key-only (`BlobIO.read_key/4`) paths. `KeyGrants` reads it via
  `bctx.actor` and runs `KeyGrants.resolve_for_actor/4` against the
  configured grants resource.
- **`:max_lifetime_seconds`** — a positive integer cap on the
  bearer's *remaining* lifetime (`expires - now`). Refuses tokens
  presented with more remaining lifetime than the cap, regardless of
  the `expires_in` the URL builder used. A 300-second cap is a
  reasonable default: long enough that a slow client can complete a
  download, short enough that a leaked bearer is unusable a few
  minutes later.

Match the encryption layer's signed-URL config to the proxy:

```elixir
layers [
  {AshStorage.Layer.Encryption,
   layer_id: "…",
   key_manager: {AshEnvelope.BlobIO.KeyManagers.KeyGrants, …},
   proxy_base_url: "/storage",
   access:
     {:signed,
      secret: Application.compile_env(:my_app, :proxy_signing_secret)},
   expires_in: 300}
]
```

`:expires_in` and `:max_lifetime_seconds` should normally match — the
layer never mints a URL the proxy would refuse.

**Rotation cadence.** Rotate the signing secret at least annually,
and immediately on any suspected leak. Two-phase change:

1. Deploy with the new secret in `config :my_app, :proxy_signing_secret`.
   New URLs are minted with the new secret; outstanding URLs minted
   against the old secret fail the proxy's verification.
2. After the longest possible URL TTL has elapsed (≤
   `:max_lifetime_seconds`), retire the old secret. No URL re-signing
   is needed — outstanding tokens simply expire.

This is T9 in the risk assessment. With the configuration above it is
Undesirable (down from Inacceptable downstream of EA3); without
`:actor_assign` or with an outer-auth gap it returns to Inacceptable.
SR31 / SR32 lock the documentation commitments; C28 locks the
encryption layer forcing the proxy strategy; C29 names the upstream
contract this section relies on.

### Grant-relationship metadata

The `key_grants` and `grant_requests` tables expose, to any reader of
those tables, which principal has access to (or has requested access
to) which subject. The library does not provide cryptographic
concealment of this relationship — encrypted-index designs that hide
it are out of scope for v1. Integrators whose threat model treats
"who has access to X" as itself sensitive must layer access controls
on the rows of those tables.

### Cryptographic primitives and horizon

| Primitive | Used for | BSI TR-02102 horizon |
|---|---|---|
| AES-256-GCM (12-byte IV, 16-byte tag) | Data encryption; DEK wrapping under derived key | Recommended through 2030 |
| X25519 (Curve25519 ECDH) | Asymmetric DEK wrapping (ECIES) | Recommended through 2030 |
| HKDF-SHA256 (single block, ≤ 32 bytes) | Derive AES key from ECDH shared secret | Recommended through 2030 |
| SHA-256 (HMAC, HKDF) | Underlying hash | Recommended through 2030 |

Quantum-capable adversaries are outside the current threat model.
X25519 is broken by Shor's algorithm against a cryptanalytically
relevant quantum computer; the project's review cadence (annual,
recorded in `CHANGELOG.md`) tracks the BSI horizon and equivalent
guidance and will rotate primitives before the horizon shifts.

### Recommended integrator tests

```elixir
defmodule MyApp.SecurityPostureTest do
  use ExUnit.Case, async: true

  test "key-grant resources enforce policies" do
    # Defaults to checking :read, :create, :destroy coverage —
    # matches the actions a KeyGrants resource defines.
    AshEnvelope.TestHelpers.assert_policies_defined!(MyApp.KeyGrant)

    # GrantRequests has :update (for fulfill), not :destroy.
    AshEnvelope.TestHelpers.assert_policies_defined!(MyApp.GrantRequest,
      actions: [:read, :create, :update]
    )
  end
end
```

This catches three classes of mistake: declaring a grants resource
without an authorizer, declaring an empty `policies do … end`, and —
the most common — declaring policies that cover some but not all of
the action types the resource exposes (e.g. uncommenting the `:read`
and `:destroy` policies from the generator scaffold but leaving the
`:create` sharing-model branches commented out). Combined with
`authorize?: true` on the default Config the missing coverage
produces fail-closed runtime errors, not a silent authorization
bypass — but the test catches it before deploy.

For deeper coverage in your application's tests, exercise the
`AshEnvelope.KeyGrants` and `AshEnvelope.GrantRequests` public APIs
under actors with and without policy clearance, and assert your
policies behave as intended.
