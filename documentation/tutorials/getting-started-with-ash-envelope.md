# Getting Started with AshEnvelope

## Installation

`ash_envelope` is not on Hex yet — it depends on an unreleased branch of
`ash_storage`, and Hex does not allow publishing packages with git
dependencies. Until `ash_storage` ships on Hex, install `ash_envelope`
as a git dependency in `mix.exs`:

```elixir
{:ash_envelope, git: "https://github.com/intcube-io/ash_envelope.git"}
```

This pulls in `ash_storage` as a transitive git dependency (pinned to
the BlobIO branch `ash_envelope` tracks), so your app will also carry
that git dependency. A regular Hex install (`{:ash_envelope, "~> ..."}`)
will become available once `ash_storage` is released on Hex.

## What this library is for

`ash_envelope` owns the **DEK lifecycle**: generating per-record data
encryption keys, wrapping them under one or more recipients' X25519
public keys, and managing multi-recipient grants. The byte-level AEAD
over **blob** ciphertext is owned by `AshStorage.Layer.Encryption`,
which ash_envelope plugs into via its `AshEnvelope.BlobIO.KeyManagers.*`
modules. For **regular fields** (a column in your Ash resource that
isn't a blob), ash_envelope ships `encrypt/3` and `decrypt/3` — the
symmetric step of the multi-recipient grant pattern.

For **single-key field encryption** with one app-wide vault key (no
per-record DEK, no multi-recipient grants), use
[`ash_cloak`](https://hexdocs.pm/ash_cloak) — it provides Ecto types,
a vault abstraction, and key rotation. ash_envelope and ash_cloak
cover different use cases.

## Field encryption with multi-recipient grants

Encrypt a field once with a fresh per-record DEK; wrap that DEK into
one grant row per recipient. Adding / revoking recipients =
grant-row management; the ciphertext never moves.

```elixir
# One config struct for the grants table (see "Multi-Recipient Key
# Grants" below for generating the resource this points at).
defp key_grants_config do
  %AshEnvelope.KeyGrants.Config{
    resource: MyApp.MessageKeyGrant,
    subject_id_attribute: :message_id,
    actor_public_key_attribute: :encryption_public_key,
    actor_private_key_attribute: :encryption_private_key
  }
end

# At write time
def create_message(attrs, sender, recipients) do
  config = key_grants_config()
  message_id = Ash.UUID.generate()
  dek = AshEnvelope.generate_dek()

  # Pass record id as :context to bind ciphertext to the row.
  # A DBA who swaps body_ciphertext between rows triggers
  # :decryption_failed instead of disclosing one row's body under
  # another row's identity.
  ciphertext = AshEnvelope.encrypt(attrs.body, dek, context: to_string(message_id))

  {:ok, message} =
    MyApp.Messages.create_message(%{id: message_id, body_ciphertext: ciphertext})

  for recipient <- [sender | recipients] do
    AshEnvelope.KeyGrants.create_for_actor(config, message.id, dek, recipient, MyApp.Domain)
  end
end

# At read time
def read_message(message, actor) do
  config = key_grants_config()

  {:ok, dek} =
    AshEnvelope.KeyGrants.resolve_for_actor(config, message.id, actor, MyApp.Domain)

  {:ok, body} =
    AshEnvelope.decrypt(message.body_ciphertext, dek, context: to_string(message.id))

  %{message | body: body}
end
```

`:context` is optional — ciphertexts written without it can still be
decrypted with no context. Pass a stable per-row identifier when you
write, and the same identifier on read.

## Envelope Encryption with DEK Wrapping

For envelope encryption, each record gets its own Data Encryption Key
(DEK). The DEK is wrapped with the recipient's X25519 **public** key, so
only the holder of the matching **private** key can unwrap it. Sharing
with another user only requires their public key — the granter never
needs the recipient's secret.

```elixir
# X25519 key pair — public is shareable, private must stay secret
{public_key, private_key} = AshEnvelope.generate_key_pair()

# Per-record data key
dek = AshEnvelope.generate_dek()

# Wrap the DEK for storage (anyone with the public key can do this)
wrapped = AshEnvelope.wrap_dek(dek, public_key)

# Later, the holder of the private key unwraps it
{:ok, ^dek} = AshEnvelope.unwrap_dek(wrapped, private_key)
```

`wrap_dek/2` returns a binary blob; `KeyGrants` base64-encodes it
before persisting.

## Multi-Recipient Key Grants

When multiple users need access to the same encrypted resource, use Key
Grants. Each user gets their own wrapped copy of the DEK, wrapped to
their X25519 public key.

### 1. Generate the scaffolding

```bash
mix ash_envelope.gen.key_grants MyApp.Document \
  --grants-resource MyApp.FileKeyGrant \
  --domain MyApp.Catalog \
  --user-resource MyApp.User
```

This prints step-by-step instructions for setting up the grants resource, migration, and integration points.

The scaffolded grants table is keyed by the attachment's **blob row**
(`blob_id`), because that is the id the `KeyGrants` BlobIO manager sees
on every read path. For grants over your own records (the field
encryption pattern above), pass `--file-id-attribute` and point the
migration's `references(...)` at your record table instead.

### 2. Use Key Grants in your code

```elixir
# Build a config struct (subject = the attachment's blob row)
config = %AshEnvelope.KeyGrants.Config{
  resource: MyApp.FileKeyGrant,
  subject_id_attribute: :blob_id,
  actor_public_key_attribute: :encryption_public_key,
  actor_private_key_attribute: :encryption_private_key
}

blob_id = document.file.blob_id

# Create a grant when a record is created (wraps DEK with actor's public key)
AshEnvelope.KeyGrants.create_for_actor(config, blob_id, raw_dek, actor, MyApp.Catalog)

# Resolve the DEK for an actor (unwraps with the actor's private key)
{:ok, raw_dek} = AshEnvelope.KeyGrants.resolve_for_actor(config, blob_id, actor, MyApp.Catalog)

# Share access with another user (only needs the target's public key)
AshEnvelope.KeyGrants.share(config, blob_id, actor, target_user, MyApp.Catalog)

# Revoke access
AshEnvelope.KeyGrants.revoke(grant_record, MyApp.Catalog)
```

## Encrypted file attachments (`AshStorage` integration)

`AshEnvelope` integrates with file attachments through
`AshStorage.BlobIO`. The `AshStorage.Layer.Encryption` layer owns
the AES-256-GCM byte path; `AshEnvelope` ships two key managers that
plug into that layer:

- `AshEnvelope.BlobIO.KeyManagers.Asymmetric` — DEK wrapped with the
  actor's X25519 public key. Single-recipient blobs.
- `AshEnvelope.BlobIO.KeyManagers.KeyGrants` — DEK fanned out per
  principal into the `AshEnvelope.KeyGrants` resource. Multi-recipient
  blobs; works with `AshEnvelope.Reconcile`.

Single-recipient example:

```elixir
defmodule MyApp.Document do
  use Ash.Resource,
    domain: MyApp.Catalog,
    extensions: [AshStorage]

  storage do
    service {AshStorage.Service.S3, bucket: "private-blobs"}
    blob_resource MyApp.DocumentBlob
    attachment_resource MyApp.DocumentAttachment

    layer {AshStorage.Layer.Encryption,
           key_manager:
             {AshEnvelope.BlobIO.KeyManagers.Asymmetric,
              actor_public_key_attribute: :public_key,
              actor_private_key_attribute: :private_key},
           proxy_base_url: "/storage"},
          metadata_key: "documents"

    has_one_attached :file
  end
end
```

`storage do` takes one `layer` entity per layer (there is no `layers [...]`
list). `metadata_key` is the stable identifier persisted in blob metadata:
choose it once and never rename it, or existing blobs become unreadable.
`blob_resource` and `attachment_resource` point at your `AshStorage.BlobResource`
and `AshStorage.AttachmentResource` modules.

For multi-recipient blobs, generate the grants scaffolding with
`mix ash_envelope.gen.key_grants` and use the `KeyGrants` key manager;
pair it with the `AshEnvelope.Reconcile` extension to keep grants in
sync with the resource's `:read` policy.

## Backup-key escrow (optional)

Setting `:backup_public_key` in `config :ash_envelope, ...` makes both
KeyManagers embed an additional X25519 ECIES wrap of every DEK under
the encryption layer's metadata, so plaintext is recoverable even if
every authorized principal loses their private key.

    config :ash_envelope,
      backup_public_key: System.fetch_env!("ASH_ENVELOPE_BACKUP_PUBLIC_KEY")

Recovery goes through `AshEnvelope.recover_dek/2` or
`AshEnvelope.recover_plaintext/3` — never through a configured
KeyManager. The matching private key opens every blob ever written and
must be held outside the application database (cold storage / KMS /
split-key).

Rotate with `mix ash_envelope.rotate_backup_key`, which exits non-zero
if any blob still carries the old wrap after the pass. See the
[Security Posture](../topics/how-envelope-encryption-works.md#backup-key-escrow-opt-in)
section for the custody requirements and the recommended rotation
sequence.

## Reconciliation

For most apps, sharing and revoking shouldn't be a thing the host has
to call manually — the encrypted resource's `:read` policy already
defines who should and shouldn't have access. `AshEnvelope.Reconcile`
keeps the grants table in sync with the policy automatically.

When the actor of an authorization-changing action can't issue the
grant themselves (no key, no existing grant on the subject), a pending
**grant request** is queued and fulfilled later by any user who can.

See [Reconciliation](../topics/reconciliation.md) for the full setup.
