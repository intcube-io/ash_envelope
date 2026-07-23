# Proposal — Converging `ash_envelope` onto `ash_storage` BlobIO

Status: implemented (v0.3.0). Tracks the [`blobio/06-proxy-actor-lifetime`
branch of `wln/ash_storage`](https://github.com/wln/ash_storage/tree/blobio/06-proxy-actor-lifetime)
(tip of the rebuilt `blobio/*` stack, successor to the original
`blob-io-stack` branch) until BlobIO lands on `ash_storage`'s `main`.

This proposal sketches how `ash_envelope` could stop shipping its own
storage-wrapping service and instead express its entire storage story
as **two `AshStorage.Encryption.KeyManager` implementations**
plus the standalone `AshEnvelope.Reconcile` extension. The result:

- `ash_storage` owns the byte path (BlobIO + Layers + serving).
- `ash_envelope` owns the *key/grant lifecycle* and *policy ↔ grants
  reconciliation*.
- The three current `AshEnvelope.Storage` modes (`:simple`,
  `:actor_wrapped`, `:key_grants`) become library-provided KeyManager
  modules — composable rather than hard-coded.
- The process-dictionary handoff that currently couples upload and
  `after_action` (see `lib/ash_envelope/storage/encrypted.ex:145`)
  disappears because BlobContext already carries actor, tenant,
  resource, attachment, and blob into both `wrap_dek/3` and
  `unwrap_dek/3`.

---

## Context

### What `ash_storage` BlobIO already provides

`AshStorage.BlobIO` centralizes service IO behind a single entrypoint
(`read/3`, `write/3`, `read_key/4`, `url/3`, `serving_strategy/3`,
`prepare_direct_upload/2`). Every call carries a `BlobContext`
(resource, attachment, record, blob, actor, tenant, operation) through
the pipeline.

Above the service, an **ordered, persisted layer chain** runs. Each
layer implements `AshStorage.BlobIO.Layer`:

```elixir
@callback layer_id(opts) :: String.t()
@callback write(Writer.Operation.t(), opts) :: {:ok, Writer.Operation.t()} | {:error, term()}
@callback read(Reader.Operation.t(), opts) :: {:ok, Reader.Operation.t()} | {:error, term()}
@callback serving(Serving.Operation.t(), opts) :: {:ok, Serving.Operation.t()} | {:error, term()}
@callback direct_upload(DirectUploads.Operation.t(), opts) :: {:ok, _} | {:error, term()}
```

Layer metadata is persisted on the blob under
`metadata["ash_storage"]["blob_io"]["layers"]` as a list of
`%{"layer_id", "version", "metadata"}` entries. Reads use the persisted
metadata to select and reverse the layer chain that wrote the bytes.

`AshStorage.Layer.Encryption` is one such layer: it
envelope-encrypts bytes with AES-256-GCM, persists IV/tag, and
delegates DEK wrapping to a configured `KeyManager`:

```elixir
@callback wrap_dek(dek :: binary(), Writer.Operation.t(), opts) ::
            {:ok, wrapped_dek :: map()} | {:error, term()}
@callback unwrap_dek(wrapped_dek :: map(), Reader.Operation.t(), opts) ::
            {:ok, dek :: binary()} | {:error, term()}
@callback rewrap_dek(wrapped_dek :: map(), RewrapOperation.t(), opts) ::
            {:ok, wrapped_dek :: map()} | {:error, term()} # optional
```

A `Cloak`-based KeyManager ships bundled. `BlobIO.Encryption.rewrap/3`
rotates the wrap on an existing blob without re-uploading bytes.

### What `ash_envelope` currently does

`AshEnvelope.Storage` is a Spark extension that wraps an attachment's
storage service with `AshEnvelope.Storage.Encrypted` (a delegating
`AshStorage.Service` implementation). The extension picks one of three
**modes** statically from which DSL keys the integrator set:

| Mode | Trigger | DEK custody |
|---|---|---|
| `:simple` | no key attributes set | DEK base64-encoded in `metadata["envelope_v1"]["wrapped_dek"]` |
| `:actor_wrapped` | `actor_public_key_attribute` set | DEK wrapped with the actor's X25519 public key |
| `:key_grants` | `key_grants_resource` set | DEK stored in a per-(subject, principal) grants table |

`AshEnvelope.KeyGrants` provides `create_for_actor`, `resolve_for_actor`,
`share`, `revoke` against any Ash resource that conforms to the
`Config` shape.

`AshEnvelope.Reconcile` is the distinctive piece: a Spark extension
with an `affects` DSL that walks the encrypted resource's read policy
via `Ash.can?(:read, subject, actor:)` and keeps `KeyGrants` in sync
when "affecting" resources (memberships, role attributes, etc.)
change. It supports `:sync` and `:async`-via-Oban modes.

---

## Friction in the current design

1. **Three modes encoded as a static dispatch** in
   `AshEnvelope.Storage.Info.mode/1`. Each new policy (KMS, HSM,
   tenant-scoped KEK, recipient wrapping by attachment) requires a
   fork or a fourth mode. The Elixir idiom for this shape is a
   behaviour, not an enum.

2. **Process-dictionary handoff in `:key_grants` mode.** The DEK is
   stashed via `Process.put({:ash_envelope_dek, key}, ...)` so a
   downstream `after_action` change can read it. The moduledoc itself
   warns: *"if the upload runs in a different Erlang process than the
   parent record's `after_action`, the key grant will not be created
   and the file will be undecryptable. Keep upload + create on the
   same process."* That's a load-bearing runtime constraint imposed
   by a missing data channel.

3. **No first-class rewrap.** Rotating a KEK, migrating from cloak to
   KMS, or rewrapping after a recipient-policy change requires
   re-uploading bytes — even though only the wrap needs to change.
   The security doc's "envelope integrity bound" section warns about
   the rotation gap but ships no helper.

4. **One mode per resource.** An app with a mix of confidentiality
   tiers (public attachments, single-actor confidential attachments,
   multi-recipient shared attachments on the same resource) can't
   express that today.

5. **Duplicate byte-path code.** `AshEnvelope.Storage.Encrypted`
   reimplements upload/download/delete/url/exists?/upload_many
   delegation. `ash_storage`'s Layer behaviour already owns that
   shape.

---

## Proposed architecture

Two `KeyManager` modules ship from `ash_envelope`, plus the existing
`Reconcile` extension stays where it is. `AshEnvelope.Storage` and
`AshEnvelope.Storage.Encrypted` are deprecated.

### Mode replacements

| Current mode | Replacement |
|---|---|
| `:simple` | `AshStorage.Layer.Encryption` with the bundled `KeyManagers.Cloak`, pointed at an `AshCloak`-protected vault module |
| `:actor_wrapped` | `AshEnvelope.BlobIO.KeyManagers.Asymmetric` (X25519 ECIES from `AshEnvelope.wrap_dek/2`) |
| `:key_grants` | `AshEnvelope.BlobIO.KeyManagers.KeyGrants` (fan-out into the existing `AshEnvelope.KeyGrants` resource) |

The `:simple` replacement is the important rhetorical move: today
`:simple` means "DEK plaintext-ish in metadata, gated only by a signed
URL or actor resolver in the plug". That mode exists because we did
not want to require the integrator to stand up a Cloak vault for the
no-multi-recipient case. With `ash_storage` BlobIO + `ash_cloak`, the
no-multi-recipient case is no longer a special mode — it is just the
bundled `KeyManagers.Cloak` pointed at an `AshCloak` vault. The DEK
is never in metadata in plaintext, the threat model collapses to
"protect the vault key", and the per-mode `Plug` guard
(`validate_simple_mode_guard!`) goes away.

### Wiring

```elixir
defmodule MyApp.Document do
  use Ash.Resource,
    extensions: [
      AshStorage,
      AshEnvelope.Reconcile  # only needed for multi-recipient + policy sync
    ]

  storage do
    service {AshStorage.Service.S3, bucket: "private-blobs"}

    layers [
      {AshStorage.Layer.Encryption,
       layer_id: "document-envelope",
       key_manager:
         {AshEnvelope.BlobIO.KeyManagers.KeyGrants,
          grants_resource: MyApp.DocumentKeyGrant,
          domain: MyApp.Storage},
       proxy_base_url: "/storage"}
    ]
  end

  reconcile do
    user_resource MyApp.User
    grant_requests_resource MyApp.DocumentGrantRequest
    granter_chain [:actor, :request]

    affects MyApp.Membership do
      actions [:create, :update, :destroy]
      principal :user_id
      scope fn cs -> [org_id: Ash.Changeset.get_attribute(cs, :org_id)] end
    end
  end
end
```

The Reconcile extension does not need to know about storage. It only
needs the KeyGrants resource and the read policy on the encrypted
resource. That decoupling already exists today — this proposal
preserves it.

### KeyManager sketches

#### `AshEnvelope.BlobIO.KeyManagers.Asymmetric`

```elixir
defmodule AshEnvelope.BlobIO.KeyManagers.Asymmetric do
  @behaviour AshStorage.Encryption.KeyManager

  @impl true
  def wrap_dek(dek, %{blob_context: bctx}, opts) do
    public_key_attr = Keyword.fetch!(opts, :actor_public_key_attribute)
    public_key = AshEnvelope.resolve_actor_key(bctx.actor, public_key_attr)

    {:ok,
     %{
       "format" => "x25519-ecies-v1",
       "ciphertext" => dek |> AshEnvelope.wrap_dek(public_key) |> Base.encode64()
     }}
  end

  @impl true
  def unwrap_dek(%{"ciphertext" => ct}, %{blob_context: bctx}, opts) do
    private_key_attr = Keyword.fetch!(opts, :actor_private_key_attribute)
    private_key = AshEnvelope.resolve_actor_key(bctx.actor, private_key_attr)

    with {:ok, blob} <- Base.decode64(ct) do
      AshEnvelope.unwrap_dek(blob, private_key)
    end
  end
end
```

No process dictionary, no after-action handoff. The actor that BlobIO
already carries is the input.

#### `AshEnvelope.BlobIO.KeyManagers.KeyGrants`

```elixir
defmodule AshEnvelope.BlobIO.KeyManagers.KeyGrants do
  @behaviour AshStorage.Encryption.KeyManager

  alias AshEnvelope.KeyGrants

  @impl true
  def wrap_dek(dek, %{blob_context: bctx} = write, opts) do
    config = config_from(opts)
    subject_id = subject_id(write)

    with :ok <- KeyGrants.create_for_actor(config, subject_id, dek, bctx.actor, opts[:domain]) do
      {:ok,
       %{
         "format" => "ash_envelope_key_grants_v1",
         "subject_id" => subject_id,
         "grants_resource" => to_string(config.resource)
       }}
    end
  end

  @impl true
  def unwrap_dek(%{"subject_id" => subject_id}, %{blob_context: bctx}, opts) do
    KeyGrants.resolve_for_actor(config_from(opts), subject_id, bctx.actor, opts[:domain])
  end

  @impl true
  def rewrap_dek(wrapped_dek, _operation, _opts) do
    # Rewrap is a no-op at the blob-metadata layer for this manager —
    # grants are rewrapped per-principal via AshEnvelope.Reconcile.Runner
    # against the up-to-date read policy.
    {:ok, wrapped_dek}
  end
end
```

Persisted blob metadata holds **only** the pointer to the grants
table; the actual wrapped DEK rows live in the grants resource where
Reconcile already manages them.

### Rewrap semantics for the asymmetric manager

`BlobIO.Encryption.rewrap/3` already calls the manager's optional
`rewrap_dek/3`. The asymmetric manager can implement that to rotate
between recipients without re-uploading bytes — exactly the use case
`AshEnvelope.KeyGrants.share/5` covers today, lifted into the
BlobIO pipeline.

### What stays in `ash_envelope`

- `AshEnvelope` itself (primitives: `encrypt/2`, `decrypt/2`,
  `generate_dek/0`, `generate_key_pair/0`, `wrap_dek/2`,
  `unwrap_dek/2`, `resolve_actor_key/2`, `hkdf_sha256/4`).
- `AshEnvelope.KeyGrants` (subject-agnostic).
- `AshEnvelope.GrantRequests` (subject-agnostic).
- `AshEnvelope.Reconcile` (read-policy ↔ grants sync, `affects` DSL,
  Oban async mode).
- The full SQUARE risk assessment under `documentation/security/`.
- New: `AshEnvelope.BlobIO.KeyManagers.Asymmetric`,
  `AshEnvelope.BlobIO.KeyManagers.KeyGrants`.

### What leaves `ash_envelope`

- `AshEnvelope.Storage` (Spark extension).
- `AshEnvelope.Storage.Encrypted` (wrapping service).
- `AshEnvelope.Storage.Plug` (replaced by an `ash_storage` proxy that
  reads through `BlobIO.read/3`).
- The `:simple` / `:actor_wrapped` / `:key_grants` mode discriminator
  in `Info.mode/1`.
- The process-dictionary DEK handoff.

---

## Trade-offs

**Wins**

- One byte path, one place layers compose, one place metadata is
  persisted.
- DEK travels in a typed `Writer.Operation` instead of the process
  dictionary; the cross-process bug becomes structurally impossible.
- KeyManager is a behaviour — KMS, HSM, tenant-scoped KEK, or
  per-attachment policies become third-party modules, not forks.
- Attachment-level layer configuration (already supported by
  `ash_storage`) gives per-attachment confidentiality tiers for free.
- Rewrap-without-rebytes is available everywhere encryption is.
- The `:simple` mode warning (and the matching plug guard) disappears
  — there is no longer a mode that stores plaintext-equivalent DEKs.

**Costs**

- A breaking change for current `AshEnvelope.Storage` users. A
  deprecation window with both extensions installable side-by-side is
  feasible because they configure different DSL sections.
- Hard dependency on `ash_storage`'s BlobIO stack being merged and
  released. While `blob-io-stack` is a branch, `ash_envelope`'s
  current `AshEnvelope.Storage` works against stock `AshStorage`. The
  proposed KeyManager modules can be gated by
  `Code.ensure_loaded?(AshStorage.Encryption.KeyManager)` so
  the package degrades gracefully.
- `AshEnvelope.Storage.Plug` has security properties (path-traversal
  guard, signed-URL verification, RFC 6266 + RFC 5987 disposition
  encoding, size cap) that the equivalent `ash_storage` proxy needs
  to preserve. Worth proposing those upstream as a hardened reference
  proxy bundled with `ash_storage`.

---

## Migration sketch

1. Land `AshEnvelope.BlobIO.KeyManagers.Asymmetric` and
   `.KeyGrants` behind `Code.ensure_loaded?` gates. Existing users
   unaffected.
2. Document both KeyManagers as the recommended setup once
   `ash_storage` BlobIO ships on `main`.
3. Mark `AshEnvelope.Storage` and `AshEnvelope.Storage.Encrypted` as
   `@deprecated` with pointers to the KeyManager equivalents.
4. Provide a `mix ash_envelope.migrate.to_blob_io` task that rewrites
   `encryption do … end` blocks into `storage do layers […] end`
   blocks for each of the three modes (mechanical translation).
5. Remove the deprecated modules in the next major.

Reconcile is unaffected throughout — it only ever needed the
`KeyGrants` table to exist, and the KeyManager that writes to that
table is now driven by BlobIO.

---

## Open questions

- **Direct uploads with `KeyGrants`.** The bundled encryption layer
  rejects direct uploads because the server must see bytes to
  encrypt. Same constraint applies here. The proposed
  application-owned staging workflow (upload to a temporary bucket,
  let a server worker write the canonical encrypted blob through
  BlobIO) likely belongs in `ash_storage` docs rather than here.
- **Subject id for the `KeyGrants` manager.** The grants table is
  keyed by `(subject_id, principal_id)`. For attachments the natural
  subject is the blob id, but Reconcile's existing `subject_id_for`
  callback lets the integrator point at the parent record. The
  KeyManager needs the same indirection — likely an `opts` key
  resolved against `BlobContext` rather than hard-coded to
  `bctx.blob.id`.
- **`:rewrap_dek` for the `KeyGrants` manager.** Today, blob-level
  rewrap is a no-op; the rewrap work belongs at the grants level via
  Reconcile. Worth thinking about whether `BlobIO.Encryption.rewrap`
  should fan out to a Reconcile run for this manager, or whether the
  app should call `AshEnvelope.Reconcile.Runner` explicitly.
- **Upstreaming the hardened proxy.** Whether `AshEnvelope.Storage.Plug`'s
  hardening (signed URLs, traversal guards, disposition encoding,
  size cap) lands in `ash_storage` or stays in `ash_envelope` as an
  optional plug-around-BlobIO is a coordination question with
  `wln/ash_storage`.
- **Threat-model docs.** The per-mode threat model in
  `documentation/topics/how-envelope-encryption-works.md` needs to be
  rewritten as "per-KeyManager threat model" — which secret is
  load-bearing under each manager, what each defends against. That
  doc move is in scope for this proposal.
