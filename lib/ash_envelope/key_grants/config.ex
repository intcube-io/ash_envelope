defmodule AshEnvelope.KeyGrants.Config do
  @moduledoc """
  Configuration for a key grants table.

  Describes how to read and write rows in an Ash resource that stores
  per-principal wrapped DEKs.

  ## Fields

  - `:resource` — the Ash resource module for the grants table
  - `:subject_id_attribute` — name of the FK attribute pointing at the encrypted
    subject (a file row id, a record id, etc.)
  - `:actor_public_key_attribute` — name of the attribute on the actor struct
    holding their X25519 public key (for wrapping DEKs)
  - `:actor_private_key_attribute` — name of the attribute on the actor struct
    holding their X25519 private key (for unwrapping DEKs)
  - `:principal_id_attribute` — name of the FK attribute pointing at the
    user/principal. Defaults to `:user_id`.
  - `:dek_attribute` — name of the attribute storing the wrapped DEK blob.
    Defaults to `:wrapped_dek`.
  - `:authorize?` — whether Ash policy authorization is applied to grant
    operations. Defaults to `true`. Set to `false` only on trusted
    system-side paths (e.g. reconciliation, integration tests without
    policies). When `true`, the grants resource must define Ash policies;
    `mix ash_envelope.gen.key_grants` scaffolds a baseline set.

  ## Optional expiring-grant attributes

  When the grants resource includes an `expires_at` attribute (or any
  name passed via `:expires_at_attribute`), the table can store:

  - **Time-bounded user grants**: `principal_id` set, `dek_attribute`
    holds an X25519-wrapped DEK as usual, `expires_at` set. The user
    can resolve until the deadline; past it,
    `KeyGrants.resolve_for_actor/4` returns `:not_found`.
  - **Ephemeral worker grants**: `principal_id` is `NULL`,
    `dek_attribute` holds the DEK sealed under
    `AshEnvelope.SealKey` with AAD = subject id, `expires_at` set.
    The deferred analyzer pathway resolves via
    `KeyGrants.resolve_ephemeral/3` — no user actor needed.

  Both share the same `expires_at` purge query. The
  `principal_id IS NULL` discriminator distinguishes the two row
  kinds; no extra column or CHECK constraint is required.

  - `:expires_at_attribute` — name of a nullable `utc_datetime_usec`
    attribute. When set on a row, `resolve_for_actor/4` and
    `resolve_ephemeral/3` reject rows past the deadline. `nil` value
    means the grant is permanent. Defaults to `nil` (feature
    disabled).
  - `:ephemeral_ttl_seconds` — TTL applied when minting an ephemeral
    worker grant via `create_ephemeral/5`. Defaults to `86_400` (24h).
    Choose larger than `max_attempts × max_backoff` of the analyzer
    trigger.

  Setting `:expires_at_attribute` enables both features. The ephemeral
  helpers also require `AshEnvelope.SealKey` to be configured (see its
  moduledoc).
  """

  @enforce_keys [
    :resource,
    :actor_public_key_attribute,
    :actor_private_key_attribute
  ]
  defstruct [
    :resource,
    :actor_public_key_attribute,
    :actor_private_key_attribute,
    subject_id_attribute: :blob_id,
    principal_id_attribute: :user_id,
    dek_attribute: :wrapped_dek,
    authorize?: true,
    expires_at_attribute: nil,
    ephemeral_ttl_seconds: 86_400
  ]

  @type t :: %__MODULE__{
          resource: module(),
          subject_id_attribute: atom(),
          actor_public_key_attribute: atom(),
          actor_private_key_attribute: atom(),
          principal_id_attribute: atom(),
          dek_attribute: atom(),
          authorize?: boolean(),
          expires_at_attribute: atom() | nil,
          ephemeral_ttl_seconds: pos_integer()
        }

  @doc """
  Build a `Config` from a keyword/map of options, dropping `nil` values so
  the struct's defaults take effect for unset optional fields.

  Required: `:resource`, `:actor_public_key_attribute`, `:actor_private_key_attribute`.
  Optional (defaulted): `:subject_id_attribute` (`:blob_id`),
  `:principal_id_attribute` (`:user_id`), `:dek_attribute` (`:wrapped_dek`),
  `:authorize?` (`true`), `:ephemeral_ttl_seconds` (`86_400`).

  `:expires_at_attribute` defaults to `nil` (feature disabled). Set it
  to enable expiring grants and ephemeral worker grants.
  """
  @spec from_options(Enumerable.t()) :: t()
  def from_options(options) do
    options
    |> Enum.reject(fn {_, v} -> is_nil(v) end)
    |> then(&struct!(__MODULE__, &1))
  end

  @doc """
  True iff the expiring-grants attributes are configured. Currently
  this is equivalent to having `:expires_at_attribute` set, since
  ephemeral worker grants share the same purge column.
  """
  @spec ephemeral_configured?(t()) :: boolean()
  def ephemeral_configured?(%__MODULE__{expires_at_attribute: nil}), do: false
  def ephemeral_configured?(%__MODULE__{}), do: true
end
