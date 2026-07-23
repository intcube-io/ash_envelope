defmodule AshEnvelope.Reconcile.Context do
  @moduledoc """
  Per-call context for `AshEnvelope.Reconcile.Runner.run/2`.

  Most fields are derived from the encrypted resource's DSL by the
  transformer; the `actor` and `changeset` come from the triggering
  action.

  ## Fields

  - `:encrypted_resource` — the resource declaring the `reconcile` block.
  - `:user_resource` — derived from the configured `KeyGrants.Config`'s
    `principal_id_attribute`'s belongs_to (typically passed in by the
    transformer or the caller).
  - `:key_grants_config` — `%AshEnvelope.KeyGrants.Config{}`.
  - `:grant_requests_config` — `%AshEnvelope.GrantRequests.Config{} | nil`.
  - `:granter_chain` — list of granter strategies to try in order.
  - `:domain` — Ash domain for both grants and requests.
  - `:actor` — actor of the triggering action.
  - `:changeset` — the triggering changeset (used by `only_when` and
    scope predicates).
  - `:user_load` — optional list of loads to apply when fetching users
    (e.g. `[:encryption_private_key]` so the cloak calc resolves).
  """

  @enforce_keys [
    :encrypted_resource,
    :user_resource,
    :key_grants_config,
    :granter_chain,
    :domain
  ]

  defstruct [
    :encrypted_resource,
    :user_resource,
    :key_grants_config,
    :granter_chain,
    :domain,
    :grant_requests_config,
    :actor,
    :changeset,
    :subject_id_for,
    user_load: [],
    subject_load: []
  ]

  @type strategy ::
          :actor
          | :request
          | {:actor, keyword()}
          | {:request, keyword()}
          | {:dek_from_process, keyword()}

  @typedoc """
  Optional `when:` opt accepted by tuple-form strategies. Returning
  anything other than `true` causes the chain to skip that strategy.
  """
  @type when_predicate ::
          (Ash.Resource.record() -> boolean())
          | (Ash.Resource.record(), t() -> boolean())

  @type t :: %__MODULE__{
          encrypted_resource: module(),
          user_resource: module(),
          key_grants_config: AshEnvelope.KeyGrants.Config.t(),
          grant_requests_config: AshEnvelope.GrantRequests.Config.t() | nil,
          granter_chain: [strategy()],
          domain: module(),
          actor: term() | nil,
          changeset: Ash.Changeset.t() | nil,
          subject_id_for: (Ash.Resource.record() -> term() | nil) | nil,
          user_load: list(),
          subject_load: list()
        }
end
