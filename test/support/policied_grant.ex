defmodule AshEnvelope.Test.PoliciedGrant do
  # Grants resource with actor-scoped Ash policies mirroring the
  # `mix ash_envelope.gen.key_grants` scaffold. Exercises the
  # `authorize?: true` default of `AshEnvelope.KeyGrants` — every call
  # must thread a real actor or these policies forbid/filter it.
  @moduledoc false

  use Ash.Resource,
    domain: AshEnvelope.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  ets do
    private?(true)
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      accept [:wrapped_dek, :subject_id, :user_id, :expires_at]
    end
  end

  policies do
    # Scaffold shape: a principal reads only their own unexpired rows.
    policy action_type(:read) do
      authorize_if expr(
                     user_id == ^actor(:id) and
                       (is_nil(expires_at) or expires_at > now())
                   )
    end

    # Scaffold leaves the create rule to the integrator; any
    # authenticated actor suffices here — the point under test is that
    # a real actor is threaded (nil actor must be forbidden).
    policy action_type(:create) do
      authorize_if actor_present()
    end

    policy action_type(:destroy) do
      authorize_if expr(user_id == ^actor(:id))
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :wrapped_dek, :string do
      allow_nil? false
      public? false
    end

    attribute :subject_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :user_id, :uuid do
      allow_nil? true
      public? true
    end

    attribute :expires_at, :utc_datetime_usec do
      allow_nil? true
      public? true
    end

    timestamps()
  end
end
