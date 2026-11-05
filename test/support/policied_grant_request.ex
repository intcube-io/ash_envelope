defmodule AshEnvelope.Test.PoliciedGrantRequest do
  # Grant-requests resource with actor-scoped Ash policies mirroring the
  # `mix ash_envelope.gen.grant_requests` scaffold. Exercises the
  # `authorize?: true` default of `AshEnvelope.GrantRequests`.
  @moduledoc false

  use Ash.Resource,
    domain: AshEnvelope.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  import Ash.Expr

  ets do
    private?(true)
  end

  actions do
    defaults [:read, :destroy, update: [:fulfilled_at, :fulfilled_by_id]]

    create :create do
      primary? true

      accept [
        :subject_id,
        :user_id,
        :requested_by_id,
        :requested_at,
        :reason
      ]
    end
  end

  identities do
    identity :unique_pending, [:subject_id, :user_id],
      where: expr(is_nil(fulfilled_at)),
      pre_check_with: AshEnvelope.Test.Domain
  end

  policies do
    # Scaffold shape: targets see requests addressed to them,
    # requesters see what they triggered.
    policy action_type(:read) do
      authorize_if expr(user_id == ^actor(:id))
      authorize_if expr(requested_by_id == ^actor(:id))
    end

    policy action_type(:create) do
      authorize_if actor_present()
    end

    # Scaffold leaves "who may fulfill" to the integrator; any
    # authenticated actor suffices for these tests.
    policy action_type(:update) do
      authorize_if actor_present()
    end

    policy action_type(:destroy) do
      authorize_if expr(user_id == ^actor(:id))
      authorize_if expr(requested_by_id == ^actor(:id))
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :subject_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :user_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :requested_by_id, :uuid do
      allow_nil? true
      public? true
    end

    attribute :requested_at, :utc_datetime_usec do
      allow_nil? false
      public? true
    end

    attribute :fulfilled_at, :utc_datetime_usec do
      allow_nil? true
      public? true
    end

    attribute :fulfilled_by_id, :uuid do
      allow_nil? true
      public? true
    end

    attribute :reason, :string do
      allow_nil? true
      public? true
    end

    timestamps()
  end
end
