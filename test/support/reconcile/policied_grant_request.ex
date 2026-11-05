defmodule AshEnvelope.Test.Reconcile.PoliciedGrantRequest do
  @moduledoc false

  # Mirrors `AshEnvelope.Test.Reconcile.GrantRequest` but with
  # actor-scoped policies, so a nil-actor read under `authorize?: true`
  # matches nothing. Used to prove the runner's revoke path clears
  # pending requests via a system-side bypass.

  use Ash.Resource,
    domain: AshEnvelope.Test.Reconcile.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  ets do
    private?(true)
  end

  actions do
    defaults [:read, :destroy, update: [:fulfilled_at, :fulfilled_by_id]]

    create :create do
      primary? true

      accept [
        :document_id,
        :user_id,
        :requested_by_id,
        :requested_at,
        :reason
      ]
    end
  end

  policies do
    policy always() do
      authorize_if expr(user_id == ^actor(:id))
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :document_id, :uuid do
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
