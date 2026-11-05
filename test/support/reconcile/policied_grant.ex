defmodule AshEnvelope.Test.Reconcile.PoliciedGrant do
  @moduledoc false

  # Mirrors `AshEnvelope.Test.Reconcile.Grant` but with actor-scoped
  # policies: only the grant's owner may read or destroy their rows.
  # A nil-actor read under `authorize?: true` matches nothing — this is
  # the trap the reconcile planner's bookkeeping reads must bypass.

  use Ash.Resource,
    domain: AshEnvelope.Test.Reconcile.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  ets do
    private?(true)
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      accept [:wrapped_dek, :document_id, :user_id, :expires_at]
    end
  end

  policies do
    policy always() do
      authorize_if expr(user_id == ^actor(:id))
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :wrapped_dek, :string do
      allow_nil? false
      public? false
    end

    attribute :document_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :user_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :expires_at, :utc_datetime_usec do
      allow_nil? true
      public? true
    end

    timestamps()
  end
end
