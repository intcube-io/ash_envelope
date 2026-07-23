defmodule AshEnvelope.Test.Reconcile.Document do
  @moduledoc false

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
      accept [:title]
    end

    update :update do
      primary? true
      accept [:title]
    end
  end

  policies do
    bypass action_type([:read, :create, :update, :destroy]) do
      authorize_if actor_attribute_equals(:role, :admin)
    end

    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :recovery)

      authorize_if expr(
                     exists(
                       memberships,
                       user_id == ^actor(:id)
                     )
                   )
    end

    policy action_type([:create, :update, :destroy]) do
      authorize_if always()
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :title, :string do
      allow_nil? false
      public? true
    end
  end

  relationships do
    has_many :memberships, AshEnvelope.Test.Reconcile.Membership do
      destination_attribute :document_id
    end
  end
end
