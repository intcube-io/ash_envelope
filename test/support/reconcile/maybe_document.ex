defmodule AshEnvelope.Test.Reconcile.MaybeDocument do
  @moduledoc false

  # A document whose read policy hinges on
  # `AshEnvelope.Test.Reconcile.UnresolvableCheck` — `Ash.can?/3`
  # returns `:maybe` for it at planning time. Used to prove the
  # reconcile planner fails closed on unresolvable policy results.

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
  end

  policies do
    policy action_type(:read) do
      access_type :runtime
      authorize_if AshEnvelope.Test.Reconcile.UnresolvableCheck
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
end
