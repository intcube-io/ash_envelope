defmodule AshEnvelope.Test.Reconcile.User do
  @moduledoc false

  use Ash.Resource,
    domain: AshEnvelope.Test.Reconcile.Domain,
    data_layer: Ash.DataLayer.Ets

  ets do
    private?(true)
  end

  actions do
    defaults [:read, :destroy, update: [:role, :public_key, :private_key]]

    create :create do
      primary? true
      accept [:role, :public_key, :private_key]
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :role, :atom do
      allow_nil? false
      default :user
      public? true
      constraints one_of: [:user, :admin, :recovery]
    end

    attribute :public_key, :binary do
      allow_nil? true
      public? true
    end

    attribute :private_key, :binary do
      allow_nil? true
      sensitive? true
      public? false
    end
  end
end
