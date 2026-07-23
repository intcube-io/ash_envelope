defmodule AshEnvelope.Test.Reconcile.Grant do
  @moduledoc false

  use Ash.Resource,
    domain: AshEnvelope.Test.Reconcile.Domain,
    data_layer: Ash.DataLayer.Ets

  ets do
    private?(true)
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      accept [:wrapped_dek, :document_id, :user_id]
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

    timestamps()
  end
end
