defmodule AshEnvelope.Test.Reconcile.GrantRequest do
  @moduledoc false

  use Ash.Resource,
    domain: AshEnvelope.Test.Reconcile.Domain,
    data_layer: Ash.DataLayer.Ets

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
