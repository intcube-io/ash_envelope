defmodule AshEnvelope.Test.Grant do
  @moduledoc false

  use Ash.Resource,
    domain: AshEnvelope.Test.Domain,
    data_layer: Ash.DataLayer.Ets

  ets do
    private?(true)
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      accept [:wrapped_dek, :subject_id, :user_id, :expires_at]
    end

    update :corrupt_dek do
      accept [:wrapped_dek]
    end

    update :expire do
      require_atomic? false
      accept [:expires_at]
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
      # Nullable so ephemeral worker grants (no principal) can coexist
      # with user grants in the same table.
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
