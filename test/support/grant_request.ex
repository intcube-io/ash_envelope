defmodule AshEnvelope.Test.GrantRequest do
  @moduledoc false

  use Ash.Resource,
    domain: AshEnvelope.Test.Domain,
    data_layer: Ash.DataLayer.Ets

  import Ash.Expr

  ets do
    private?(true)
  end

  actions do
    defaults [:read, update: [:fulfilled_at, :fulfilled_by_id]]

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

    destroy :destroy do
      primary? true
      require_atomic? false

      # Test hook: rows flagged "unrevokable" refuse destruction so
      # error propagation in revoke paths can be exercised.
      change fn changeset, _context ->
        if changeset.data.reason == "unrevokable" do
          Ash.Changeset.add_error(changeset, field: :reason, message: "cannot revoke")
        else
          changeset
        end
      end
    end
  end

  identities do
    # Locks SR15: one pending row per (subject, target). Concurrent
    # `GrantRequests.create/6` calls must race-recover into a single row.
    identity :unique_pending, [:subject_id, :user_id],
      where: expr(is_nil(fulfilled_at)),
      pre_check_with: AshEnvelope.Test.Domain
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
