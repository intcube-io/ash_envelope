defmodule AshEnvelope.Test.Reconcile.MtMembership do
  @moduledoc false

  # Attribute-multitenant affecting resource for `MtDocument`. Creating
  # a row with a tenant is the trigger the multitenancy tests use to
  # assert the reconcile fan-out inherits `changeset.tenant`.

  use Ash.Resource,
    domain: AshEnvelope.Test.Reconcile.Domain,
    data_layer: Ash.DataLayer.Ets

  ets do
    private?(true)
  end

  multitenancy do
    strategy(:attribute)
    attribute(:org_id)
    global?(true)
  end

  actions do
    defaults [:read, :destroy]

    # Seeds rows without firing reconciliation (no SyncPrincipal change).
    create :seed do
      accept [:user_id, :document_id, :org_id]
    end

    create :create do
      primary? true
      accept [:user_id, :document_id, :org_id]

      change(
        {AshEnvelope.Reconcile.Changes.SyncPrincipal,
         encrypted_resource: AshEnvelope.Test.Reconcile.MtDocument}
      )
    end

    create :async_create do
      accept [:user_id, :document_id, :org_id]

      change(
        {AshEnvelope.Reconcile.Changes.SyncPrincipal,
         encrypted_resource: AshEnvelope.Test.Reconcile.MtDocument, mode: :async}
      )
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :user_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :document_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :org_id, :string do
      allow_nil? true
      public? true
    end
  end
end
