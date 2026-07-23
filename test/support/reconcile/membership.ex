defmodule AshEnvelope.Test.Reconcile.Membership do
  @moduledoc false

  use Ash.Resource,
    domain: AshEnvelope.Test.Reconcile.Domain,
    data_layer: Ash.DataLayer.Ets

  ets do
    private?(true)
  end

  actions do
    defaults [:read, :destroy, update: []]

    create :create do
      primary? true
      accept [:user_id, :document_id]
    end

    # Lookup-form actions used by the affects-DSL integration tests.
    # They look up principal/scope/only_when from
    # `AshEnvelope.Test.Reconcile.DocumentWithAffects`'s `affects` entry
    # at runtime — no per-action principal/scope/only_when boilerplate.

    create :lookup_create do
      accept [:user_id, :document_id]

      change(
        {AshEnvelope.Reconcile.Changes.SyncPrincipal,
         encrypted_resource: AshEnvelope.Test.Reconcile.DocumentWithAffects}
      )
    end

    destroy :lookup_destroy do
      require_atomic? false

      change(
        {AshEnvelope.Reconcile.Changes.SyncPrincipal,
         encrypted_resource: AshEnvelope.Test.Reconcile.DocumentWithAffects}
      )
    end

    # Async-mode variant used by the async-trigger integration tests.
    # The change carries `mode: :async` so the trigger enqueues an Oban
    # job instead of running reconciliation inline.

    create :async_create do
      accept [:user_id, :document_id]

      change(
        {AshEnvelope.Reconcile.Changes.SyncPrincipal,
         encrypted_resource: AshEnvelope.Test.Reconcile.DocumentWithAffects, mode: :async}
      )
    end

    destroy :async_destroy do
      require_atomic? false

      change(
        {AshEnvelope.Reconcile.Changes.SyncPrincipal,
         encrypted_resource: AshEnvelope.Test.Reconcile.DocumentWithAffects, mode: :async}
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
  end
end
