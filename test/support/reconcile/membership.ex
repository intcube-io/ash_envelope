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

    # Reassigns the membership to another document. Explicit-form scope
    # using the documented `get_attribute || get_data` pattern — used to
    # assert that the document the membership was moved *away from* is
    # reconciled too (its grant revoked), not just the new one.
    update :move do
      require_atomic? false
      accept [:document_id]

      change(
        {AshEnvelope.Reconcile.Changes.SyncPrincipal,
         encrypted_resource: AshEnvelope.Test.Reconcile.DocumentWithAffects,
         principal: :user_id,
         scope: &__MODULE__.document_scope/1}
      )
    end

    update :async_move do
      require_atomic? false
      accept [:document_id]

      change(
        {AshEnvelope.Reconcile.Changes.SyncPrincipal,
         encrypted_resource: AshEnvelope.Test.Reconcile.DocumentWithAffects,
         principal: :user_id,
         scope: &__MODULE__.document_scope/1,
         mode: :async}
      )
    end
  end

  @doc false
  def document_scope(cs) do
    [
      id:
        Ash.Changeset.get_attribute(cs, :document_id) || Ash.Changeset.get_data(cs, :document_id)
    ]
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
