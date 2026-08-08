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

    # Explicit-form action whose scope resolves to an empty list. Used to
    # assert that `[]` means "no subjects" (a no-op) rather than an empty
    # keyword filter that would fan out over the entire table.
    create :empty_scope_create do
      accept [:user_id, :document_id]

      change(
        {AshEnvelope.Reconcile.Changes.SyncPrincipal,
         encrypted_resource: AshEnvelope.Test.Reconcile.DocumentWithAffects,
         principal: :user_id,
         scope: &__MODULE__.empty_scope/1}
      )
    end

    # Explicit-form async action whose scope returns bare subject ids
    # (not records, not a keyword filter). Used to assert the async
    # trigger builds job args from bare ids without crashing.
    create :async_create_bare_ids do
      accept [:user_id, :document_id]

      change(
        {AshEnvelope.Reconcile.Changes.SyncPrincipal,
         encrypted_resource: AshEnvelope.Test.Reconcile.DocumentWithAffects,
         principal: :user_id,
         scope: &__MODULE__.bare_ids_scope/1,
         mode: :async}
      )
    end
  end

  @doc false
  def empty_scope(_cs), do: []

  @doc false
  def bare_ids_scope(cs), do: [Ash.Changeset.get_attribute(cs, :document_id)]

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
