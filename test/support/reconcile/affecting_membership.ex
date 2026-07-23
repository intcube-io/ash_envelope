defmodule AshEnvelope.Test.Reconcile.AffectingMembership do
  @moduledoc false

  # Mirrors `AshEnvelope.Test.Reconcile.Membership` but uses the
  # `AshEnvelope.Reconcile.Affecting` extension to auto-inject
  # `SyncPrincipal` instead of wiring it manually per action. The
  # `affects` entry on `DocumentWithAffects` lists this resource's
  # `:create` and `:destroy` actions, so reconciliation should fire on
  # those without any per-action `change` declarations here.

  use Ash.Resource,
    domain: AshEnvelope.Test.Reconcile.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshEnvelope.Reconcile.Affecting]

  ets do
    private?(true)
  end

  reconcile_affecting do
    encrypts(AshEnvelope.Test.Reconcile.DocumentWithAffects)
  end

  actions do
    defaults [:read]

    create :create do
      primary? true
      accept [:user_id, :document_id]
    end

    destroy :destroy do
      primary? true
    end

    # Action whose name is NOT listed in the encrypted resource's
    # `affects` entry — used to prove the auto-injected change
    # silently no-ops for non-listed actions.
    update :touch do
      accept []
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
