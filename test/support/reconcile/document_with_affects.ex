defmodule AshEnvelope.Test.Reconcile.DocumentWithAffects do
  @moduledoc false

  # Mirrors `AshEnvelope.Test.Reconcile.Document` but also installs the
  # `AshEnvelope.Reconcile` extension and declares two `affects` entries
  # — one keyed off `Membership` (FK -> document_id), one keyed off the
  # User resource gated by an `only_when` predicate. Used by the
  # affects-DSL tests to exercise `Info.affects*` lookups.

  use Ash.Resource,
    domain: AshEnvelope.Test.Reconcile.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshEnvelope.Reconcile]

  ets do
    private?(true)
  end

  reconcile do
    user_resource(AshEnvelope.Test.Reconcile.User)
    granter_chain([:actor, :request])
    domain(AshEnvelope.Test.Reconcile.Domain)
    key_grants_resource(AshEnvelope.Test.Reconcile.Grant)
    key_grants_subject_id_attribute(:document_id)
    actor_public_key_attribute(:public_key)
    actor_private_key_attribute(:private_key)
    grant_requests_resource(AshEnvelope.Test.Reconcile.GrantRequest)
    grant_requests_subject_id_attribute(:document_id)

    affects AshEnvelope.Test.Reconcile.Membership do
      actions([
        :create,
        :destroy,
        :lookup_create,
        :lookup_destroy,
        :async_create,
        :async_destroy
      ])

      principal(:user_id)

      scope(fn cs ->
        doc_id =
          Ash.Changeset.get_attribute(cs, :document_id) ||
            Ash.Changeset.get_data(cs, :document_id)

        [id: doc_id]
      end)
    end

    affects AshEnvelope.Test.Reconcile.User do
      actions([:update])
      principal(:id)
      scope(:all)

      only_when(fn cs -> Ash.Changeset.changing_attribute?(cs, :role) end)
    end

    # Used by the Affecting-extension integration tests. The
    # `AffectingMembership` resource installs
    # `AshEnvelope.Reconcile.Affecting` so its `:create`/`:destroy`
    # actions auto-fire reconciliation against this entry without any
    # per-action `change SyncPrincipal` boilerplate.
    affects AshEnvelope.Test.Reconcile.AffectingMembership do
      actions([:create, :destroy])
      principal(:user_id)

      scope(fn cs ->
        doc_id =
          Ash.Changeset.get_attribute(cs, :document_id) ||
            Ash.Changeset.get_data(cs, :document_id)

        [id: doc_id]
      end)
    end
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      accept [:title]
    end

    update :update do
      primary? true
      accept [:title]
    end
  end

  policies do
    bypass action_type([:read, :create, :update, :destroy]) do
      authorize_if actor_attribute_equals(:role, :admin)
    end

    policy action_type(:read) do
      authorize_if expr(exists(memberships, user_id == ^actor(:id)))
      authorize_if expr(exists(affecting_memberships, user_id == ^actor(:id)))
    end

    policy action_type([:create, :update, :destroy]) do
      authorize_if always()
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :title, :string do
      allow_nil? false
      public? true
    end
  end

  relationships do
    has_many :memberships, AshEnvelope.Test.Reconcile.Membership do
      destination_attribute :document_id
    end

    has_many :affecting_memberships, AshEnvelope.Test.Reconcile.AffectingMembership do
      destination_attribute :document_id
    end
  end
end
