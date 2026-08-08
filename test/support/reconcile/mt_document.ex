defmodule AshEnvelope.Test.Reconcile.MtDocument do
  @moduledoc false

  # Attribute-multitenant variant of `DocumentWithAffects`, used by the
  # multitenancy tests. `global? true` mirrors hosts that also allow
  # tenant-less system reads — which is exactly the configuration where
  # a reconcile fan-out that forgets the tenant silently spans every
  # tenant instead of raising. The `affects` entry deliberately uses
  # `scope :all` (the widest fan-out) so the tests can prove the stream
  # stays inside the triggering changeset's tenant.

  use Ash.Resource,
    domain: AshEnvelope.Test.Reconcile.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshEnvelope.Reconcile]

  ets do
    private?(true)
  end

  multitenancy do
    strategy(:attribute)
    attribute(:org_id)
    global?(true)
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

    affects AshEnvelope.Test.Reconcile.MtMembership do
      actions([:create, :async_create])
      principal(:user_id)
      scope(:all)
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
    policy action_type(:read) do
      authorize_if expr(exists(memberships, user_id == ^actor(:id)))
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

    attribute :org_id, :string do
      allow_nil? true
      public? true
    end
  end

  relationships do
    has_many :memberships, AshEnvelope.Test.Reconcile.MtMembership do
      destination_attribute :document_id
    end
  end
end
