defmodule AshEnvelope.Test.BlobIO.PoliciedGrant do
  # Grants resource carrying the policy shape `mix ash_envelope.gen.key_grants`
  # scaffolds (actor-scoped read, self-revoke destroy) plus a create policy
  # that admits only rows with a principal. Exercises the KeyGrants BlobIO
  # manager under its default `authorize?: true`: the ephemeral worker
  # paths have neither actor nor principal, so unless the manager runs
  # them system-side every attach with `expires_at_attribute` configured
  # is forbidden and every analyzer read is filtered to :not_found.
  @moduledoc false

  use Ash.Resource,
    domain: AshEnvelope.Test.BlobIO.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  ets do
    private?(true)
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      accept [:wrapped_dek, :subject_id, :user_id, :expires_at]
    end
  end

  policies do
    # Scaffold shape: a principal reads only their own unexpired rows.
    policy action_type(:read) do
      authorize_if expr(
                     user_id == ^actor(:id) and
                       (is_nil(expires_at) or expires_at > now())
                   )
    end

    # Application code may only create user grants.
    policy action_type(:create) do
      authorize_if AshEnvelope.Test.BlobIO.HasPrincipal
    end

    policy action_type(:destroy) do
      authorize_if expr(user_id == ^actor(:id))
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
