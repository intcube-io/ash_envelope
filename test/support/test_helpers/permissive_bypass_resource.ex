defmodule AshEnvelope.Test.TestHelpers.PermissiveBypassResource do
  @moduledoc false
  # Has a genuinely restrictive policy AND an unconditionally permissive
  # `bypass`. The bypass short-circuits every other policy, so despite
  # the restrictive coverage the resource is wide open. Exercises
  # `assert_policies_defined!/2`'s bypass-aware permissive detection.

  use Ash.Resource,
    domain: AshEnvelope.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer],
    validate_domain_inclusion?: false

  ets do
    private?(true)
  end

  actions do
    defaults [:read, :destroy]
    create :create
  end

  attributes do
    uuid_primary_key :id
  end

  policies do
    bypass always() do
      authorize_if always()
    end

    policy always() do
      authorize_if actor_present()
    end
  end
end
