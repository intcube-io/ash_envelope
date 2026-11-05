defmodule AshEnvelope.Test.TestHelpers.WithPoliciesResource do
  @moduledoc false
  # Baseline "correctly configured" fixture: authorizer, a policy that
  # covers every action type, and a check that actually restricts who
  # may act (so strict permissive-coverage detection passes).

  use Ash.Resource,
    domain: AshEnvelope.Test.Domain,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer],
    validate_domain_inclusion?: false

  ets do
    private?(true)
  end

  actions do
    defaults [:read]
  end

  attributes do
    uuid_primary_key :id
  end

  policies do
    policy always() do
      authorize_if actor_present()
    end
  end
end
