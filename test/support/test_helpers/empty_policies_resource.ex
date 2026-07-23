defmodule AshEnvelope.Test.TestHelpers.EmptyPoliciesResource do
  @moduledoc false

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
  end
end
