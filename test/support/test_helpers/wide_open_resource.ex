defmodule AshEnvelope.Test.TestHelpers.WideOpenResource do
  @moduledoc false
  # A resource whose only policy is unconditionally permissive:
  # `policy always() do authorize_if always() end`. Every action type is
  # "covered", but the coverage is vacuous — every actor is authorized.
  # Exercises `assert_policies_defined!/2`'s permissive-coverage
  # detection: raises by default, passes with `allow_permissive: true`.

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
    policy always() do
      authorize_if always()
    end
  end
end
