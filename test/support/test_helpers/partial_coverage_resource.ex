defmodule AshEnvelope.Test.TestHelpers.PartialCoverageResource do
  @moduledoc false
  # Has `:read`, `:create`, and `:destroy` actions but only a policy
  # for `:read`. Exercises `assert_policies_defined!/2`'s action-coverage
  # check: the default `actions: [:read, :create, :destroy]` should
  # raise; `actions: [:read]` should pass.

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
    policy action_type(:read) do
      authorize_if always()
    end
  end
end
