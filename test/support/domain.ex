defmodule AshEnvelope.Test.Domain do
  @moduledoc false
  use Ash.Domain

  resources do
    resource AshEnvelope.Test.Grant
    resource AshEnvelope.Test.GrantRequest
    resource AshEnvelope.Test.PoliciedGrant
    resource AshEnvelope.Test.PoliciedGrantRequest
    resource AshEnvelope.Test.TestHelpers.NoAuthorizerResource
    resource AshEnvelope.Test.TestHelpers.EmptyPoliciesResource
    resource AshEnvelope.Test.TestHelpers.WithPoliciesResource
    resource AshEnvelope.Test.TestHelpers.PartialCoverageResource
    resource AshEnvelope.Test.TestHelpers.WideOpenResource
    resource AshEnvelope.Test.TestHelpers.PermissiveBypassResource
  end
end
