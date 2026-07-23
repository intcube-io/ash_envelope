defmodule AshEnvelope.ConfigDefaultsTest do
  @moduledoc """
  Locks in the SR13 invariant: grant-mutating Config defaults route through
  Ash authorization unless the integrator explicitly opts out.
  """

  use ExUnit.Case, async: true

  alias AshEnvelope.GrantRequests.Config, as: GRConfig
  alias AshEnvelope.KeyGrants.Config, as: KGConfig

  describe "KeyGrants.Config defaults" do
    test "authorize? defaults to true" do
      config = %KGConfig{
        resource: AshEnvelope.Test.Grant,
        actor_public_key_attribute: :public_key,
        actor_private_key_attribute: :private_key
      }

      assert config.authorize? == true
    end

    test "from_options/1 inherits the authorize? default when not supplied" do
      config =
        KGConfig.from_options(
          resource: AshEnvelope.Test.Grant,
          actor_public_key_attribute: :public_key,
          actor_private_key_attribute: :private_key
        )

      assert config.authorize? == true
    end

    test "explicit authorize?: false is respected" do
      config = %KGConfig{
        resource: AshEnvelope.Test.Grant,
        actor_public_key_attribute: :public_key,
        actor_private_key_attribute: :private_key,
        authorize?: false
      }

      assert config.authorize? == false
    end
  end

  describe "GrantRequests.Config defaults" do
    test "authorize? defaults to true" do
      config = %GRConfig{
        resource: AshEnvelope.Test.GrantRequest,
        subject_id_attribute: :subject_id
      }

      assert config.authorize? == true
    end

    test "explicit authorize?: false is respected" do
      config = %GRConfig{
        resource: AshEnvelope.Test.GrantRequest,
        subject_id_attribute: :subject_id,
        authorize?: false
      }

      assert config.authorize? == false
    end
  end
end
