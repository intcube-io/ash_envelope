defmodule AshEnvelope.Reconcile.ValidateConfigTest do
  # async: false — Code.compile_string mutates the global module table, and
  # the unique-suffix scheme below means each compile registers a fresh
  # module that can't be cleaned up without taking down code-server.
  use ExUnit.Case, async: false

  test "compile-fails when a required field is missing" do
    err =
      assert_raise Spark.Error.DslError, fn ->
        compile_resource(:missing_private_key, """
        use Ash.Resource,
          domain: AshEnvelope.Test.Reconcile.Domain,
          data_layer: Ash.DataLayer.Ets,
          extensions: [AshEnvelope.Reconcile]

        ets do
          private?(true)
        end

        reconcile do
          user_resource(AshEnvelope.Test.Reconcile.User)
          domain(AshEnvelope.Test.Reconcile.Domain)
          key_grants_resource(AshEnvelope.Test.Reconcile.Grant)
          actor_public_key_attribute(:public_key)
          # actor_private_key_attribute intentionally missing
        end

        attributes do
          uuid_primary_key :id
        end
        """)
      end

    assert err.message =~ "actor_private_key_attribute"
  end

  test "compiles cleanly when all required fields are set" do
    # `granter_chain [:actor]` — the default chain includes `:request`,
    # which would additionally require `grant_requests_resource`.
    compile_resource(:happy_path, """
    use Ash.Resource,
      domain: AshEnvelope.Test.Reconcile.Domain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshEnvelope.Reconcile]

    ets do
      private?(true)
    end

    reconcile do
      user_resource(AshEnvelope.Test.Reconcile.User)
      domain(AshEnvelope.Test.Reconcile.Domain)
      key_grants_resource(AshEnvelope.Test.Reconcile.Grant)
      actor_public_key_attribute(:public_key)
      actor_private_key_attribute(:private_key)
      granter_chain([:actor])
    end

    attributes do
      uuid_primary_key :id
    end
    """)
  end

  test "compiles cleanly with :request in the chain when grant_requests_resource is set" do
    compile_resource(:request_with_resource, """
    use Ash.Resource,
      domain: AshEnvelope.Test.Reconcile.Domain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshEnvelope.Reconcile]

    ets do
      private?(true)
    end

    reconcile do
      user_resource(AshEnvelope.Test.Reconcile.User)
      domain(AshEnvelope.Test.Reconcile.Domain)
      key_grants_resource(AshEnvelope.Test.Reconcile.Grant)
      actor_public_key_attribute(:public_key)
      actor_private_key_attribute(:private_key)
      grant_requests_resource(AshEnvelope.Test.Reconcile.GrantRequest)
      granter_chain([{:actor, when: &Kernel.is_map/1}, :request])
    end

    attributes do
      uuid_primary_key :id
    end
    """)
  end

  test "compile-fails when :request is in the chain (by default) without grant_requests_resource" do
    err =
      assert_raise Spark.Error.DslError, fn ->
        compile_resource(:request_without_resource, """
        use Ash.Resource,
          domain: AshEnvelope.Test.Reconcile.Domain,
          data_layer: Ash.DataLayer.Ets,
          extensions: [AshEnvelope.Reconcile]

        ets do
          private?(true)
        end

        reconcile do
          user_resource(AshEnvelope.Test.Reconcile.User)
          domain(AshEnvelope.Test.Reconcile.Domain)
          key_grants_resource(AshEnvelope.Test.Reconcile.Grant)
          actor_public_key_attribute(:public_key)
          actor_private_key_attribute(:private_key)
          # granter_chain defaults to [:actor, :request]
          # grant_requests_resource intentionally missing
        end

        attributes do
          uuid_primary_key :id
        end
        """)
      end

    assert err.message =~ "grant_requests_resource"
    assert err.message =~ ":request"
  end

  test "compile-fails on an unknown granter strategy shape" do
    err =
      assert_raise Spark.Error.DslError, fn ->
        compile_resource(:unknown_strategy, """
        use Ash.Resource,
          domain: AshEnvelope.Test.Reconcile.Domain,
          data_layer: Ash.DataLayer.Ets,
          extensions: [AshEnvelope.Reconcile]

        ets do
          private?(true)
        end

        reconcile do
          user_resource(AshEnvelope.Test.Reconcile.User)
          domain(AshEnvelope.Test.Reconcile.Domain)
          key_grants_resource(AshEnvelope.Test.Reconcile.Grant)
          actor_public_key_attribute(:public_key)
          actor_private_key_attribute(:private_key)
          granter_chain([:actor, :carrier_pigeon])
        end

        attributes do
          uuid_primary_key :id
        end
        """)
      end

    assert err.message =~ "unknown strategy"
    assert err.message =~ "carrier_pigeon"
  end

  # Each test compiles a fresh module name so reruns don't collide. The
  # System.unique_integer suffix is per-process, sufficient for ExUnit.
  defp compile_resource(label, body) do
    mod_name =
      Module.concat([
        "AshEnvelope.Reconcile.ValidateConfigTest.Generated",
        "#{label}_#{System.unique_integer([:positive])}"
      ])

    Code.compile_string("""
    defmodule #{inspect(mod_name)} do
      @moduledoc false
    #{body}
    end
    """)

    mod_name
  end
end
