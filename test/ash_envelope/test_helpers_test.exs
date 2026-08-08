defmodule AshEnvelope.TestHelpersTest do
  use ExUnit.Case, async: true

  alias AshEnvelope.TestHelpers

  alias AshEnvelope.Test.TestHelpers.{
    EmptyPoliciesResource,
    NoAuthorizerResource,
    PartialCoverageResource,
    PermissiveBypassResource,
    WideOpenResource,
    WithPoliciesResource
  }

  describe "assert_policies_defined!/2 — authorizer + non-empty policies" do
    test "raises when the resource has no Ash.Policy.Authorizer" do
      message =
        assert_raise(RuntimeError, fn ->
          TestHelpers.assert_policies_defined!(NoAuthorizerResource)
        end).message

      assert message =~ "does not have `Ash.Policy.Authorizer` configured"
    end

    test "raises when the resource has the authorizer but no policies" do
      message =
        assert_raise(RuntimeError, fn ->
          TestHelpers.assert_policies_defined!(EmptyPoliciesResource)
        end).message

      assert message =~ "has `Ash.Policy.Authorizer` configured but no policies"
    end

    test "returns :ok when the resource has an always-condition policy with a restricting check" do
      assert :ok = TestHelpers.assert_policies_defined!(WithPoliciesResource)
    end
  end

  describe "assert_policies_defined!/2 — action coverage" do
    test "default actions catch a missing :create policy on a resource that has a :create action" do
      message =
        assert_raise(RuntimeError, fn ->
          TestHelpers.assert_policies_defined!(PartialCoverageResource)
        end).message

      assert message =~ "No policy could apply to action type `:create`"
    end

    test "default actions catch a missing :destroy policy" do
      # Same resource, narrowed `:actions` to surface destroy specifically.
      message =
        assert_raise(RuntimeError, fn ->
          TestHelpers.assert_policies_defined!(PartialCoverageResource, actions: [:destroy])
        end).message

      assert message =~ "No policy could apply to action type `:destroy`"
    end

    test "passes when actions:[] disables the coverage check" do
      assert :ok = TestHelpers.assert_policies_defined!(PartialCoverageResource, actions: [])
    end

    test "passes when actions: narrows to only the covered action" do
      assert :ok = TestHelpers.assert_policies_defined!(PartialCoverageResource, actions: [:read])
    end

    test "skips action types the resource does not define (:update on a resource with no :update action)" do
      # WithPoliciesResource has only `:read`. Asking for `:update` coverage
      # is a no-op rather than a failure, because requiring policies for
      # actions that don't exist would be noise.
      assert :ok = TestHelpers.assert_policies_defined!(WithPoliciesResource, actions: [:update])
    end
  end

  describe "assert_policies_defined!/2 — permissive-coverage detection" do
    test "a wide-open resource (policy always() / authorize_if always()) raises by default" do
      # `policy always() do authorize_if always() end` "covers" every
      # action type, but authorizes every actor — the coverage is
      # vacuous, so strict mode (the default) rejects it.
      message =
        assert_raise(RuntimeError, fn ->
          TestHelpers.assert_policies_defined!(WideOpenResource)
        end).message

      assert message =~ "covered only by unconditionally"
      assert message =~ "allow_permissive: true"
    end

    test "a wide-open resource passes with allow_permissive: true" do
      assert :ok = TestHelpers.assert_policies_defined!(WideOpenResource, allow_permissive: true)
    end

    test "an unconditionally permissive bypass raises even alongside restrictive policies" do
      # A permissive bypass short-circuits every other policy, so the
      # restrictive `actor_present()` policy next to it is moot.
      message =
        assert_raise(RuntimeError, fn ->
          TestHelpers.assert_policies_defined!(PermissiveBypassResource)
        end).message

      assert message =~ "covered only by unconditionally"
    end

    test "a permissive bypass passes with allow_permissive: true" do
      assert :ok =
               TestHelpers.assert_policies_defined!(PermissiveBypassResource,
                 allow_permissive: true
               )
    end

    test "a restricting check under an always() condition is not flagged" do
      # WithPoliciesResource: `policy always() do authorize_if
      # actor_present() end` — broad condition, but the check narrows
      # who may act, so it is not vacuous.
      assert :ok = TestHelpers.assert_policies_defined!(WithPoliciesResource)
    end

    test "actions: [] disables permissive detection along with coverage" do
      assert :ok = TestHelpers.assert_policies_defined!(WideOpenResource, actions: [])
    end
  end
end
