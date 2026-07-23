defmodule AshEnvelope.TestHelpersTest do
  use ExUnit.Case, async: true

  alias AshEnvelope.TestHelpers

  alias AshEnvelope.Test.TestHelpers.{
    EmptyPoliciesResource,
    NoAuthorizerResource,
    PartialCoverageResource,
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

    test "returns :ok when the resource has an always-policy and only a :read action" do
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

    test "always-policy on a multi-action resource passes default coverage" do
      # If the integrator adds a `policy always()` they implicitly cover
      # every action type the resource defines.
      assert :ok = TestHelpers.assert_policies_defined!(WithPoliciesResource)
    end
  end
end
