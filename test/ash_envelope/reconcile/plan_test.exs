defmodule AshEnvelope.Reconcile.PlanTest do
  use ExUnit.Case, async: true

  alias AshEnvelope.Reconcile.Plan

  describe "empty?/1" do
    test "true for a plan with no grants and no revocations" do
      assert Plan.empty?(%Plan{})
    end

    test "true even when errors are populated" do
      assert Plan.empty?(%Plan{errors: [{"x", :reason}]})
    end

    test "false when grants are populated" do
      refute Plan.empty?(%Plan{grants: [%{principal_id: "p"}]})
    end

    test "false when revocations are populated" do
      refute Plan.empty?(%Plan{revocations: [%{principal_id: "p"}]})
    end
  end
end
