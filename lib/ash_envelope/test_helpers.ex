defmodule AshEnvelope.TestHelpers do
  @moduledoc """
  Assertions for integrator test suites.

  Helpers in this module make it easier to verify that an integrating
  application has wired the authorization-sensitive parts of AshEnvelope
  correctly. They are intended to be called from the integrator's own
  ExUnit tests — typically once per grants resource at the top of the
  suite — so misconfigurations surface as test failures rather than as
  runtime authorization bypasses.

  ## Usage

      defmodule MyApp.SecurityPostureTest do
        use ExUnit.Case, async: true

        test "key-grant resources enforce policies" do
          AshEnvelope.TestHelpers.assert_policies_defined!(MyApp.KeyGrant)
          AshEnvelope.TestHelpers.assert_policies_defined!(MyApp.GrantRequest,
            actions: [:read, :create, :update]
          )
        end
      end
  """

  @default_actions [:read, :create, :destroy]

  @doc """
  Raise unless `resource` has `Ash.Policy.Authorizer` configured, at
  least one policy declared, and (by default) at least one policy
  capable of applying to each of `:read`, `:create`, and `:destroy`
  actions that the resource actually defines.

  Catches the common misconfiguration of a `KeyGrants` / `GrantRequests`
  resource where the integrator declared an authorizer and a `:read`
  policy but left a `:create` or `:destroy` policy block commented out
  (the shape `mix ash_envelope.gen.key_grants` ships in, where the
  `:create` sharing-model branches are intentionally commented).

  ## Options

  * `:actions` — list of action types to require coverage for. Defaults
    to `[:read, :create, :destroy]`. The check skips any action type
    that the resource does not actually define (so the helper does not
    fail on, say, a read-only resource for a missing `:create` policy).
    Pass `actions: []` to disable the coverage check and retain only
    the legacy "authorizer + at least one policy" semantics.

  ## Behaviour

  * Raises if `resource` does not include `Ash.Policy.Authorizer` in
    its `authorizers:` list.
  * Raises if `resource` includes the authorizer but has an empty
    `policies do end` block.
  * Raises if any required action type (defaulting to `[:read, :create,
    :destroy]`, intersected with the actions the resource defines) has
    no policy whose `condition` could match.
  * Otherwise returns `:ok`.

  A policy is considered to "possibly cover" an action type when none
  of its `Action` / `ActionType` condition checks rule out that type.
  Runtime checks like `actor_attribute_equals(:role, :admin)` count as
  non-restricting — they narrow *who* may act, not *which* actions.
  """
  @spec assert_policies_defined!(module(), keyword()) :: :ok | no_return()
  def assert_policies_defined!(resource, opts \\ []) when is_atom(resource) do
    authorizers = Ash.Resource.Info.authorizers(resource)

    cond do
      Ash.Policy.Authorizer not in authorizers ->
        raise """
        AshEnvelope.TestHelpers.assert_policies_defined!/2 failed for #{inspect(resource)}.

        The resource does not have `Ash.Policy.Authorizer` configured. Add it
        to the `use Ash.Resource` declaration:

            use Ash.Resource,
              ...
              authorizers: [Ash.Policy.Authorizer]

        AshEnvelope's grant-mutating APIs default to `authorize?: true`, so
        any resource backing a `KeyGrants.Config` or `GrantRequests.Config`
        must define policies. Run `mix ash_envelope.gen.key_grants` (or
        `gen.grant_requests`) for a baseline policy scaffold.
        """

      Ash.Policy.Info.policies(resource) == [] ->
        raise """
        AshEnvelope.TestHelpers.assert_policies_defined!/2 failed for #{inspect(resource)}.

        The resource has `Ash.Policy.Authorizer` configured but no policies
        defined. AshEnvelope's grant-mutating APIs default to `authorize?:
        true`, so an empty `policies do end` block will reject every action.

        Run `mix ash_envelope.gen.key_grants` (or `gen.grant_requests`) for
        a baseline policy scaffold, or pass `authorize?: false` on the
        Config struct if you intentionally bypass authorization.
        """

      true ->
        opts
        |> Keyword.get(:actions, @default_actions)
        |> List.wrap()
        |> Enum.each(&assert_action_covered!(resource, &1))

        :ok
    end
  end

  defp assert_action_covered!(resource, action_type) do
    defined? =
      resource
      |> Ash.Resource.Info.actions()
      |> Enum.any?(&(&1.type == action_type))

    if defined? do
      policies = Ash.Policy.Info.policies(resource)

      if Enum.any?(policies, &policy_could_apply_to?(&1, action_type, resource)) do
        :ok
      else
        raise """
        AshEnvelope.TestHelpers.assert_policies_defined!/2 failed for #{inspect(resource)}.

        No policy could apply to action type `#{inspect(action_type)}`.
        AshEnvelope's grant-mutating APIs default to `authorize?: true`, so
        without a covering policy this action will be rejected at runtime
        (or, worse, run unprotected if the integrator later flips
        `authorize?: false` to work around the failure).

        Either:

        * Add a policy whose condition matches `:#{action_type}` actions
          (e.g. `policy action_type(:#{action_type})` or `policy always()`),
          or
        * Pass `actions: [...]` to `assert_policies_defined!/2` to
          explicitly opt the action out (e.g. `actions: [:read, :create]`
          to skip `:destroy`).

        Generator scaffolds (`mix ash_envelope.gen.key_grants`) ship with
        sharing-model `:create` policies commented out so you can pick a
        pattern (admin-only, intra-org, anyone-with-a-grant); uncomment one
        before relying on the resource in production.
        """
      end
    else
      :ok
    end
  end

  # A policy could apply to `action_type` if NONE of its condition checks rule
  # out that type. Static-true (`always()`), runtime checks
  # (`actor_attribute_equals/2`, filter checks, etc.) are non-restricting.
  # `Action` and `ActionType` checks restrict.
  defp policy_could_apply_to?(policy, action_type, resource) do
    policy.condition
    |> List.wrap()
    |> Enum.all?(&check_could_apply?(&1, action_type, resource))
  end

  defp check_could_apply?({Ash.Policy.Check.Static, opts}, _action_type, _resource) do
    Keyword.get(opts, :result) == true
  end

  defp check_could_apply?({Ash.Policy.Check.ActionType, opts}, action_type, _resource) do
    case Keyword.get(opts, :type) do
      nil -> true
      ^action_type -> true
      types when is_list(types) -> action_type in types
      other when is_atom(other) -> other == action_type
    end
  end

  defp check_could_apply?({Ash.Policy.Check.Action, opts}, action_type, resource) do
    opts
    |> Keyword.get(:action)
    |> List.wrap()
    |> Enum.any?(fn name ->
      case Ash.Resource.Info.action(resource, name) do
        %{type: ^action_type} -> true
        _ -> false
      end
    end)
  end

  defp check_could_apply?(_other_check, _action_type, _resource) do
    # Runtime, filter, actor- and relation-based checks don't restrict by
    # action type; conservatively assume they could apply.
    true
  end
end
