defmodule AshEnvelope.TestHelpers do
  @moduledoc """
  Assertions for integrator test suites.

  Helpers in this module make it easier to verify that an integrating
  application has wired the authorization-sensitive parts of AshEnvelope
  correctly. They are intended to be called from the integrator's own
  ExUnit tests — typically once per grants resource at the top of the
  suite.

  ## What these helpers do (and do not) check

  `assert_policies_defined!/2` checks policy **existence and coverage**,
  not **restrictiveness**. It verifies that an authorizer is configured,
  that at least one policy is declared, and that each required action
  type has at least one policy whose condition could match it. It does
  not evaluate what those policies allow: a policy that authorizes the
  wrong actors, or a forbid-only policy that rejects everyone, satisfies
  the coverage check just the same.

  By default the helper additionally flags one degenerate case: an
  action type whose entire coverage is unconditionally permissive
  (`policy always()` / `policy true` containing only `authorize_if
  always()` checks), which authorizes every actor for that action. See
  the `:allow_permissive` option. Beyond that special case, verifying
  that policies are *correct* — that they authorize the right actors and
  forbid the rest — still requires ordinary authorization tests against
  the resource.

  ## Usage

      defmodule MyApp.SecurityPostureTest do
        use ExUnit.Case, async: true

        test "key-grant resources define covering policies" do
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

  This is a *coverage* check, not a *restrictiveness* check — see the
  module documentation for what it deliberately does not verify.

  ## Options

  * `:actions` — list of action types to require coverage for. Defaults
    to `[:read, :create, :destroy]`. The check skips any action type
    that the resource does not actually define (so the helper does not
    fail on, say, a read-only resource for a missing `:create` policy).
    Pass `actions: []` to disable the coverage check (including the
    permissive-coverage detection below) and retain only the legacy
    "authorizer + at least one policy" semantics.

  * `:allow_permissive` — defaults to `false`. When `false`, the helper
    also raises if every policy covering a required action type is
    unconditionally permissive — a condition of `always()`/`true` and
    nothing but `authorize_if always()` checks — or if such a policy is
    a `bypass`, since either way the action type is authorized for
    every actor and the coverage is vacuous. Pass `allow_permissive:
    true` if a wide-open policy is intentional (e.g. a resource whose
    access control lives entirely outside Ash policies).

  ## Behaviour

  * Raises if `resource` does not include `Ash.Policy.Authorizer` in
    its `authorizers:` list.
  * Raises if `resource` includes the authorizer but has an empty
    `policies do end` block.
  * Raises if any required action type (defaulting to `[:read, :create,
    :destroy]`, intersected with the actions the resource defines) has
    no policy whose `condition` could match.
  * Raises if a required action type is covered only by unconditionally
    permissive policies (unless `allow_permissive: true`).
  * Otherwise returns `:ok`.

  A policy is considered to "possibly cover" an action type when none
  of its `Action` / `ActionType` condition checks rule out that type.
  Runtime checks like `actor_attribute_equals(:role, :admin)` count as
  non-restricting — they narrow *who* may act, not *which* actions.

  ## Limitations

  * A policy whose checks reject the actors you care about (or a
    forbid-only policy that rejects everyone) still counts as coverage.
  * Permissive-coverage detection only recognises the literal
    `always()`/`true` shape. A policy that is effectively wide open
    through other means (e.g. a custom check that always returns
    `true`) is not detected.
  * `bypass` policies are treated like ordinary policies for coverage
    purposes; their short-circuit semantics are only considered by the
    permissive-coverage detection.
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
        allow_permissive? = Keyword.get(opts, :allow_permissive, false)

        opts
        |> Keyword.get(:actions, @default_actions)
        |> List.wrap()
        |> Enum.each(&assert_action_covered!(resource, &1, allow_permissive?))

        :ok
    end
  end

  defp assert_action_covered!(resource, action_type, allow_permissive?) do
    defined? =
      resource
      |> Ash.Resource.Info.actions()
      |> Enum.any?(&(&1.type == action_type))

    if defined? do
      covering =
        resource
        |> Ash.Policy.Info.policies()
        |> Enum.filter(&policy_could_apply_to?(&1, action_type, resource))

      cond do
        covering == [] ->
          raise_uncovered!(resource, action_type)

        not allow_permissive? and only_permissive_coverage?(covering) ->
          raise_permissive!(resource, action_type)

        true ->
          :ok
      end
    else
      :ok
    end
  end

  defp raise_uncovered!(resource, action_type) do
    raise """
    AshEnvelope.TestHelpers.assert_policies_defined!/2 failed for #{inspect(resource)}.

    No policy could apply to action type `#{inspect(action_type)}`.
    AshEnvelope's grant-mutating APIs default to `authorize?: true`, so
    without a covering policy this action will be rejected at runtime
    (or, worse, run unprotected if the integrator later flips
    `authorize?: false` to work around the failure).

    Either:

    * Add a policy whose condition matches `:#{action_type}` actions
      (e.g. `policy action_type(:#{action_type})`), or
    * Pass `actions: [...]` to `assert_policies_defined!/2` to
      explicitly opt the action out (e.g. `actions: [:read, :create]`
      to skip `:destroy`).

    Generator scaffolds (`mix ash_envelope.gen.key_grants`) ship with
    sharing-model `:create` policies commented out so you can pick a
    pattern (admin-only, intra-org, anyone-with-a-grant); uncomment one
    before relying on the resource in production.
    """
  end

  defp raise_permissive!(resource, action_type) do
    raise """
    AshEnvelope.TestHelpers.assert_policies_defined!/2 failed for #{inspect(resource)}.

    Action type `#{inspect(action_type)}` is covered only by unconditionally
    permissive policies (condition `always()`/`true` with nothing but
    `authorize_if always()` checks). Such a policy authorizes every actor,
    so the coverage this helper checks for is vacuous: the action type is
    effectively unprotected even though "a policy exists".

    Either:

    * Replace the wide-open policy with one that actually restricts access
      (e.g. `authorize_if actor_attribute_equals(:role, :admin)`), or
    * Pass `allow_permissive: true` to `assert_policies_defined!/2` if a
      wide-open policy is intentional for this resource.
    """
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

  # Coverage is vacuous when every covering policy is unconditionally
  # permissive, or when an unconditionally permissive `bypass` is among
  # them — a bypass short-circuits all other policies, so even genuinely
  # restrictive coverage alongside it is moot.
  defp only_permissive_coverage?(covering) do
    Enum.all?(covering, &unconditionally_permissive?/1) or
      Enum.any?(covering, &(&1.bypass? && unconditionally_permissive?(&1)))
  end

  # `policy always() do authorize_if always() end` (or `policy true`):
  # every condition check is static-true and every inner check is an
  # `authorize_if` that statically evaluates to true.
  defp unconditionally_permissive?(policy) do
    condition_always_true? =
      policy.condition
      |> List.wrap()
      |> Enum.all?(&static_true_condition?/1)

    checks = List.wrap(policy.policies)

    condition_always_true? and checks != [] and
      Enum.all?(checks, &authorize_if_always?/1)
  end

  defp static_true_condition?({Ash.Policy.Check.Static, opts}),
    do: Keyword.get(opts, :result) == true

  defp static_true_condition?(_other), do: false

  defp authorize_if_always?(%{type: :authorize_if, check_module: Ash.Policy.Check.Static} = check) do
    Keyword.get(check.check_opts, :result) == true
  end

  defp authorize_if_always?(_check), do: false
end
