defmodule AshEnvelope.Reconcile.Runner do
  @moduledoc """
  Pure-Elixir core of `AshEnvelope.Reconcile`.

  Three entry points:

  - `plan/2` — compute the diff (grants to issue, grants to revoke)
    without writing anything. Returns a `Plan.t()`.
  - `apply_plan!/2` — execute the plan atomically. By default the
    write-side runs inside `Ash.transaction/3` so a single failed grant
    rolls the whole batch back; pass `transaction: false` to opt out.
  - `run/2` — convenience: `apply_plan!(ctx, plan(ctx, pairs))`. The
    in-line change modules (`SyncSubject`, `SyncPrincipal`) call this
    in their default `:sync` mode.

  Truth model: `Ash.can?(:read, subject_record, actor: principal)` is
  the source of truth. If the policy authorizes the principal but no
  grant exists, the plan lists the pair under `:grants`. If a grant
  exists but the policy no longer authorizes, the pair lands under
  `:revocations`. No-op pairs aren't recorded (cheap to recompute).

  The grant table's subject id is derived via `ctx.subject_id_for` (or
  `& &1.id` by default). This lets grants live on a related row (e.g.
  an attachment blob) rather than the encrypted resource itself.

  Planning errors are collected per pair into `Plan.errors`, never
  raised. Apply-side failures (granter-chain errors, failed revokes)
  are logged *and* aggregated: `run/3` and `apply_plan!/3` return
  `:ok` only when every entry succeeded, otherwise
  `{:error, aggregate}` (see `t:apply_error/0`) so callers can react
  — retry, alert, or fail the surrounding job. Exhausted granter
  chains (`:skip`) are logged but not treated as failures.
  """

  alias AshEnvelope.{GrantRequests, KeyGrants}
  alias AshEnvelope.Reconcile.{Context, Granter, Plan}

  require Ash.Query
  require Logger

  @typedoc """
  Aggregate failure report returned by `run/3` and `apply_plan!/3`.

  - `:grant_failures` — `[{principal_id, subject_id, reason}]` for
    grant entries whose granter chain returned `{:error, reason}`.
  - `:revoke_failures` — `[{principal_id, subject_id, reason}]` for
    revocation entries where reading the grant rows, destroying a
    grant, or clearing a pending grant request failed.
  - `:plan_errors` — `[{principal_id, reason}]` carried over from
    `Plan.errors` (pairs that errored during planning).
  """
  @type apply_error :: %{
          grant_failures: [{term(), term(), term()}],
          revoke_failures: [{term(), term(), term()}],
          plan_errors: [{term(), term()}]
        }

  @doc """
  Convenience: `apply_plan!(ctx, plan(ctx, pairs), opts)`.

  Same defaults and return contract as `apply_plan!/3`
  (`transaction: true`; `:ok` or `{:error, aggregate}`).
  """
  @spec run(Context.t(), [{term(), Ash.Resource.record() | term()}], keyword()) ::
          :ok | {:error, apply_error()}
  def run(%Context{} = ctx, pairs, opts \\ []) when is_list(pairs) do
    plan = plan(ctx, pairs)
    apply_plan!(ctx, plan, opts)
  end

  @doc """
  Fulfill a pre-loaded list of pending grant request rows by re-wrapping
  the DEK from `ctx.actor` to each request's target.

  Designed for the user-driven Apply flow (e.g. a LiveView page where an
  authorized user fulfills outstanding requests in their session). The
  caller has already filtered the list of requests they want to apply
  (typically via `AshEnvelope.GrantRequests.list_fulfillable_for/4`).

  ## Options

  - `:on_progress` — `(progress :: map -> any)` callback fired after
    each request. Receives `%{done: pos_integer, total: pos_integer,
    request: record, status: :ok | :skipped | {:error, term}}`. Default:
    a no-op. The LiveView pattern is to `send(self(), {:progress, meta})`
    and render in `handle_info/2`.

  ## Behavior

  Each request is processed independently:

  - Already-fulfilled rows (`fulfilled_at` not nil) → `:skipped`.
  - Target user gone or load fails → counted in `errors`.
  - Otherwise calls `AshEnvelope.GrantRequests.fulfill/6` which is
    idempotent against the underlying grant identity and
    `is_nil(fulfilled_at)`. Concurrent fulfillers race-safely.

  Errors are collected into the summary, never raised. No transaction
  wrapping — partial progress is fine because the request table is the
  source of truth and re-runs are safe.
  """
  @spec fulfill_pending(Context.t(), [Ash.Resource.record()], keyword()) :: %{
          ok: non_neg_integer(),
          skipped: non_neg_integer(),
          errors: [{Ash.Resource.record(), term()}]
        }
  def fulfill_pending(ctx, requests, opts \\ [])

  def fulfill_pending(%Context{grant_requests_config: nil}, requests, _opts)
      when is_list(requests) do
    %{ok: 0, skipped: 0, errors: Enum.map(requests, &{&1, :no_grant_requests_resource})}
  end

  def fulfill_pending(%Context{} = ctx, requests, opts) when is_list(requests) do
    on_progress = Keyword.get(opts, :on_progress, fn _ -> :ok end)
    total = length(requests)

    requests
    |> Enum.with_index(1)
    |> Enum.reduce(%{ok: 0, skipped: 0, errors: []}, fn {request, idx}, acc ->
      result = fulfill_one(ctx, request)

      on_progress.(%{
        done: idx,
        total: total,
        request: request,
        status: status_of(result)
      })

      track(acc, request, result)
    end)
  end

  defp fulfill_one(%Context{} = ctx, request) do
    config = ctx.grant_requests_config
    grants_config = ctx.key_grants_config
    actor = ctx.actor

    cond do
      is_nil(actor) ->
        {:error, :no_actor}

      Map.get(request, config.fulfilled_at_attribute) ->
        :already_fulfilled

      true ->
        target_id = Map.get(request, config.target_principal_id_attribute)

        case load_target(ctx, target_id) do
          {:ok, target} when not is_nil(target) ->
            GrantRequests.fulfill(config, grants_config, request, actor, target, ctx.domain,
              tenant: ctx.tenant
            )

          {:ok, nil} ->
            {:error, :target_not_found}

          :not_found ->
            {:error, :target_not_found}

          {:error, _} = err ->
            err
        end
    end
  end

  defp load_target(%Context{} = ctx, target_id) do
    case Ash.get(ctx.user_resource, target_id,
           domain: ctx.domain,
           tenant: ctx.tenant,
           authorize?: false
         ) do
      {:ok, user} ->
        {:ok, user}

      {:error, %Ash.Error.Invalid{errors: errors}} ->
        if Enum.any?(errors, &match?(%Ash.Error.Query.NotFound{}, &1)) do
          :not_found
        else
          {:error, errors}
        end

      {:error, %Ash.Error.Query.NotFound{}} ->
        :not_found

      {:error, _} = err ->
        err
    end
  end

  defp status_of(:ok), do: :ok
  defp status_of(:already_fulfilled), do: :skipped
  defp status_of({:error, _} = err), do: err

  defp track(acc, _request, :ok), do: %{acc | ok: acc.ok + 1}
  defp track(acc, _request, :already_fulfilled), do: %{acc | skipped: acc.skipped + 1}

  defp track(acc, request, {:error, reason}),
    do: %{acc | errors: [{request, reason} | acc.errors]}

  @doc """
  Compute the reconciliation diff for `pairs` without writing anything.

  Returns a `Plan.t()` describing what `apply_plan!/3` would do.
  Cheap and side-effect-free; safe to call from a UI handler to render
  a confirmation dialog.

  Each pair is `{principal_id, subject_record_or_id}`. Records are
  preferred (already-loaded relations skip a re-fetch).
  """
  @spec plan(Context.t(), [{term(), Ash.Resource.record() | term()}]) :: Plan.t()
  def plan(%Context{} = ctx, pairs) when is_list(pairs) do
    Enum.reduce(pairs, %Plan{}, fn {principal_id, subject_input}, acc ->
      classify_pair(ctx, principal_id, subject_input, acc)
    end)
  end

  @doc """
  Execute a previously computed plan.

  ## Options

  - `:transaction` — wrap the writes in `Ash.transaction/3` so a
    failure mid-apply rolls back the whole batch. Default `true`.

  Granter-chain failures (`{:error, _}`) and exhausted chains
  (`:skip`) are logged at `:warning` and the apply continues with the
  next entry — they don't trigger a rollback unless you wrap an
  explicit raise around them. The transaction guard is there to
  protect against unexpected exceptions inside the apply phase, not to
  enforce all-grants-or-no-grants semantics across granter strategies.

  Returns `:ok` when every entry applied cleanly (exhausted chains
  count as non-failures) and the plan carried no planning errors.
  Otherwise returns `{:error, aggregate}` where `aggregate` is a
  `t:apply_error/0` map collecting `:grant_failures`,
  `:revoke_failures`, and the plan's `:errors` as `:plan_errors`.
  """
  @spec apply_plan!(Context.t(), Plan.t(), keyword()) :: :ok | {:error, apply_error()}
  def apply_plan!(%Context{} = ctx, %Plan{} = plan, opts \\ []) do
    if Plan.empty?(plan) do
      aggregate(plan, [], [])
    else
      do_apply = fn ->
        grant_failures = Enum.flat_map(plan.grants, &issue_grant_entry(ctx, &1))
        revoke_failures = Enum.flat_map(plan.revocations, &revoke_entry(ctx, &1))
        {grant_failures, revoke_failures}
      end

      {grant_failures, revoke_failures} =
        if Keyword.get(opts, :transaction, true) do
          # Only the grants and grant_requests resources are written here.
          # Excluding `encrypted_resource` avoids requiring it to share a
          # repo/data layer with the grants table — the planner has already
          # finished its reads.
          case Ash.transaction(
                 tap_with_requests([ctx.key_grants_config.resource], ctx),
                 fn -> do_apply.() end
               ) do
            {:ok, failures} ->
              failures

            {:error, reason} ->
              raise "AshEnvelope.Reconcile.apply_plan!/3 failed: #{inspect(reason)}"
          end
        else
          do_apply.()
        end

      aggregate(plan, grant_failures, revoke_failures)
    end
  end

  defp aggregate(%Plan{errors: []}, [], []), do: :ok

  defp aggregate(%Plan{errors: plan_errors}, grant_failures, revoke_failures) do
    {:error,
     %{
       grant_failures: grant_failures,
       revoke_failures: revoke_failures,
       plan_errors: plan_errors
     }}
  end

  defp tap_with_requests(resources, %Context{grant_requests_config: nil}), do: resources

  defp tap_with_requests(resources, %Context{grant_requests_config: %{resource: r}}),
    do: [r | resources]

  # ---- planning ----

  defp classify_pair(ctx, principal_id, subject_input, %Plan{} = plan) do
    with {:ok, principal} when not is_nil(principal) <- load_principal(ctx, principal_id),
         {:ok, subject} when not is_nil(subject) <- load_subject(ctx, subject_input),
         {:ok, grant_subject_id} <- resolve_grant_subject_id(ctx, subject) do
      # `maybe_is: false`: an unresolvable `:maybe` policy result must not
      # authorize issuing a decryption grant — fail closed. `run_queries?`
      # (default `true`) still resolves filter checks against the data
      # layer first, so this only changes the answer for checks the
      # authorizer genuinely cannot decide at planning time.
      should_grant? =
        Ash.can?({subject, :read}, principal,
          domain: ctx.domain,
          tenant: ctx.tenant,
          maybe_is: false
        )

      grant_status = grant_status(ctx, grant_subject_id, principal_id)

      cond do
        should_grant? and grant_status != :live ->
          %{
            plan
            | grants: [
                %{
                  principal_id: principal_id,
                  subject: subject,
                  subject_id: grant_subject_id,
                  target: principal
                }
                | plan.grants
              ]
          }

        not should_grant? and grant_status != :absent ->
          %{
            plan
            | revocations: [
                %{principal_id: principal_id, subject_id: grant_subject_id}
                | plan.revocations
              ]
          }

        true ->
          plan
      end
    else
      {:ok, nil} ->
        plan

      :no_grant_subject ->
        plan

      {:error, reason} ->
        %{plan | errors: [{principal_id, reason} | plan.errors]}
    end
  end

  defp load_principal(ctx, principal_id) do
    Ash.get(ctx.user_resource, principal_id,
      domain: ctx.domain,
      tenant: ctx.tenant,
      authorize?: false,
      load: ctx.user_load
    )
  end

  defp load_subject(ctx, %_{} = record) do
    if ctx.subject_load == [] do
      {:ok, record}
    else
      Ash.load(record, ctx.subject_load,
        domain: ctx.domain,
        tenant: ctx.tenant,
        authorize?: false
      )
    end
  end

  defp load_subject(ctx, subject_id) do
    Ash.get(ctx.encrypted_resource, subject_id,
      domain: ctx.domain,
      tenant: ctx.tenant,
      authorize?: false,
      load: ctx.subject_load
    )
  end

  defp resolve_grant_subject_id(%Context{subject_id_for: nil}, subject) do
    {:ok, Map.get(subject, :id)}
  end

  defp resolve_grant_subject_id(%Context{subject_id_for: fun}, subject)
       when is_function(fun, 1) do
    case fun.(subject) do
      nil -> :no_grant_subject
      id -> {:ok, id}
    end
  end

  defp grant_status(ctx, subject_id, principal_id) do
    config = ctx.key_grants_config

    # System-side bookkeeping read: bypass policies on the grants resource.
    # Authorization for the pair was already decided by the planner via
    # `Ash.can?({subject, :read}, principal)` — this read only answers
    # whether a row exists. Honoring `config.authorize?` here meant every
    # nil-actor planner read on a policy-protected grants table came back
    # empty, so stale grants were never planned for revocation.
    config.resource
    |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
    |> Ash.Query.filter(^[{config.principal_id_attribute, principal_id}])
    |> Ash.Query.limit(1)
    |> Ash.read(domain: ctx.domain, tenant: ctx.tenant, authorize?: false)
    |> case do
      {:ok, [grant | _]} -> if expired?(grant, config), do: :expired, else: :live
      _ -> :absent
    end
  end

  # An expired row counts as absent for issuance (`KeyGrants.resolve_for_actor/4`
  # already rejects it, and the documented contract is that reconcile re-issues
  # it while the read policy still authorizes) but as present for revocation
  # (an unauthorized principal's stale row should still be cleaned up).
  defp expired?(_grant, %KeyGrants.Config{expires_at_attribute: nil}), do: false

  defp expired?(grant, %KeyGrants.Config{expires_at_attribute: attr}) do
    case Map.get(grant, attr) do
      %DateTime{} = expires_at -> DateTime.compare(expires_at, DateTime.utc_now()) != :gt
      _ -> false
    end
  end

  # ---- applying ----

  # Each apply-side entry function returns a list of failure tuples
  # (`{principal_id, subject_id, reason}`), empty on success, so
  # `apply_plan!/3` can aggregate them into its return value.

  defp issue_grant_entry(ctx, %{
         subject: subject,
         subject_id: subject_id,
         target: target,
         principal_id: principal_id
       }) do
    destroy_expired_grants(ctx, subject_id, principal_id)

    case Granter.try_chain(ctx, subject, subject_id, target) do
      :ok ->
        []

      :skip ->
        Logger.warning(
          "[AshEnvelope.Reconcile] no granter could issue grant for #{inspect({principal_id, subject_id})}; chain exhausted"
        )

        []

      {:error, reason} ->
        Logger.warning(
          "[AshEnvelope.Reconcile] grant issuance failed for #{inspect({principal_id, subject_id})}: #{inspect(reason)}"
        )

        [{principal_id, subject_id, reason}]
    end
  end

  # The planner counts expired rows as absent, so a grant about to be issued
  # would collide with a stale expired row on the grants table's
  # (subject, principal) unique index. Clear expired rows for the pair first.
  # Same system-side bypass rationale as `revoke_entry/2`: the planner's
  # `Ash.can?` already made the security decision.
  defp destroy_expired_grants(
         %Context{key_grants_config: %KeyGrants.Config{expires_at_attribute: nil}},
         _subject_id,
         _principal_id
       ) do
    :ok
  end

  defp destroy_expired_grants(ctx, subject_id, principal_id) do
    config = ctx.key_grants_config

    stale_query =
      config.resource
      |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
      |> Ash.Query.filter(^[{config.principal_id_attribute, principal_id}])

    case Ash.read(stale_query, domain: ctx.domain, tenant: ctx.tenant, authorize?: false) do
      {:ok, grants} ->
        grants
        |> Enum.filter(&expired?(&1, config))
        |> Enum.each(fn grant ->
          case KeyGrants.revoke(grant, ctx.domain, authorize?: false, tenant: ctx.tenant) do
            :ok ->
              :ok

            {:ok, _} ->
              :ok

            {:error, reason} ->
              Logger.warning(
                "[AshEnvelope.Reconcile] expired-grant cleanup failed for #{inspect({principal_id, subject_id})}: #{inspect(reason)}"
              )
          end
        end)

      {:error, reason} ->
        Logger.warning(
          "[AshEnvelope.Reconcile] expired-grant cleanup read failed for #{inspect({principal_id, subject_id})}: #{inspect(reason)}"
        )
    end

    :ok
  end

  defp revoke_entry(ctx, %{principal_id: principal_id, subject_id: subject_id}) do
    revoke_grants(ctx, principal_id, subject_id) ++
      revoke_pending_requests(ctx, principal_id, subject_id)
  end

  defp revoke_grants(ctx, principal_id, subject_id) do
    config = ctx.key_grants_config

    grant_query =
      config.resource
      |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
      |> Ash.Query.filter(^[{config.principal_id_attribute, principal_id}])

    case Ash.read(grant_query, domain: ctx.domain, tenant: ctx.tenant, authorize?: false) do
      {:ok, grants} ->
        Enum.flat_map(grants, fn grant ->
          # System-side revocation: bypass policies on the grants resource.
          # Authorization for *whether* to revoke was already decided by the
          # planner via `Ash.can?({subject, :read}, principal)`.
          case KeyGrants.revoke(grant, ctx.domain, authorize?: false, tenant: ctx.tenant) do
            :ok ->
              []

            {:ok, _} ->
              []

            {:error, reason} ->
              Logger.warning(
                "[AshEnvelope.Reconcile] revoke failed for #{inspect({principal_id, subject_id})}: #{inspect(reason)}"
              )

              [{principal_id, subject_id, reason}]
          end
        end)

      {:error, reason} ->
        Logger.warning(
          "[AshEnvelope.Reconcile] revoke read failed for #{inspect({principal_id, subject_id})}: #{inspect(reason)}"
        )

        [{principal_id, subject_id, {:revoke_read_failed, reason}}]
    end
  end

  defp revoke_pending_requests(%Context{grant_requests_config: nil}, _principal_id, _subject_id),
    do: []

  defp revoke_pending_requests(ctx, principal_id, subject_id) do
    # Same system-side bypass as the grant revoke above: the planner's
    # `Ash.can?` already decided the target lost access, and a nil-actor
    # policy read on the requests table would silently match nothing.
    case GrantRequests.revoke_pending_for(
           ctx.grant_requests_config,
           subject_id,
           principal_id,
           ctx.domain,
           authorize?: false,
           tenant: ctx.tenant
         ) do
      {:ok, _} ->
        []

      {:error, reason} ->
        Logger.warning(
          "[AshEnvelope.Reconcile] revoke_pending_for failed for #{inspect({principal_id, subject_id})}: #{inspect(reason)}"
        )

        [{principal_id, subject_id, {:revoke_pending_failed, reason}}]
    end
  end
end
