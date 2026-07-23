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

  Errors are collected per pair into `Plan.errors`, never raised.
  Granter-chain failures during apply are logged and skipped, not
  fatal — wrap in `Ash.transaction/3` yourself if you need stricter
  semantics.
  """

  alias AshEnvelope.{GrantRequests, KeyGrants}
  alias AshEnvelope.Reconcile.{Context, Granter, Plan}

  require Ash.Query
  require Logger

  @doc """
  Convenience: `apply_plan!(ctx, plan(ctx, pairs), opts)`.

  Same defaults as `apply_plan!/3` (`transaction: true`).
  """
  @spec run(Context.t(), [{term(), Ash.Resource.record() | term()}], keyword()) :: :ok
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
            GrantRequests.fulfill(config, grants_config, request, actor, target, ctx.domain)

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
    case Ash.get(ctx.user_resource, target_id, domain: ctx.domain, authorize?: false) do
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
  (`:skip`) are logged at `:warning` and continue with the next
  entry — they don't trigger a rollback unless you wrap an explicit
  raise around them. The transaction guard is there to protect
  against unexpected exceptions inside the apply phase, not to
  enforce all-grants-or-no-grants semantics across granter strategies.

  Returns `:ok` unconditionally.
  """
  @spec apply_plan!(Context.t(), Plan.t(), keyword()) :: :ok
  def apply_plan!(%Context{} = ctx, %Plan{} = plan, opts \\ []) do
    if Plan.empty?(plan) do
      :ok
    else
      do_apply = fn ->
        Enum.each(plan.grants, &issue_grant_entry(ctx, &1))
        Enum.each(plan.revocations, &revoke_entry(ctx, &1))
        :ok
      end

      if Keyword.get(opts, :transaction, true) do
        # Only the grants and grant_requests resources are written here.
        # Excluding `encrypted_resource` avoids requiring it to share a
        # repo/data layer with the grants table — the planner has already
        # finished its reads.
        case Ash.transaction(
               tap_with_requests([ctx.key_grants_config.resource], ctx),
               fn -> do_apply.() end
             ) do
          {:ok, _} ->
            :ok

          {:error, reason} ->
            raise "AshEnvelope.Reconcile.apply_plan!/3 failed: #{inspect(reason)}"
        end
      else
        do_apply.()
      end
    end
  end

  defp tap_with_requests(resources, %Context{grant_requests_config: nil}), do: resources

  defp tap_with_requests(resources, %Context{grant_requests_config: %{resource: r}}),
    do: [r | resources]

  # ---- planning ----

  defp classify_pair(ctx, principal_id, subject_input, %Plan{} = plan) do
    with {:ok, principal} when not is_nil(principal) <- load_principal(ctx, principal_id),
         {:ok, subject} when not is_nil(subject) <- load_subject(ctx, subject_input),
         {:ok, grant_subject_id} <- resolve_grant_subject_id(ctx, subject) do
      should_grant? = Ash.can?({subject, :read}, principal, domain: ctx.domain)
      has_grant? = grant_exists?(ctx, grant_subject_id, principal_id)

      cond do
        should_grant? and not has_grant? ->
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

        not should_grant? and has_grant? ->
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
      authorize?: false,
      load: ctx.user_load
    )
  end

  defp load_subject(ctx, %_{} = record) do
    if ctx.subject_load == [] do
      {:ok, record}
    else
      Ash.load(record, ctx.subject_load, domain: ctx.domain, authorize?: false)
    end
  end

  defp load_subject(ctx, subject_id) do
    Ash.get(ctx.encrypted_resource, subject_id,
      domain: ctx.domain,
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

  defp grant_exists?(ctx, subject_id, principal_id) do
    config = ctx.key_grants_config

    config.resource
    |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
    |> Ash.Query.filter(^[{config.principal_id_attribute, principal_id}])
    |> Ash.Query.limit(1)
    |> Ash.read(domain: ctx.domain, authorize?: config.authorize?)
    |> case do
      {:ok, [_ | _]} -> true
      _ -> false
    end
  end

  # ---- applying ----

  defp issue_grant_entry(ctx, %{
         subject: subject,
         subject_id: subject_id,
         target: target,
         principal_id: principal_id
       }) do
    case Granter.try_chain(ctx, subject, subject_id, target) do
      :ok ->
        :ok

      :skip ->
        Logger.warning(
          "[AshEnvelope.Reconcile] no granter could issue grant for #{inspect({principal_id, subject_id})}; chain exhausted"
        )

        :ok

      {:error, reason} ->
        Logger.warning(
          "[AshEnvelope.Reconcile] grant issuance failed for #{inspect({principal_id, subject_id})}: #{inspect(reason)}"
        )

        :ok
    end
  end

  defp revoke_entry(ctx, %{principal_id: principal_id, subject_id: subject_id}) do
    config = ctx.key_grants_config

    grant_query =
      config.resource
      |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
      |> Ash.Query.filter(^[{config.principal_id_attribute, principal_id}])

    case Ash.read(grant_query, domain: ctx.domain, authorize?: false) do
      {:ok, grants} ->
        Enum.each(grants, fn grant ->
          # System-side revocation: bypass policies on the grants resource.
          # Authorization for *whether* to revoke was already decided by the
          # planner via `Ash.can?({subject, :read}, principal)`.
          case KeyGrants.revoke(grant, ctx.domain, authorize?: false) do
            :ok ->
              :ok

            {:ok, _} ->
              :ok

            {:error, reason} ->
              Logger.warning(
                "[AshEnvelope.Reconcile] revoke failed for #{inspect({principal_id, subject_id})}: #{inspect(reason)}"
              )
          end
        end)

      {:error, reason} ->
        Logger.warning(
          "[AshEnvelope.Reconcile] revoke read failed for #{inspect({principal_id, subject_id})}: #{inspect(reason)}"
        )
    end

    if requests_config = ctx.grant_requests_config do
      case GrantRequests.revoke_pending_for(requests_config, subject_id, principal_id, ctx.domain) do
        {:ok, _} ->
          :ok

        {:error, reason} ->
          Logger.warning(
            "[AshEnvelope.Reconcile] revoke_pending_for failed for #{inspect({principal_id, subject_id})}: #{inspect(reason)}"
          )
      end
    end

    :ok
  end
end
