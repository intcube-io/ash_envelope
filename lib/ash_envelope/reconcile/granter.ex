defmodule AshEnvelope.Reconcile.Granter do
  @moduledoc """
  Granter strategies for `AshEnvelope.Reconcile`.

  Each strategy attempts to issue a `KeyGrants` row for `target` on
  `subject_id`. They return one of:

  - `:ok` — a grant was issued (or queued via a request row).
  - `:skip` — strategy can't help in this case; runner should try the next.
  - `{:error, reason}` — strategy failed terminally for this pair.

  The runner walks the configured chain in order and stops at the first
  `:ok` (or `{:error, _}`).

  ## Built-in strategies

  - `{:dek_from_process, key_for: fun}` — when the encryption pipeline
    has stashed the freshly generated DEK in the process dictionary
    under `{:ash_envelope_dek, storage_key}`, bootstrap a grant for the
    target directly from that DEK. `fun.(subject_record)` must return
    the storage key. Useful for the very first grant on a freshly
    uploaded blob, before any user has a grant to share from.
  - `:actor` — the actor of the triggering changeset must already hold a
    grant on `subject_id` AND have their private key loaded on their
    user struct. Calls `AshEnvelope.KeyGrants.share/5`. Accepts `{:actor, opts}`
    form for `:when` filtering — see below.
  - `:request` — write a pending `GrantRequests` row. Requires the
    encrypted resource's `reconcile do` block to set
    `grant_requests_resource`. Accepts `{:request, opts}` form for
    `:when` filtering.

  ## Conditional strategies via `:when`

  Any tuple-form strategy accepts a `:when` predicate that gates whether
  the strategy fires for a given target principal. When the predicate
  returns false (or anything other than `true`), the chain treats the
  strategy as `:skip` and continues to the next one. Both 1-arity
  (`(target -> boolean)`) and 2-arity (`(target, ctx -> boolean)`)
  predicates are accepted; the 2-arity form is useful when the decision
  depends on the actor or other context fields.

  A common pattern for "request-by-default" reconciliation: limit
  `:actor`-based inline rewraps to recipients the actor knows or owns
  (themselves, the recovery backup), and let everyone else fall through
  to `:request`:

      granter_chain([
        {:dek_from_process, key_for: &storage_key/1, when: &self_or_backup?/2},
        {:actor, when: &self_or_backup?/2},
        :request
      ])

      def self_or_backup?(target, %{actor: %{id: id}}) when not is_nil(id),
        do: target.id == id or target.role == :backup
      def self_or_backup?(_, _), do: false
  """

  alias AshEnvelope.{GrantRequests, KeyGrants}
  alias AshEnvelope.Reconcile.Context

  require Ash.Query

  @type result :: :ok | :skip | {:error, term()}

  @doc """
  Try the configured chain in order. Returns `:ok` on first success,
  `:skip` if every strategy returned `:skip`, or `{:error, reason}` for
  the first strategy that errored terminally.
  """
  @spec try_chain(Context.t(), Ash.Resource.record(), term(), term()) :: result()
  def try_chain(%Context{} = ctx, subject, subject_id, %{} = target) do
    Enum.reduce_while(ctx.granter_chain, :skip, fn strategy, _acc ->
      case maybe_run_strategy(strategy, ctx, subject, subject_id, target) do
        :ok -> {:halt, :ok}
        {:error, _} = err -> {:halt, err}
        :skip -> {:cont, :skip}
      end
    end)
  end

  # `:when` filter — if the strategy carries `when:` opts and the predicate
  # returns false, treat as `:skip` so the chain advances to the next entry.
  defp maybe_run_strategy(strategy, ctx, subject, subject_id, target) do
    if when_allows?(strategy, target, ctx) do
      run_strategy(strategy, ctx, subject, subject_id, target)
    else
      :skip
    end
  end

  defp when_allows?({_name, opts}, target, ctx) when is_list(opts) do
    case Keyword.get(opts, :when) do
      nil -> true
      fun when is_function(fun, 1) -> fun.(target) == true
      fun when is_function(fun, 2) -> fun.(target, ctx) == true
    end
  end

  defp when_allows?(_strategy, _target, _ctx), do: true

  defp run_strategy({:dek_from_process, opts}, ctx, subject, subject_id, target) do
    try_dek_from_process(ctx, subject, subject_id, target, opts)
  end

  defp run_strategy({:actor, opts}, ctx, _subject, subject_id, target) when is_list(opts),
    do: try_actor(ctx, subject_id, target)

  defp run_strategy(:actor, ctx, _subject, subject_id, target),
    do: try_actor(ctx, subject_id, target)

  defp run_strategy({:request, opts}, ctx, _subject, subject_id, target) when is_list(opts),
    do: try_request(ctx, subject_id, target)

  defp run_strategy(:request, ctx, _subject, subject_id, target),
    do: try_request(ctx, subject_id, target)

  defp run_strategy(unknown, _ctx, _subject, _subject_id, _target) do
    {:error, {:unknown_strategy, unknown}}
  end

  # ---- :dek_from_process ----

  defp try_dek_from_process(ctx, subject, subject_id, target, opts) do
    key_fun = Keyword.get(opts, :key_for)

    if is_function(key_fun, 1) do
      case key_fun.(subject) do
        nil ->
          :skip

        storage_key ->
          case Process.get({:ash_envelope_dek, storage_key}) do
            nil ->
              :skip

            raw_dek when is_binary(raw_dek) ->
              KeyGrants.create_for_actor(
                ctx.key_grants_config,
                subject_id,
                raw_dek,
                target,
                ctx.domain
              )
          end
      end
    else
      :skip
    end
  end

  # ---- :actor ----

  defp try_actor(%Context{actor: nil}, _subject_id, _target), do: :skip

  defp try_actor(ctx, subject_id, target) do
    actor = ensure_private_key_loaded(ctx, ctx.actor)

    cond do
      target.id == Map.get(actor, :id) ->
        # Sharing to oneself is a no-op when the actor doesn't yet have a
        # grant — fall through to other strategies (typically :request).
        :skip

      not has_private_key?(actor, ctx.key_grants_config) ->
        :skip

      true ->
        case KeyGrants.share(ctx.key_grants_config, subject_id, actor, target, ctx.domain) do
          :ok -> :ok
          {:error, :not_found} -> :skip
          {:error, _} = err -> err
        end
    end
  end

  # The actor coming in from the changeset may not have the configured
  # private-key calc loaded (typically a cloak-decrypt). Reload before
  # using them as a granter.
  defp ensure_private_key_loaded(_ctx, nil), do: nil

  defp ensure_private_key_loaded(ctx, actor) do
    attr = ctx.key_grants_config.actor_private_key_attribute

    case Map.get(actor, attr) do
      val when is_binary(val) and val != "" -> actor
      _ -> reload_actor(ctx, actor)
    end
  end

  defp reload_actor(ctx, actor) do
    with id when not is_nil(id) <- Map.get(actor, :id),
         {:ok, reloaded} <-
           Ash.get(ctx.user_resource, id,
             domain: ctx.domain,
             authorize?: false,
             load: ctx.user_load
           ) do
      reloaded
    else
      _ -> actor
    end
  end

  # ---- :request ----

  defp try_request(%Context{grant_requests_config: nil}, _subject_id, _target) do
    {:error, :no_grant_requests_resource}
  end

  defp try_request(ctx, subject_id, target) do
    GrantRequests.create(
      ctx.grant_requests_config,
      subject_id,
      target,
      ctx.actor,
      ctx.domain
    )
  end

  # ---- helpers ----

  defp has_private_key?(actor, %{actor_private_key_attribute: attr}) do
    val = Map.get(actor, attr)
    is_binary(val) and byte_size(val) > 0
  end
end
