defmodule AshEnvelope.Reconcile.Changes.SyncPrincipal do
  @moduledoc """
  Ash resource change to install on an "affecting" resource — i.e. one
  whose lifecycle changes who is authorized to read an encrypted
  resource (memberships, role attributes, etc.).

  When the action commits, walks the configured `scope` to enumerate
  subjects in the encrypted resource and reconciles each
  `(this_principal, subject)` pair via `AshEnvelope.Reconcile.Runner`.

  ## Options

  - `:encrypted_resource` *(required)* — the resource declaring the
    `reconcile do` block. Used to look up the runner context, and (in
    lookup form) to find the matching `affects` entry for this resource.
  - `:principal` *(optional)* — name of the FK attribute on this
    resource pointing at the user/principal whose authorization may
    have shifted (e.g. `:user_id` on a membership table, `:id` on the
    user resource itself).
  - `:scope` *(optional)* — either `:all` (every encrypted record) or
    a `(Ash.Changeset.t() -> Ash.Query.t() | keyword() | [term()])` filter.
    A function returning a keyword list filters the encrypted resource; a
    bare list is treated as subject ids. An empty list means "no
    subjects" and the change is a no-op.
  - `:only_when` *(optional)* — `(Ash.Changeset.t() -> boolean())`. When
    it returns `false`, the change is a no-op. Useful for `User.update`
    actions that only matter when a specific attribute changes.

  ## Hook timing

  In `:sync` mode reconciliation runs in `after_transaction`, post-commit
  — the fan-out (policy checks + grant writes) shouldn't hold the
  triggering transaction open. In `:async` mode the scope is resolved and
  the Oban job inserted in `after_action`, *inside* the transaction, so
  the job commits (or rolls back) atomically with the triggering write —
  a crash after commit can't silently drop the reconciliation.

  ## Lookup form (preferred)

  When `:principal`, `:scope`, and `:only_when` are all omitted, the
  change resolves them at runtime from the encrypted resource's
  `affects __MODULE__` entry whose `actions` list includes the action
  being executed. Declare those entries in the encrypted resource's
  `reconcile do` block so the wire-up on the affecting resource is a
  one-liner:

      destroy :destroy do
        change {AshEnvelope.Reconcile.Changes.SyncPrincipal,
                encrypted_resource: MyApp.Document}
      end

  When the encrypted resource has no matching entry for the current
  action, the change is a silent no-op — handy for actions you don't
  want to fire reconciliation on.

  ## Explicit form

  Pass `principal:`/`scope:`/`only_when:` directly to override (or
  bypass) the lookup. Useful when the affecting resource lives outside
  the host's control or when one action wants different semantics than
  the declared `affects` entry:

      destroy :destroy do
        change {AshEnvelope.Reconcile.Changes.SyncPrincipal,
                encrypted_resource: MyApp.Document,
                principal: :user_id,
                scope: fn cs -> [org_id: Ash.Changeset.get_data(cs, :org_id)] end}
      end
  """
  use Ash.Resource.Change

  alias AshEnvelope.Reconcile.{Affects, Info, Mode, Runner}

  require Ash.Query
  require Logger

  @impl true
  def init(opts) do
    if Keyword.has_key?(opts, :encrypted_resource) do
      {:ok, opts}
    else
      {:error,
       "AshEnvelope.Reconcile.Changes.SyncPrincipal: missing required option :encrypted_resource"}
    end
  end

  @impl true
  def change(changeset, opts, _context) do
    encrypted = Keyword.fetch!(opts, :encrypted_resource)

    case Mode.resolve(opts, encrypted) do
      :async ->
        # Enqueue inside the action's transaction (`after_action`) rather
        # than post-commit (`after_transaction`): a crash between commit
        # and `Oban.insert!` would otherwise lose the reconciliation
        # permanently. With the standard setup (Oban sharing the
        # resource's repo) the job row commits atomically with the
        # triggering write; a failed insert rolls the write back.
        Ash.Changeset.after_action(changeset, fn cs, record ->
          maybe_run(cs, opts, {:ok, record})
          {:ok, record}
        end)

      :sync ->
        Ash.Changeset.after_transaction(changeset, fn cs, result ->
          case result do
            {:ok, _} -> maybe_run(cs, opts, result)
            :ok -> maybe_run(cs, opts, result)
            _ -> result
          end
        end)
    end
  end

  defp maybe_run(cs, opts, result) do
    encrypted = Keyword.fetch!(opts, :encrypted_resource)
    action_name = cs.action && cs.action.name

    with {:ok, principal_attr, scope, only_when} <-
           resolve(encrypted, cs.resource, action_name, opts),
         true <- only_when?(cs, only_when) do
      run(cs, encrypted, principal_attr, scope, opts, result)
    else
      _ -> result
    end
  end

  defp resolve(encrypted, affecting_resource, action_name, opts) do
    explicit_principal = Keyword.get(opts, :principal)
    explicit_scope = Keyword.get(opts, :scope)
    explicit_only_when = Keyword.get(opts, :only_when)

    cond do
      explicit_principal && explicit_scope ->
        {:ok, explicit_principal, explicit_scope, explicit_only_when}

      action_name == nil ->
        :no_match

      true ->
        case Info.affects_for_action(encrypted, affecting_resource, action_name) do
          %Affects{} = entry ->
            {:ok, explicit_principal || entry.principal, explicit_scope || entry.scope,
             explicit_only_when || entry.only_when}

          nil ->
            :no_match
        end
    end
  end

  defp only_when?(_cs, nil), do: true
  defp only_when?(cs, fun) when is_function(fun, 1), do: fun.(cs) == true

  defp run(cs, encrypted, principal_attr, scope, opts, result) do
    actor = cs.context[:private][:actor]

    # Reconcile both old and new principal ids. On a `:create` only the
    # changeset attribute exists; on a `:destroy` only the data attribute
    # exists; on an `:update` that reassigns the FK, both differ — and we
    # must reconcile both so the prior holder is revoked AND the new one
    # is granted.
    principal_ids =
      [
        Ash.Changeset.get_data(cs, principal_attr),
        Ash.Changeset.get_attribute(cs, principal_attr)
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    case principal_ids do
      [] ->
        result

      ids ->
        with {:ok, ctx} <- Info.context(encrypted),
             ctx = %{ctx | actor: actor, changeset: cs},
             {:ok, subjects} <- enumerate_subjects(ctx, scope, cs) do
          pairs = for id <- ids, subject <- subjects, do: {id, subject}
          execute(Mode.resolve(opts, encrypted), ctx, pairs, result)
        else
          {:error, reason} ->
            Logger.warning("[AshEnvelope.Reconcile.SyncPrincipal] #{inspect(reason)}")
            result
        end
    end
  end

  defp execute(:sync, ctx, pairs, result) do
    Runner.run(ctx, pairs)
    result
  end

  defp execute(:async, ctx, pairs, result) do
    enqueue_async_jobs(ctx, pairs)
    result
  end

  defp enqueue_async_jobs(_ctx, []), do: :ok

  defp enqueue_async_jobs(ctx, pairs) do
    unless Code.ensure_loaded?(AshEnvelope.Reconcile.AsyncWorker) do
      raise """
      AshEnvelope.Reconcile :async mode requires Oban as a dependency.
      Add `{:oban, "~> 2.18"}` to your mix.exs and configure a queue, or
      switch the resource's `reconcile do mode end` to `:sync`.
      """
    end

    encrypted = ctx.encrypted_resource
    queue = ok_or(Info.reconcile_oban_queue(encrypted), :ash_envelope_reconcile)
    chunk_size = ok_or(Info.reconcile_oban_chunk_size(encrypted), 5000)
    oban_name = ok_or(Info.reconcile_oban_name(encrypted), Oban)
    actor_id = ctx.actor && Map.get(ctx.actor, :id)

    # Pairs may now span multiple principals (e.g. an `:update` that
    # reassigns the FK reconciles both old and new). Group by principal_id
    # so each Oban job carries one principal + its subject ids.
    pairs
    |> Enum.group_by(fn {pid, _} -> pid end, fn {_, subject} -> subject_id(subject) end)
    |> Enum.each(fn {principal_id, subject_ids} ->
      subject_ids
      |> Enum.reject(&is_nil/1)
      |> Enum.chunk_every(chunk_size)
      |> Enum.each(fn chunk ->
        args = %{
          "encrypted_resource" => Atom.to_string(encrypted),
          "principal_id" => principal_id,
          "actor_id" => actor_id,
          "subject_ids" => chunk
        }

        enqueue(args, queue, oban_name)
      end)
    end)

    :ok
  end

  # Scope functions may return loaded records *or* bare subject ids (the
  # `affects` scope docs allow both, and the sync path handles either via
  # `Runner.load_subject/2`). Mirror that here when building job args.
  defp subject_id(subject) when is_map(subject), do: Map.get(subject, :id)
  defp subject_id(id), do: id

  # Test hook: a 2-arity function `(args, queue) -> any` registered under
  # `Application.get_env(:ash_envelope, :reconcile_async_enqueuer)` is
  # called instead of `Oban.insert!/2`. Used by the test suite to capture
  # enqueued jobs without standing up Oban + Postgres. In production this
  # falls through to `Oban.insert!/2` against the instance configured via
  # `reconcile do oban_name end` (default `Oban`).
  defp enqueue(args, queue, oban_name) do
    case Application.get_env(:ash_envelope, :reconcile_async_enqueuer) do
      nil ->
        changeset = AshEnvelope.Reconcile.AsyncWorker.new(args, queue: queue)
        Oban.insert!(oban_name, changeset)

      fun when is_function(fun, 2) ->
        fun.(args, queue)
    end
  end

  defp ok_or({:ok, value}, _default), do: value
  defp ok_or(_, default), do: default

  defp enumerate_subjects(ctx, :all, _cs),
    do: read_subjects(ctx.encrypted_resource, ctx)

  defp enumerate_subjects(ctx, fun, cs) when is_function(fun, 1),
    do: enumerate_filter_result(ctx, fun.(cs))

  defp enumerate_subjects(_ctx, scope, _cs),
    do: {:error, {:unsupported_scope, scope}}

  # `Keyword.keyword?([])` is true, so without this clause an empty list
  # would fall through below as an empty keyword filter and match the
  # ENTIRE table — fanning reconciliation out over every subject. A scope
  # resolving to `[]` means "no subjects": do nothing.
  defp enumerate_filter_result(_ctx, []), do: {:ok, []}

  defp enumerate_filter_result(ctx, list) when is_list(list) do
    if Keyword.keyword?(list) do
      ctx.encrypted_resource
      |> Ash.Query.filter(^list)
      |> read_subjects(ctx)
    else
      {:ok, list}
    end
  end

  defp enumerate_filter_result(ctx, %Ash.Query{} = query),
    do: read_subjects(query, ctx)

  defp enumerate_filter_result(_ctx, other),
    do: {:error, {:invalid_scope_result, other}}

  # Reads the full scope as a stream and materializes it. Crash loudly
  # rather than silently truncating: if a tenant has more subjects than
  # `:reconcile_max_subjects` (default 100k) the operator sees the error
  # and decides whether to raise the cap, narrow the scope, or move to a
  # chunked async strategy.
  defp read_subjects(query_or_resource, ctx) do
    query =
      case query_or_resource do
        %Ash.Query{} = q -> q
        resource -> Ash.Query.new(resource)
      end

    query =
      if ctx.subject_load == [], do: query, else: Ash.Query.load(query, ctx.subject_load)

    max = Application.get_env(:ash_envelope, :reconcile_max_subjects, 100_000)

    try do
      list =
        query
        |> Ash.stream!(domain: ctx.domain, authorize?: false, batch_size: 500)
        |> Enum.take(max + 1)

      if length(list) > max do
        {:error, {:scope_too_large, max}}
      else
        {:ok, list}
      end
    rescue
      e -> {:error, e}
    end
  end
end
