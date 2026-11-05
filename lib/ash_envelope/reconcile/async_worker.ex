if Code.ensure_loaded?(Oban) do
  defmodule AshEnvelope.Reconcile.AsyncWorker do
    @moduledoc """
    Oban worker that runs `AshEnvelope.Reconcile` fan-out off the
    triggering request when the encrypted resource has `mode :async`.

    The trigger (`SyncPrincipal`) resolves the scope to a list of subject
    ids in the request — a single filtered SELECT, fast — and enqueues
    one or more jobs of this worker carrying:

    - `"encrypted_resource"` — module name as string
    - `"principal_id"` — the user/principal whose authorization changed
    - `"actor_id"` — id of the actor that triggered the change (may be
      `nil` when the trigger had no actor; the worker then falls through
      strategies that need actor-side key material)
    - `"subject_ids"` — list of encrypted-resource primary keys
    - `"tenant"` — tenant of the triggering changeset (may be `nil` for
      single-tenant hosts). The trigger serializes it via
      `Ash.ToTenant.to_tenant/2`, so struct tenants (context
      multitenancy) are reduced to their primitive representation before
      enqueue. Hosts using context multitenancy must make sure that
      value survives a JSON round-trip (string/integer) and is accepted
      as a tenant by every resource the runner touches.

    No key material rides in the args. The actor's private key lives in
    the user table (cloak-encrypted at rest); the worker re-decrypts it
    via the configured `:user_load` calc when re-loading the actor by id.
    The cloak vault is a server secret already available to the worker
    process, so no new secret distribution is needed.

    On completion the granter chain has either issued grants
    (`{:actor, when: ...}` or `:dek_from_process` paths) or written
    pending `GrantRequest` rows (`:request` path) for every subject the
    principal is authorized to read.

    Idempotent: `Runner.run/2` checks `grant_exists?` and the request
    table's `is_nil(fulfilled_at)` guard before issuing, so retries skip
    completed pairs.

    Failure handling: when `Runner.run/2` reports that any pair failed
    to apply (a grant issuance or revocation errored), `perform/1`
    returns `{:error, aggregate}` so Oban retries the job with backoff,
    up to `max_attempts: 5`. Combined with idempotency, each retry only
    re-attempts the still-failing pairs. Permanently broken jobs
    (unknown `encrypted_resource` module in the args) are discarded
    instead of retried.
    """
    use Oban.Worker, max_attempts: 5

    alias AshEnvelope.Reconcile.{Info, Runner}

    require Logger

    @impl Oban.Worker
    def perform(%Oban.Job{args: args}) do
      args["encrypted_resource"]
      |> decode_module()
      |> dispatch_perform(args)
    end

    # Deterministic — the encrypted_resource arg is wrong or the module
    # has been removed since enqueue. Discard rather than retry: 5
    # back-off retries won't make a missing module appear.
    defp dispatch_perform({:error, reason}, _args) do
      Logger.warning("[AshEnvelope.Reconcile.AsyncWorker] discarding: #{inspect(reason)}")
      {:discard, reason}
    end

    defp dispatch_perform({:ok, encrypted}, args), do: run_perform(encrypted, args)

    defp run_perform(encrypted, args) do
      # Always succeeds for a resource that compiled: the required
      # `reconcile do` fields are enforced by ValidateConfig.
      {:ok, base_ctx} = Info.context(encrypted)
      # Restore the tenant before loading anything so the actor
      # re-load (and everything the runner does) stays tenant-scoped.
      base_ctx = %{base_ctx | tenant: args["tenant"]}

      actor = load_actor_arg(base_ctx, args["actor_id"])
      principal_id = cast_id(encrypted, args["principal_id"])
      subject_ids = Enum.map(args["subject_ids"] || [], &cast_id(encrypted, &1))

      ctx = %{base_ctx | actor: actor}
      pairs = Enum.map(subject_ids, &{principal_id, &1})
      run_and_report(ctx, pairs)
    end

    defp run_and_report(ctx, pairs) do
      case Runner.run(ctx, pairs) do
        :ok ->
          :ok

        {:error, aggregate} ->
          # Return the aggregate so Oban retries (idempotent — only the
          # still-failing pairs are re-attempted on the next attempt).
          Logger.warning(
            "[AshEnvelope.Reconcile.AsyncWorker] reconcile completed with failures, will retry: #{inspect(aggregate)}"
          )

          {:error, aggregate}
      end
    end

    defp load_actor_arg(_base_ctx, nil), do: nil

    defp load_actor_arg(base_ctx, actor_id),
      do: load_actor(base_ctx, cast_id(base_ctx.user_resource, actor_id))

    defp decode_module(nil), do: {:error, :missing_encrypted_resource}

    defp decode_module(module_name) when is_binary(module_name) do
      {:ok, String.to_existing_atom(module_name)}
    rescue
      ArgumentError -> {:error, {:unknown_module, module_name}}
    end

    # JSON round-trips strings as strings, but resource primary keys may be
    # integers, atoms, or otherwise non-string. Cast the deserialized value
    # back to the resource's PK type so downstream queries don't quietly
    # mis-filter (the Iron Law of Oban).
    defp cast_id(_resource, nil), do: nil

    defp cast_id(resource, value) do
      with [pk_attr] <- Ash.Resource.Info.primary_key(resource),
           %{type: type, constraints: constraints} <-
             Ash.Resource.Info.attribute(resource, pk_attr),
           {:ok, casted} <- Ash.Type.cast_input(type, value, constraints || []) do
        casted
      else
        _ -> value
      end
    end

    defp load_actor(ctx, actor_id) do
      case Ash.get(ctx.user_resource, actor_id,
             domain: ctx.domain,
             tenant: ctx.tenant,
             authorize?: false,
             load: ctx.user_load
           ) do
        {:ok, actor} ->
          actor

        {:error, _} ->
          # Actor was deleted between enqueue and run. Granter chain
          # falls through to `:request` for cross-user pairs and skips
          # actor-self / backup since no actor key is available.
          nil
      end
    end
  end
end
