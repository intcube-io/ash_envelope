defmodule AshEnvelope.KeyGrants do
  @moduledoc """
  Subject-agnostic envelope encryption key management.

  Provides create/resolve/share/revoke operations against any Ash resource that
  stores per-principal wrapped DEKs. Uses X25519 asymmetric wrapping so that
  sharing only requires the recipient's public key.

  ## Usage

      config = %AshEnvelope.KeyGrants.Config{
        resource: MyApp.KeyGrant,
        subject_id_attribute: :record_id,
        actor_public_key_attribute: :public_key,
        actor_private_key_attribute: :private_key
      }

      # Create a grant (wraps DEK with actor's public key):
      AshEnvelope.KeyGrants.create_for_actor(config, record.id, raw_dek, actor, domain)

      # Resolve a grant (unwraps DEK with actor's private key):
      {:ok, raw_dek} = AshEnvelope.KeyGrants.resolve_for_actor(config, record.id, actor, domain)

      # Share with another user (only needs target's public key):
      AshEnvelope.KeyGrants.share(config, record.id, actor, target_actor, domain)

  ## Time-bounded grants

  Pass `expires_at:` to `create_for_actor/6` to give a principal
  time-bounded access. `resolve_for_actor/4` rejects expired rows as
  `:not_found`. A separate purge job (e.g. an Oban cron) deletes
  expired rows on a cadence — the read policy on the encrypted
  resource remains the source of truth for access (an expired row is
  re-issued by reconcile on its next pass if the policy still
  authorizes the principal).

  Requires `:expires_at_attribute` on the `Config`.

  ## Ephemeral worker grants

  For deferred analyzer pipelines that need to decrypt without a user
  actor in scope, `create_ephemeral/5` writes a row with
  `principal_id IS NULL` whose `dek_attribute` holds the DEK sealed
  directly under `AshEnvelope.SealKey` (AAD = subject id). No
  intermediate keypair — the seal key is symmetric and the worker
  pathway is fully inside the trust domain, so the X25519 wrap used
  for user grants would be overhead. Same `expires_at` column drives
  the TTL purge as for time-bounded user grants.

  `resolve_ephemeral/3` is the read counterpart. `renew_ephemeral/5`
  and `renew_ephemeral_with_actor/5` cover the admin "re-mint a fresh
  ephemeral" flow.

  Requires `:expires_at_attribute` on the `Config` and a configured
  `AshEnvelope.SealKey`.

  ## Authorization actors

  Every call that goes through Ash with `authorize?: true` (the
  `Config` default) threads an actor so the resource's policies are
  evaluated against a real principal, never `nil`:

  * `create_for_actor/6` / `resolve_for_actor/5` — policies see the
    grantee `actor` argument.
  * `share/6` — the granting-side resolve and the grant create run
    with the **calling** (granting) actor; the target-side existence
    check runs with the **target** actor (it reads the target's own
    rows, matching read policies shaped like `user_id == ^actor(:id)`).
  * `revoke/3` — policies see `opts[:actor]` (defaults to `nil`).
  * Ephemeral calls (`create_ephemeral/5`, `resolve_ephemeral/4`,
    `renew_ephemeral/5`) have no natural principal; policies see
    `opts[:actor]` (defaults to `nil`). These are typically system-side
    paths run with `authorize?: false` via the `Config`.
    `renew_ephemeral_with_actor/5` forwards its `actor` argument.

  Every one of these accepts an `opts[:actor]` override when a
  distinct authorization actor is required.
  """

  alias AshEnvelope.KeyGrants.Config
  alias AshEnvelope.SealKey

  import Ash.Expr
  require Ash.Query

  @doc """
  Wrap `raw_dek` with the actor's public key and insert a grant row.

  `opts[:expires_at]` accepts a `DateTime` to make the grant
  time-bounded; requires `Config.expires_at_attribute` to be set.

  **Authorization:** the create runs with `actor` as the Ash actor, so
  policies see the grantee. Pass `opts[:actor]` when a different
  principal should be authorized (e.g. `share/6` creating a grant for
  the target on behalf of the granting caller).

  Returns `:ok` on success or `{:error, reason}` on failure. An actor
  without a usable public key (attribute `nil`, or not a 32-byte key)
  yields `{:error, {:missing_actor_key, attr}}` or
  `{:error, {:invalid_actor_key, attr}}` rather than raising, so batch
  callers (`AshEnvelope.GrantRequests.fulfill_outstanding/5`,
  reconciliation) can count the failure and move on.
  """
  @spec create_for_actor(Config.t(), term(), binary(), term(), module(), keyword()) ::
          :ok | {:error, term()}
  def create_for_actor(%Config{} = config, subject_id, raw_dek, actor, domain, opts \\ []) do
    with pid when not is_nil(pid) <- principal_id(actor),
         {:ok, public_key} <-
           AshEnvelope.fetch_actor_key(actor, config.actor_public_key_attribute) do
      wrapped = raw_dek |> AshEnvelope.wrap_dek(public_key) |> Base.encode64()

      attrs = %{
        config.subject_id_attribute => subject_id,
        config.principal_id_attribute => pid,
        config.dek_attribute => wrapped
      }

      attrs = maybe_put_expires_at(attrs, config, Keyword.get(opts, :expires_at))

      create_result =
        Ash.create(config.resource, attrs,
          domain: domain,
          actor: Keyword.get(opts, :actor, actor),
          authorize?: config.authorize?
        )

      case create_result do
        {:ok, _} -> :ok
        {:error, _} = err -> err
      end
    else
      nil -> {:error, :missing_principal}
      {:error, _} = err -> err
    end
  end

  @doc """
  Look up the actor's grant row and return the unwrapped raw DEK.

  When the grants resource carries an `expires_at_attribute`, rows
  past their deadline are treated as if they don't exist
  (`{:error, :not_found}`).

  **Authorization:** the read runs with `actor` as the Ash actor
  (override via `opts[:actor]`), so actor-scoped read policies
  (`user_id == ^actor(:id)`) see the resolving principal.

  Returns `{:ok, raw_dek}` (32-byte binary) or `{:error, :not_found}`.
  When a live grant exists but the actor carries no usable private key,
  returns `{:error, {:missing_actor_key, attr}}` or
  `{:error, {:invalid_actor_key, attr}}` rather than raising. The key
  check runs after the grant lookup, so an actor loaded with only a
  public key still gets `:not_found` when they hold no grant (this is
  what lets `share/6` accept public-key-only targets).
  """
  @spec resolve_for_actor(Config.t(), term(), term(), module(), keyword()) ::
          {:ok, binary()}
          | {:error,
             :not_found | :corrupted_dek | :decryption_failed | :missing_principal | term()}
  def resolve_for_actor(%Config{} = config, subject_id, actor, domain, opts \\ []) do
    case principal_id(actor) do
      nil ->
        {:error, :missing_principal}

      pid ->
        query =
          config.resource
          |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
          |> Ash.Query.filter(^[{config.principal_id_attribute, pid}])
          |> Ash.Query.select(select_user_grant(config))

        read_opts = [
          domain: domain,
          actor: Keyword.get(opts, :actor, actor),
          authorize?: config.authorize?
        ]

        with {:ok, [grant | _]} <- Ash.read(query, read_opts),
             :ok <- check_not_expired(grant, config),
             {:ok, private_key} <-
               AshEnvelope.fetch_actor_key(actor, config.actor_private_key_attribute),
             {:ok, decoded} <- Base.decode64(Map.get(grant, config.dek_attribute)) do
          AshEnvelope.unwrap_dek(decoded, private_key)
        else
          {:ok, []} -> {:error, :not_found}
          {:error, :expired} -> {:error, :not_found}
          :error -> {:error, :corrupted_dek}
          {:error, _} = err -> err
        end
    end
  end

  @doc """
  Share a DEK with `target_actor`.

  Resolves the granting actor's DEK (needs their private key), then
  re-wraps it for the target (only needs their public key — the
  target's private key is never touched, so a target loaded with only
  their public key is fine). If `target_actor` already has a live
  grant for this subject, returns `:ok` without creating a duplicate;
  the idempotency check is a plain existence read, and a create that
  loses a concurrent race against the grants unique identity is
  recovered as `:ok` after re-checking.

  With `Config.expires_at_attribute` set, an expired-but-unpurged row
  for the target does not block re-sharing: it is purged system-side
  (`authorize?: false`, mirroring the TTL purge job — the row is
  already invisible to every resolve path) before the fresh grant is
  created.

  `opts[:expires_at]` is forwarded to `create_for_actor/6` if the
  target needs a fresh grant.

  **Authorization:** the granting-side resolve and the grant create
  run with the calling `actor` (override the create's actor via
  `opts[:actor]`); the target-side existence check runs with
  `target_actor`, whose own rows it reads.

  Returns `:ok` or `{:error, reason}`.
  """
  @spec share(Config.t(), term(), term(), term(), module(), keyword()) ::
          :ok | {:error, term()}
  def share(%Config{} = config, subject_id, actor, target_actor, domain, opts \\ []) do
    case principal_id(target_actor) do
      nil ->
        {:error, :missing_principal}

      target_id ->
        with {:ok, raw_dek} <- resolve_for_actor(config, subject_id, actor, domain) do
          do_share(config, subject_id, raw_dek, actor, target_actor, target_id, domain, opts)
        end
    end
  end

  defp do_share(config, subject_id, raw_dek, actor, target_actor, target_id, domain, opts) do
    create_opts = Keyword.put_new(opts, :actor, actor)

    case target_grant_active?(config, subject_id, target_actor, domain) do
      {:ok, true} ->
        :ok

      {:ok, false} ->
        with :ok <- purge_expired_grants_for(config, subject_id, target_id, domain) do
          case create_for_actor(config, subject_id, raw_dek, target_actor, domain, create_opts) do
            :ok ->
              :ok

            {:error, _} = err ->
              # A concurrent share may have won the race against the
              # grants unique identity. Re-check before reporting the
              # failure so duplicate-key conflicts surface as :ok.
              case target_grant_active?(config, subject_id, target_actor, domain) do
                {:ok, true} -> :ok
                _ -> err
              end
          end
        end

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Delete a single grant row. Returns `:ok` or `{:error, reason}`.

  **Authorization:** Defaults to `authorize?: true`. The grants resource's
  Ash policies decide whether the caller may revoke. Pass
  `authorize?: false` only for trusted system paths (e.g. reconciliation
  workers running with no actor).
  """
  @spec revoke(Ash.Resource.record(), module(), keyword()) :: :ok | {:error, term()}
  def revoke(grant_record, domain, opts \\ []) do
    actor = Keyword.get(opts, :actor)

    Ash.destroy(grant_record,
      domain: domain,
      actor: actor,
      authorize?: Keyword.get(opts, :authorize?, true)
    )
  end

  # -- Ephemeral worker grants --

  @doc """
  Mint an ephemeral worker grant: seal `raw_dek` directly under
  `AshEnvelope.SealKey` with AAD = subject id, insert a row with
  `principal_id IS NULL` and `expires_at = now + ttl`.

  No keypair — the seal key is symmetric and the worker pathway is
  fully inside the trust domain, so the X25519 wrap used for user
  grants would be overhead. Compromise of the env seal key plus DB
  read recovers the DEK from any live ephemeral row; both the
  current and the previously-deployed keypair design have the same
  property because the keypair's private half would also be sealed
  under the env seal key. The simpler form has one fewer column and
  one fewer crypto operation per read.

  `opts[:expires_at]` overrides the default TTL
  (`config.ephemeral_ttl_seconds` from now).

  **Authorization:** there is no natural principal on this system-side
  path; policies see `opts[:actor]` (defaults to `nil`).

  Raises `ArgumentError` if the config doesn't have
  `:expires_at_attribute` set.
  """
  @spec create_ephemeral(Config.t(), term(), binary(), module(), keyword()) ::
          {:ok, Ash.Resource.record()} | {:error, term()}
  def create_ephemeral(%Config{} = config, subject_id, raw_dek, domain, opts \\ [])
      when byte_size(raw_dek) == 32 do
    require_ephemeral!(config)

    with {:ok, sealed} <- SealKey.seal(raw_dek, context: to_string(subject_id)) do
      insert_ephemeral(config, subject_id, sealed, domain, opts)
    end
  end

  defp insert_ephemeral(%Config{} = config, subject_id, sealed, domain, opts) do
    expires_at =
      Keyword.get(
        opts,
        :expires_at,
        DateTime.add(DateTime.utc_now(), config.ephemeral_ttl_seconds, :second)
      )

    attrs = %{
      config.subject_id_attribute => subject_id,
      config.dek_attribute => Base.encode64(sealed),
      config.expires_at_attribute => expires_at
    }

    Ash.create(config.resource, attrs,
      domain: domain,
      actor: Keyword.get(opts, :actor),
      authorize?: config.authorize?
    )
  end

  @doc """
  Resolve the ephemeral row for `subject_id`, validate TTL, and
  unseal the stored DEK.

  Returns `{:ok, raw_dek}` (32-byte binary) or:

  * `{:error, :not_found}` — no ephemeral row for this subject
  * `{:error, :expired}` — row past `expires_at`
  * `{:error, :decryption_failed}` — sealed value can't be opened
    (wrong seal key, AAD mismatch, tampered bytes)
  * `{:error, :corrupted_dek}` — stored sealed value isn't valid
    base64

  **Authorization:** there is no natural principal on this system-side
  path; policies see `opts[:actor]` (defaults to `nil`).
  """
  @spec resolve_ephemeral(Config.t(), term(), module(), keyword()) ::
          {:ok, binary()}
          | {:error, :not_found | :expired | :corrupted_dek | :decryption_failed | term()}
  def resolve_ephemeral(%Config{} = config, subject_id, domain, opts \\ []) do
    require_ephemeral!(config)

    principal_ref = ref(config.principal_id_attribute)

    query =
      config.resource
      |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
      |> Ash.Query.filter(is_nil(^principal_ref))
      |> Ash.Query.limit(1)

    read_opts = [
      domain: domain,
      actor: Keyword.get(opts, :actor),
      authorize?: config.authorize?
    ]

    with {:ok, [row | _]} <- Ash.read(query, read_opts),
         :ok <- check_not_expired(row, config),
         {:ok, sealed} <- decode_base64(Map.get(row, config.dek_attribute)) do
      SealKey.unseal(sealed, context: to_string(subject_id))
    else
      {:ok, []} -> {:error, :not_found}
      {:error, _} = err -> err
    end
  end

  @doc """
  Replace the ephemeral row for `subject_id` with a freshly minted
  one (fresh seal of the DEK, new TTL).

  Lower-level than `renew_ephemeral_with_actor/5`. The caller is
  responsible for supplying the correct `raw_dek` — this function has
  no oracle to verify it. Passing the wrong bytes destroys the
  legitimate row and inserts an unusable one; the worker pathway then
  surfaces `:decryption_failed` until someone calls `renew_ephemeral`
  again with the correct DEK. User reads via grants are unaffected
  regardless. Prefer `renew_ephemeral_with_actor/5` whenever a user
  actor exists; use this function for disaster-recovery flows that
  obtain `raw_dek` via `AshEnvelope.recover_dek/2`.

  `opts[:expires_at]` overrides the default TTL.

  Idempotent against missing rows: if no row exists for `subject_id`,
  `renew_ephemeral/5` simply creates one.

  The replacement DEK is sealed *before* the existing row is touched,
  so a seal failure (missing/invalid seal key) leaves the current
  ephemeral row intact. The scaffolded one-ephemeral-per-subject
  unique index rules out insert-before-destroy, so if the insert of
  the replacement fails after the destroy, the previous row is
  restored best-effort and the insert error is returned.

  **Authorization:** there is no natural principal on this system-side
  path; policies see `opts[:actor]` (defaults to `nil`).
  """
  @spec renew_ephemeral(Config.t(), term(), binary(), module(), keyword()) ::
          {:ok, Ash.Resource.record()} | {:error, term()}
  def renew_ephemeral(%Config{} = config, subject_id, raw_dek, domain, opts \\ [])
      when byte_size(raw_dek) == 32 do
    require_ephemeral!(config)

    with {:ok, sealed} <- SealKey.seal(raw_dek, context: to_string(subject_id)),
         {:ok, previous} <- fetch_ephemeral_row(config, subject_id, domain, opts),
         :ok <- destroy_ephemeral_for_subject(config, subject_id, domain, opts) do
      case insert_ephemeral(config, subject_id, sealed, domain, opts) do
        {:ok, _} = ok ->
          ok

        {:error, _} = err ->
          restore_ephemeral_row(config, previous, domain, opts)
          err
      end
    end
  end

  @doc """
  Re-run-safe variant of `renew_ephemeral/5` that takes an `actor`
  and proves authority before touching anything.

  This is the **primary admin API** for re-minting an ephemeral grant
  after the TTL window. It unwraps the DEK via the actor's user
  grant and only then destroys-and-recreates the ephemeral row. If
  the actor has no user grant, the wrong private key, or any other
  reason the unwrap fails, the existing ephemeral row is not touched.

  Use `renew_ephemeral/5` directly only when the DEK is obtained
  through a non-user-grant path (e.g. backup-key recovery via
  `AshEnvelope.recover_dek/2`).

  **Authorization:** policies see `actor` for the grant resolve and
  for the ephemeral destroy/create (override the latter via
  `opts[:actor]`).
  """
  @spec renew_ephemeral_with_actor(Config.t(), term(), term(), module(), keyword()) ::
          {:ok, Ash.Resource.record()} | {:error, term()}
  def renew_ephemeral_with_actor(%Config{} = config, subject_id, actor, domain, opts \\ []) do
    with {:ok, dek} <- resolve_for_actor(config, subject_id, actor, domain) do
      renew_ephemeral(config, subject_id, dek, domain, Keyword.put_new(opts, :actor, actor))
    end
  end

  # -- Internal helpers --

  defp principal_id(actor) when is_map(actor), do: Map.get(actor, :id)
  defp principal_id(nil), do: nil

  defp select_user_grant(%Config{expires_at_attribute: nil} = config) do
    [config.dek_attribute]
  end

  defp select_user_grant(%Config{} = config) do
    [config.dek_attribute, config.expires_at_attribute]
  end

  defp check_not_expired(_row, %Config{expires_at_attribute: nil}), do: :ok

  defp check_not_expired(row, %Config{expires_at_attribute: attr}) do
    case Map.get(row, attr) do
      nil ->
        :ok

      %DateTime{} = expires_at ->
        if DateTime.compare(expires_at, DateTime.utc_now()) == :gt do
          :ok
        else
          {:error, :expired}
        end
    end
  end

  defp maybe_put_expires_at(attrs, _config, nil), do: attrs

  defp maybe_put_expires_at(_attrs, %Config{expires_at_attribute: nil}, _expires_at) do
    raise ArgumentError,
          "expires_at supplied but #{inspect(Config)}.expires_at_attribute is not configured"
  end

  defp maybe_put_expires_at(attrs, %Config{expires_at_attribute: attr}, expires_at) do
    Map.put(attrs, attr, expires_at)
  end

  defp decode_base64(value) when is_binary(value) do
    case Base.decode64(value) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :corrupted_dek}
    end
  end

  defp decode_base64(_), do: {:error, :corrupted_dek}

  # Expiry-aware existence read for the target's grant on a subject.
  # Runs with the target as the Ash actor (it reads the target's own
  # rows) and never needs the target's private key, so it stays safe
  # for targets loaded with only their public key.
  defp target_grant_active?(%Config{} = config, subject_id, target_actor, domain) do
    query =
      config.resource
      |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
      |> Ash.Query.filter(^[{config.principal_id_attribute, principal_id(target_actor)}])
      |> Ash.Query.select(select_grant_existence(config))

    case Ash.read(query, domain: domain, actor: target_actor, authorize?: config.authorize?) do
      {:ok, rows} -> {:ok, Enum.any?(rows, &(check_not_expired(&1, config) == :ok))}
      {:error, _} = err -> err
    end
  end

  defp select_grant_existence(%Config{expires_at_attribute: nil} = config) do
    [config.subject_id_attribute]
  end

  defp select_grant_existence(%Config{} = config) do
    [config.expires_at_attribute]
  end

  # Expired rows are semantically nonexistent — every resolve path
  # already treats them as :not_found and scaffolded read policies
  # filter them out. Purging them here mirrors the system-side TTL
  # purge job (hence authorize?: false) and keeps re-sharing from
  # colliding with the scaffolded (subject, user_id) unique index.
  defp purge_expired_grants_for(%Config{expires_at_attribute: nil}, _subject_id, _pid, _domain) do
    :ok
  end

  defp purge_expired_grants_for(%Config{} = config, subject_id, target_id, domain) do
    expires_ref = ref(config.expires_at_attribute)

    config.resource
    |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
    |> Ash.Query.filter(^[{config.principal_id_attribute, target_id}])
    |> Ash.Query.filter(not is_nil(^expires_ref) and ^expires_ref <= ^DateTime.utc_now())
    |> Ash.bulk_destroy(
      :destroy,
      %{},
      domain: domain,
      authorize?: false,
      return_errors?: true,
      strategy: [:atomic, :stream]
    )
    |> case do
      %Ash.BulkResult{status: :success} -> :ok
      %Ash.BulkResult{status: :error, errors: errors} -> {:error, errors}
    end
  end

  defp fetch_ephemeral_row(%Config{} = config, subject_id, domain, opts) do
    principal_ref = ref(config.principal_id_attribute)

    query =
      config.resource
      |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
      |> Ash.Query.filter(is_nil(^principal_ref))
      |> Ash.Query.limit(1)

    read_opts = [
      domain: domain,
      actor: Keyword.get(opts, :actor),
      authorize?: config.authorize?
    ]

    case Ash.read(query, read_opts) do
      {:ok, [row | _]} -> {:ok, row}
      {:ok, []} -> {:ok, nil}
      {:error, _} = err -> err
    end
  end

  # Best-effort undo when the replacement insert fails after the old
  # ephemeral row was destroyed: put the previous sealed value and
  # expiry back so renewal never degrades into pure revocation.
  defp restore_ephemeral_row(_config, nil, _domain, _opts), do: :ok

  defp restore_ephemeral_row(%Config{} = config, previous, domain, opts) do
    attrs = %{
      config.subject_id_attribute => Map.get(previous, config.subject_id_attribute),
      config.dek_attribute => Map.get(previous, config.dek_attribute),
      config.expires_at_attribute => Map.get(previous, config.expires_at_attribute)
    }

    Ash.create(config.resource, attrs,
      domain: domain,
      actor: Keyword.get(opts, :actor),
      authorize?: config.authorize?
    )

    :ok
  end

  defp destroy_ephemeral_for_subject(%Config{} = config, subject_id, domain, opts) do
    principal_ref = ref(config.principal_id_attribute)

    config.resource
    |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
    |> Ash.Query.filter(is_nil(^principal_ref))
    |> Ash.bulk_destroy(
      :destroy,
      %{},
      domain: domain,
      actor: Keyword.get(opts, :actor),
      authorize?: config.authorize?,
      return_errors?: true,
      strategy: [:atomic, :stream]
    )
    |> case do
      %Ash.BulkResult{status: :success} -> :ok
      %Ash.BulkResult{status: :error, errors: errors} -> {:error, errors}
    end
  end

  defp require_ephemeral!(%Config{} = config) do
    if Config.ephemeral_configured?(config) do
      :ok
    else
      raise ArgumentError,
            "expiring-grant attributes are not configured. Set :expires_at_attribute " <>
              "on AshEnvelope.KeyGrants.Config to enable ephemeral worker grants."
    end
  end
end
