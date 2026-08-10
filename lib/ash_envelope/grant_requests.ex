defmodule AshEnvelope.GrantRequests do
  @moduledoc """
  Pending grant requests for envelope encryption.

  Sibling primitive to `AshEnvelope.KeyGrants`. A grant request captures
  "this principal *should* have a grant on this subject, but the actor
  who triggered the authorization-changing event couldn't issue it."

  Typical flow:

  1. A reconciliation step (often `AshEnvelope.Reconcile`) decides that
     `target_user` should have read access to `subject_id` but the current
     `actor` either doesn't hold a grant on the subject or has no usable
     private key on hand. `create/5` writes a pending request.

  2. Later, an actor who *does* hold a grant comes online (admin opening
     a UI panel, login hook calling `fulfill_outstanding/5`, etc.). The
     pending request is matched against that actor's grants and fulfilled
     by re-wrapping the DEK to the target.

  3. Once fulfilled, the request row is marked with `fulfilled_at` and
     `fulfilled_by` and is no longer surfaced as pending.

  Concurrent fulfillment is safe: `fulfill/5` only flips a row whose
  `fulfilled_at` is still `nil`, so two simultaneous fulfillers will at
  worst race on the underlying grant create (which is itself idempotent
  via the `KeyGrants` unique identity).

  ## Usage

      requests_config = %AshEnvelope.GrantRequests.Config{
        resource: MyApp.GrantRequest,
        subject_id_attribute: :blob_id
      }

      key_grants_config = %AshEnvelope.KeyGrants.Config{
        resource: MyApp.KeyGrant,
        subject_id_attribute: :blob_id,
        actor_public_key_attribute: :encryption_public_key,
        actor_private_key_attribute: :encryption_private_key
      }

      # Queue a request when the current actor can't grant directly:
      AshEnvelope.GrantRequests.create(
        requests_config,
        blob_id,
        target_user,
        requesting_actor,
        MyApp.Domain
      )

      # Later, on a logged-in actor with grants, fulfill what they can:
      AshEnvelope.GrantRequests.fulfill_outstanding(
        requests_config,
        key_grants_config,
        actor,
        MyApp.Domain
      )
  """

  alias AshEnvelope.GrantRequests.Config
  alias AshEnvelope.KeyGrants

  import Ash.Expr, only: [ref: 1]

  require Ash.Query

  @doc """
  Create a pending grant request for `target_actor` on `subject_id`.

  Idempotent against the `(subject_id, target_principal_id, where pending)`
  identity: if an unfulfilled request already exists for the same target
  and subject, returns `:ok` without creating a duplicate.

  `requested_by_actor` may be `nil`.

  Returns `:ok` on success, `{:error, reason}` otherwise.
  """
  @spec create(Config.t(), term(), term(), term() | nil, module(), keyword()) ::
          :ok | {:error, term()}
  def create(%Config{} = config, subject_id, target_actor, requested_by_actor, domain, opts \\ []) do
    case principal_id(target_actor) do
      nil ->
        {:error, :missing_target_principal}

      target_id ->
        do_create(config, subject_id, target_id, requested_by_actor, domain, opts)
    end
  end

  defp do_create(config, subject_id, target_id, requested_by_actor, domain, opts) do
    case lookup_pending(config, subject_id, target_id, domain) do
      {:ok, %_{}} ->
        :ok

      {:ok, nil} ->
        attrs = %{
          config.subject_id_attribute => subject_id,
          config.target_principal_id_attribute => target_id,
          config.requested_by_attribute => principal_id(requested_by_actor),
          config.requested_at_attribute => DateTime.utc_now()
        }

        attrs =
          case Keyword.get(opts, :reason) do
            nil -> attrs
            reason -> Map.put(attrs, config.reason_attribute, reason)
          end

        case Ash.create(config.resource, attrs, domain: domain, authorize?: config.authorize?) do
          {:ok, _} ->
            :ok

          {:error, _} = err ->
            # A concurrent create may have won the race against the
            # `unique_pending` identity. Re-check before reporting the
            # failure so duplicate-key conflicts surface as :ok (idempotent).
            case lookup_pending(config, subject_id, target_id, domain) do
              {:ok, %_{}} -> :ok
              _ -> err
            end
        end

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Return all unfulfilled requests for `subject_id`.
  """
  @spec list_pending_for_subject(Config.t(), term(), module(), keyword()) ::
          {:ok, [Ash.Resource.record()]} | {:error, term()}
  def list_pending_for_subject(%Config{} = config, subject_id, domain, _opts \\ []) do
    config.resource
    |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
    |> filter_pending(config)
    |> Ash.read(domain: domain, authorize?: config.authorize?)
  end

  @doc """
  Return all unfulfilled requests `actor` could fulfill — i.e. requests
  whose subject the actor already holds a `KeyGrant` for.

  Loads the actor's grants first, then narrows the pending-request query
  to the matching subject ids in the database (rather than reading every
  pending row into memory). Cheap when the actor holds a bounded number
  of grants.
  """
  @spec list_fulfillable_for(Config.t(), KeyGrants.Config.t(), term(), module()) ::
          {:ok, [Ash.Resource.record()]} | {:error, term()}
  def list_fulfillable_for(
        %Config{} = config,
        %KeyGrants.Config{} = grants_config,
        actor,
        domain
      ) do
    case principal_id(actor) do
      nil ->
        {:error, :missing_principal}

      actor_id ->
        do_list_fulfillable_for(config, grants_config, actor_id, domain)
    end
  end

  defp do_list_fulfillable_for(config, grants_config, actor_id, domain) do
    with {:ok, grants} <- list_actor_grants(grants_config, actor_id, domain) do
      actor_subject_ids =
        grants
        |> Enum.map(&Map.get(&1, grants_config.subject_id_attribute))
        |> Enum.uniq()

      case actor_subject_ids do
        [] ->
          {:ok, []}

        ids ->
          subject_attr = config.subject_id_attribute
          target_attr = config.target_principal_id_attribute

          query =
            config.resource
            |> Ash.Query.filter(^[{subject_attr, [in: ids]}])
            |> Ash.Query.filter(^[{target_attr, [not_eq: actor_id]}])
            |> filter_pending(config)

          Ash.read(query, domain: domain, authorize?: config.authorize?)
      end
    end
  end

  @doc """
  Fulfill a single pending request: re-wrap the DEK from `actor` to the
  request's target user via `KeyGrants.share/5`, then mark the row
  fulfilled.

  Caller is responsible for loading `target_actor` (target principal +
  their public key). The request row carries the target id; this function
  does not load it.

  Concurrent fulfillment is safe: the update conditions on
  `is_nil(fulfilled_at)`, so a second fulfiller simply gets `:ok`.

  Returns `:ok` on success or `{:error, reason}` otherwise.
  """
  @spec fulfill(
          Config.t(),
          KeyGrants.Config.t(),
          Ash.Resource.record(),
          term(),
          term(),
          module()
        ) ::
          :ok | {:error, term()}
  def fulfill(
        %Config{} = config,
        %KeyGrants.Config{} = grants_config,
        request,
        actor,
        target_actor,
        domain
      ) do
    if Map.get(request, config.fulfilled_at_attribute) do
      :ok
    else
      subject_id = Map.get(request, config.subject_id_attribute)

      with :ok <- KeyGrants.share(grants_config, subject_id, actor, target_actor, domain),
           {:ok, fresh} <-
             Ash.get(config.resource, request.id, domain: domain, authorize?: config.authorize?),
           :ok <- ensure_pending(fresh, config) do
        attrs = %{
          config.fulfilled_at_attribute => DateTime.utc_now(),
          config.fulfilled_by_attribute => principal_id(actor)
        }

        case Ash.update(fresh, attrs, domain: domain, authorize?: config.authorize?) do
          {:ok, _} -> :ok
          {:error, _} = err -> err
        end
      else
        # `share/5` succeeded but a concurrent fulfiller already flipped the
        # request — both outcomes are equivalent from the caller's POV.
        :already_fulfilled -> :ok
        {:error, _} = err -> err
      end
    end
  end

  defp ensure_pending(record, config) do
    case Map.get(record, config.fulfilled_at_attribute) do
      nil -> :ok
      _ -> :already_fulfilled
    end
  end

  @doc """
  For every pending request `actor` can fulfill, load the target principal
  via `target_loader` and call `fulfill/6`. Returns `{ok_count, error_count}`.

  `target_loader` is `(target_principal_id -> {:ok, target_actor} | {:error, _})`
  — typically `&Ash.get(MyApp.User, &1, authorize?: false, load: [:public_key])`.
  """
  @spec fulfill_outstanding(
          Config.t(),
          KeyGrants.Config.t(),
          term(),
          module(),
          (term() -> {:ok, term()} | {:error, term()})
        ) ::
          {non_neg_integer(), non_neg_integer()}
  def fulfill_outstanding(
        %Config{} = config,
        %KeyGrants.Config{} = grants_config,
        actor,
        domain,
        target_loader
      )
      when is_function(target_loader, 1) do
    case list_fulfillable_for(config, grants_config, actor, domain) do
      {:ok, requests} ->
        Enum.reduce(requests, {0, 0}, fn request, {ok, err} ->
          target_id = Map.get(request, config.target_principal_id_attribute)

          case target_loader.(target_id) do
            {:ok, target_actor} ->
              case fulfill(config, grants_config, request, actor, target_actor, domain) do
                :ok -> {ok + 1, err}
                {:error, _} -> {ok, err + 1}
              end

            {:error, _} ->
              {ok, err + 1}
          end
        end)

      {:error, reason} ->
        require Logger

        Logger.warning(
          "AshEnvelope.GrantRequests.fulfill_outstanding/5 failed: #{inspect(reason)}"
        )

        {0, 0}
    end
  end

  @doc """
  Drop unfulfilled grant requests for `(subject_id, target_principal_id)`.

  Used by reconciliation when a target loses authorization on a subject —
  any pending request for them on that subject is no longer relevant.

  `opts[:authorize?]` overrides `config.authorize?` for the read and the
  destroys. Trusted system paths (e.g. the reconcile runner, which has
  already made the authorization decision and runs without an actor) pass
  `authorize?: false`.
  """
  @spec revoke_pending_for(Config.t(), term(), term(), module(), keyword()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def revoke_pending_for(%Config{} = config, subject_id, target_id, domain, opts \\ []) do
    authorize? = Keyword.get(opts, :authorize?, config.authorize?)

    config.resource
    |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
    |> Ash.Query.filter(^[{config.target_principal_id_attribute, target_id}])
    |> filter_pending(config)
    |> Ash.read(domain: domain, authorize?: authorize?)
    |> case do
      {:ok, requests} ->
        Enum.reduce(requests, {:ok, 0}, fn req, {:ok, count} ->
          case Ash.destroy(req, domain: domain, authorize?: authorize?) do
            :ok -> {:ok, count + 1}
            {:ok, _} -> {:ok, count + 1}
            {:error, _} = err -> err
          end
        end)

      {:error, _} = err ->
        err
    end
  end

  # ---- private ----

  defp lookup_pending(config, subject_id, target_id, domain) do
    config.resource
    |> Ash.Query.filter(^[{config.subject_id_attribute, subject_id}])
    |> Ash.Query.filter(^[{config.target_principal_id_attribute, target_id}])
    |> filter_pending(config)
    |> Ash.Query.limit(1)
    |> Ash.read(domain: domain, authorize?: config.authorize?)
    |> case do
      {:ok, [row | _]} -> {:ok, row}
      {:ok, []} -> {:ok, nil}
      {:error, _} = err -> err
    end
  end

  defp list_actor_grants(grants_config, actor_id, domain) do
    grants_config.resource
    |> Ash.Query.filter(^[{grants_config.principal_id_attribute, actor_id}])
    |> Ash.Query.select([grants_config.subject_id_attribute])
    |> Ash.read(domain: domain, authorize?: grants_config.authorize?)
  end

  defp filter_pending(query, config) do
    attr = config.fulfilled_at_attribute
    Ash.Query.filter(query, is_nil(^ref(attr)))
  end

  defp principal_id(nil), do: nil
  defp principal_id(actor), do: Map.get(actor, :id)
end
