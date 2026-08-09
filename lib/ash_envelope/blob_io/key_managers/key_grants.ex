if Code.ensure_loaded?(AshStorage.Encryption.KeyManager) do
  defmodule AshEnvelope.BlobIO.KeyManagers.KeyGrants do
    @moduledoc """
    BlobIO key manager that delegates DEK custody to `AshEnvelope.KeyGrants`.

    The wrapped-DEK metadata persisted on the blob is only a pointer at the
    grants table. The wrapped DEK rows live in the grants resource, where
    `AshEnvelope.Reconcile` keeps them in sync with the encrypted resource's
    read policy.

    ## Configuration

        layers [
          {AshStorage.Layer.Encryption,
           layer_id: "documents",
           key_manager:
             {AshEnvelope.BlobIO.KeyManagers.KeyGrants,
              grants_resource: MyApp.DocumentKeyGrant,
              domain: MyApp.Storage,
              actor_public_key_attribute: :public_key,
              actor_private_key_attribute: :private_key}}
        ]

    Options:

      * `:grants_resource` — Ash resource for per-principal wrapped DEKs.
      * `:domain` — Ash domain for grant operations.
      * `:actor_public_key_attribute` — actor attribute holding the X25519
        public key (used to wrap DEKs into grant rows).
      * `:actor_private_key_attribute` — actor attribute holding the X25519
        private key (used to unwrap on read).
      * `:subject_id_attribute` — FK attribute on the grants resource
        pointing at the blob. Defaults to `:blob_id`.
      * `:principal_id_attribute` — FK attribute on the grants resource
        pointing at the principal/user. Defaults to `:user_id`.
      * `:dek_attribute` — attribute storing the wrapped DEK blob on a grant
        row. Defaults to `:wrapped_dek`.
      * `:authorize?` — whether grant create/read run under Ash policies.
        Defaults to `true`.
      * `:subject_id_resolver` — function `(BlobContext.t() -> term())` to
        derive the subject id from the blob context. Defaults to
        `& &1.blob.id`. The blob is guaranteed to be set when this is
        called (writes resolve at the finalization phase, reads after
        Reader loads the blob).
      * `:expires_at_attribute`, `:ephemeral_ttl_seconds` — opt-in
        to per-attach ephemeral worker grants and time-bounded user
        grants. When `:expires_at_attribute` is set, every successful
        write creates **two** rows on the grants resource: the user
        grant (as before) and an ephemeral grant with
        `principal_id IS NULL` whose `dek_attribute` holds the DEK
        sealed under `AshEnvelope.SealKey`. Deferred analyzer reads
        (operation `:analyze` + analyzer module set + no actor)
        resolve through the ephemeral row. See `AshEnvelope.KeyGrants`
        and the `expiring-grants` topic for threat-model and TTL
        guidance.

    ## Rewrap

    `rewrap_dek/3` is a no-op at the blob-metadata layer; the metadata
    only points at the grants table. Per-principal rewraps belong to
    `AshEnvelope.Reconcile`, which runs against the up-to-date read
    policy and the live grants resource.

    ## HTTP serving

    This key manager reads `bctx.actor` to authorize the unwrap; the
    actor must be populated before `BlobIO.read/3` is called. For HTTP
    serving, configure `AshStorage.Plug.Proxy` with `:actor_assign`
    (and a `:max_lifetime_seconds` cap on the signed bearer) — see the
    "Serving encrypted blobs over HTTP" section of
    `how-envelope-encryption-works.md` for the canonical wiring and
    SR31 / SR32 for the threat-model framing.
    """

    @behaviour AshStorage.Encryption.KeyManager

    alias AshEnvelope.BlobIO.Backup
    alias AshEnvelope.KeyGrants
    alias AshStorage.BlobIO.Reader
    alias AshStorage.BlobIO.Writer
    alias AshStorage.Encryption.{RewrapOperation, WriteFinalization}

    @format "ash_envelope_key_grants_v1"

    @impl true
    def wrap_dek(dek, %Writer.Operation{}, _opts) when is_binary(dek) do
      {:ok, %{"format" => @format} |> Backup.put_backup(Backup.wrap_for_backup(dek)), %{dek: dek}}
    end

    @impl true
    def finalize_wrapped_dek(
          %{"format" => @format},
          %WriteFinalization{context: %{blob_context: bctx, blob: blob}, handoff: %{dek: dek}},
          opts
        )
        when is_binary(dek) do
      with {:ok, config} <- config_from(opts),
           {:ok, domain} <- fetch_option(opts, :domain),
           {:ok, subject_id} <- resolve_subject_id(%{bctx | blob: blob}, opts),
           :ok <- KeyGrants.create_for_actor(config, subject_id, dek, bctx.actor, domain) do
        maybe_create_ephemeral(config, subject_id, dek, domain)
      end
    end

    def finalize_wrapped_dek(_wrapped_dek, %WriteFinalization{}, _opts) do
      {:error, {:invalid_key_grants_metadata, "wrapped_dek"}}
    end

    @impl true
    def unwrap_dek(
          %{"format" => @format},
          %Reader.Operation{blob_context: bctx},
          opts
        ) do
      with {:ok, config} <- config_from(opts),
           {:ok, domain} <- fetch_option(opts, :domain),
           {:ok, subject_id} <- resolve_subject_id(bctx, opts) do
        case ephemeral_route(bctx, config) do
          :ephemeral -> KeyGrants.resolve_ephemeral(config, subject_id, domain)
          :user_grant -> KeyGrants.resolve_for_actor(config, subject_id, bctx.actor, domain)
        end
      end
    end

    def unwrap_dek(_wrapped_dek, %Reader.Operation{}, _opts) do
      {:error, {:invalid_key_grants_metadata, "wrapped_dek"}}
    end

    @impl true
    def rewrap_dek(wrapped_dek, %RewrapOperation{}, _opts) do
      # Per-principal rewraps belong to AshEnvelope.Reconcile, not blob metadata.
      {:ok, wrapped_dek}
    end

    @doc false
    def config_from(opts) do
      with {:ok, resource} <- fetch_option(opts, :grants_resource),
           {:ok, pub_attr} <- fetch_option(opts, :actor_public_key_attribute),
           {:ok, priv_attr} <- fetch_option(opts, :actor_private_key_attribute) do
        {:ok,
         AshEnvelope.KeyGrants.Config.from_options(
           resource: resource,
           subject_id_attribute: Keyword.get(opts, :subject_id_attribute),
           actor_public_key_attribute: pub_attr,
           actor_private_key_attribute: priv_attr,
           principal_id_attribute: Keyword.get(opts, :principal_id_attribute),
           dek_attribute: Keyword.get(opts, :dek_attribute),
           authorize?: Keyword.get(opts, :authorize?),
           expires_at_attribute: Keyword.get(opts, :expires_at_attribute),
           ephemeral_ttl_seconds: Keyword.get(opts, :ephemeral_ttl_seconds)
         )}
      end
    end

    defp resolve_subject_id(bctx, opts) do
      case Keyword.get(opts, :subject_id_resolver) do
        nil -> {:ok, bctx.blob.id}
        resolver when is_function(resolver, 1) -> {:ok, resolver.(bctx)}
        other -> {:error, {:invalid_key_grants_subject_id_resolver, other}}
      end
    end

    defp fetch_option(opts, key) do
      case Keyword.fetch(opts, key) do
        {:ok, value} when not is_nil(value) -> {:ok, value}
        _ -> {:error, {:key_grants_manager_option_required, key}}
      end
    end

    # -- Ephemeral worker grant integration --

    defp maybe_create_ephemeral(config, subject_id, dek, domain) do
      if AshEnvelope.KeyGrants.Config.ephemeral_configured?(config) do
        with {:ok, _record} <- KeyGrants.create_ephemeral(config, subject_id, dek, domain) do
          :ok
        end
      else
        :ok
      end
    end

    # Positive discriminator for the ephemeral pathway. All four must hold:
    #   1. ephemeral worker grant attributes are configured on the resource
    #   2. operation is the analyzer pathway
    #   3. an analyzer module is set on the context (analyzer ran us)
    #   4. no user actor is in scope
    #
    # A user-driven read with `actor: nil` (signed-URL controller, etc.)
    # never satisfies (2)+(3), so it still goes through the user-grant
    # path and fails with `:missing_principal` instead of silently
    # unlocking via the ephemeral row.
    defp ephemeral_route(bctx, config) do
      if AshEnvelope.KeyGrants.Config.ephemeral_configured?(config) and
           bctx.operation == :analyze and
           not is_nil(bctx.analyzer) and
           is_nil(bctx.actor) do
        :ephemeral
      else
        :user_grant
      end
    end
  end
end
