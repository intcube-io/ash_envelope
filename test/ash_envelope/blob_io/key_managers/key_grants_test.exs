defmodule AshEnvelope.BlobIO.KeyManagers.KeyGrantsTest do
  # async: false because the ephemeral-grants section toggles
  # Application env (the seal key).
  use ExUnit.Case, async: false

  alias AshEnvelope.BlobIO.KeyManagers.KeyGrants
  alias AshEnvelope.KeyGrants, as: GrantsAPI
  alias AshStorage.BlobIO.BlobContext
  alias AshStorage.BlobIO.Operation.PostCreate
  alias AshStorage.BlobIO.Reader
  alias AshStorage.BlobIO.Writer
  alias AshStorage.Encryption.WriteFinalization

  require Ash.Query

  @domain AshEnvelope.Test.Domain

  setup do
    {pub, priv} = AshEnvelope.generate_key_pair()
    actor = %{id: Ash.UUID.generate(), public_key: pub, private_key: priv}

    opts = [
      grants_resource: AshEnvelope.Test.Grant,
      domain: @domain,
      actor_public_key_attribute: :public_key,
      actor_private_key_attribute: :private_key,
      subject_id_attribute: :subject_id,
      authorize?: false
    ]

    %{actor: actor, opts: opts}
  end

  defp blob(id), do: %{id: id}

  describe "wrap_dek/3 + finalize_wrapped_dek/3" do
    test "writes a grant row that resolve_for_actor can read back", %{actor: actor, opts: opts} do
      dek = AshEnvelope.generate_dek()
      bctx = BlobContext.new(actor: actor)
      blob_id = Ash.UUID.generate()

      assert {:ok, metadata, handoff} =
               KeyGrants.wrap_dek(dek, %Writer.Operation{blob_context: bctx}, opts)

      assert metadata == %{"format" => "ash_envelope_key_grants_v1"}
      assert handoff == %{dek: dek}

      finalization = %WriteFinalization{
        context: %PostCreate{blob_context: bctx, blob: blob(blob_id)},
        layer_metadata_key: "test",
        metadata: %{},
        handoff: handoff
      }

      assert :ok = KeyGrants.finalize_wrapped_dek(metadata, finalization, opts)

      {:ok, config} = KeyGrants.config_from(opts)
      assert {:ok, ^dek} = GrantsAPI.resolve_for_actor(config, blob_id, actor, @domain)
    end
  end

  describe "unwrap_dek/3" do
    test "resolves the DEK for the actor via the grants resource", %{actor: actor, opts: opts} do
      dek = AshEnvelope.generate_dek()
      blob_id = Ash.UUID.generate()
      bctx = BlobContext.new(actor: actor, blob: blob(blob_id))

      {:ok, config} = KeyGrants.config_from(opts)
      :ok = GrantsAPI.create_for_actor(config, blob_id, dek, actor, @domain)

      read = %Reader.Operation{blob_context: bctx}

      assert {:ok, ^dek} =
               KeyGrants.unwrap_dek(%{"format" => "ash_envelope_key_grants_v1"}, read, opts)
    end

    test "returns :not_found when the actor has no grant", %{actor: actor, opts: opts} do
      blob_id = Ash.UUID.generate()
      bctx = BlobContext.new(actor: actor, blob: blob(blob_id))
      read = %Reader.Operation{blob_context: bctx}

      assert {:error, :not_found} =
               KeyGrants.unwrap_dek(%{"format" => "ash_envelope_key_grants_v1"}, read, opts)
    end

    test "rejects metadata in the wrong format", %{actor: actor, opts: opts} do
      bctx = BlobContext.new(actor: actor, blob: blob(Ash.UUID.generate()))
      read = %Reader.Operation{blob_context: bctx}

      assert {:error, {:invalid_key_grants_metadata, "wrapped_dek"}} =
               KeyGrants.unwrap_dek(%{"format" => "cloak"}, read, opts)
    end

    test "honors subject_id_resolver", %{actor: actor, opts: opts} do
      dek = AshEnvelope.generate_dek()
      parent_id = Ash.UUID.generate()
      blob_id = Ash.UUID.generate()
      bctx = BlobContext.new(actor: actor, blob: %{id: blob_id, parent_id: parent_id})

      resolver_opts = Keyword.put(opts, :subject_id_resolver, & &1.blob.parent_id)
      {:ok, config} = KeyGrants.config_from(resolver_opts)
      :ok = GrantsAPI.create_for_actor(config, parent_id, dek, actor, @domain)

      read = %Reader.Operation{blob_context: bctx}

      assert {:ok, ^dek} =
               KeyGrants.unwrap_dek(
                 %{"format" => "ash_envelope_key_grants_v1"},
                 read,
                 resolver_opts
               )
    end
  end

  describe "rewrap_dek/3" do
    test "is a no-op at the blob-metadata layer", %{opts: opts} do
      metadata = %{"format" => "ash_envelope_key_grants_v1"}

      assert {:ok, ^metadata} =
               KeyGrants.rewrap_dek(
                 metadata,
                 %AshStorage.Encryption.RewrapOperation{},
                 opts
               )
    end
  end

  describe "config_from/1" do
    test "requires the grants_resource option", %{opts: opts} do
      assert {:error, {:key_grants_manager_option_required, :grants_resource}} =
               KeyGrants.config_from(Keyword.delete(opts, :grants_resource))
    end

    test "requires actor key attribute options", %{opts: opts} do
      assert {:error, {:key_grants_manager_option_required, :actor_public_key_attribute}} =
               KeyGrants.config_from(Keyword.delete(opts, :actor_public_key_attribute))

      assert {:error, {:key_grants_manager_option_required, :actor_private_key_attribute}} =
               KeyGrants.config_from(Keyword.delete(opts, :actor_private_key_attribute))
    end
  end

  describe "wrap_dek/3 validates the manager options up front" do
    # wrap_dek runs before the service upload and the blob create;
    # finalize runs after both. A misconfiguration must fail the write
    # here, not leave an uploaded ciphertext and a grant-less blob row.
    test "fails without :domain", %{actor: actor, opts: opts} do
      bctx = BlobContext.new(actor: actor)

      assert {:error, {:key_grants_manager_option_required, :domain}} =
               KeyGrants.wrap_dek(
                 AshEnvelope.generate_dek(),
                 %Writer.Operation{blob_context: bctx},
                 Keyword.delete(opts, :domain)
               )
    end

    test "fails without :grants_resource", %{actor: actor, opts: opts} do
      bctx = BlobContext.new(actor: actor)

      assert {:error, {:key_grants_manager_option_required, :grants_resource}} =
               KeyGrants.wrap_dek(
                 AshEnvelope.generate_dek(),
                 %Writer.Operation{blob_context: bctx},
                 Keyword.delete(opts, :grants_resource)
               )
    end

    test "fails on a non-function :subject_id_resolver", %{actor: actor, opts: opts} do
      bctx = BlobContext.new(actor: actor)

      assert {:error, {:invalid_key_grants_subject_id_resolver, :nope}} =
               KeyGrants.wrap_dek(
                 AshEnvelope.generate_dek(),
                 %Writer.Operation{blob_context: bctx},
                 Keyword.put(opts, :subject_id_resolver, :nope)
               )
    end
  end

  describe "with ephemeral worker grant attributes configured" do
    setup %{opts: opts} do
      previous = Application.get_env(:ash_envelope, :seal_key)
      Application.put_env(:ash_envelope, :seal_key, Base.encode64(:crypto.strong_rand_bytes(32)))

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ash_envelope, :seal_key, previous),
          else: Application.delete_env(:ash_envelope, :seal_key)
      end)

      opts =
        opts
        |> Keyword.put(:expires_at_attribute, :expires_at)
        |> Keyword.put(:ephemeral_ttl_seconds, 3600)

      %{opts: opts}
    end

    defp finalize(opts, actor, blob_id) do
      dek = AshEnvelope.generate_dek()
      bctx = BlobContext.new(actor: actor)

      {:ok, metadata, handoff} =
        KeyGrants.wrap_dek(dek, %Writer.Operation{blob_context: bctx}, opts)

      finalization = %WriteFinalization{
        context: %PostCreate{blob_context: bctx, blob: blob(blob_id)},
        layer_metadata_key: "test",
        metadata: %{},
        handoff: handoff
      }

      :ok = KeyGrants.finalize_wrapped_dek(metadata, finalization, opts)
      {dek, metadata}
    end

    test "finalize_wrapped_dek creates a user grant AND an ephemeral row", %{
      actor: actor,
      opts: opts
    } do
      blob_id = Ash.UUID.generate()
      {dek, _metadata} = finalize(opts, actor, blob_id)

      {:ok, config} = KeyGrants.config_from(opts)
      assert {:ok, ^dek} = GrantsAPI.resolve_for_actor(config, blob_id, actor, @domain)
      assert {:ok, ^dek} = GrantsAPI.resolve_ephemeral(config, blob_id, @domain)
    end

    test "analyzer-context read with actor: nil unwraps via ephemeral", %{
      actor: actor,
      opts: opts
    } do
      blob_id = Ash.UUID.generate()
      {dek, metadata} = finalize(opts, actor, blob_id)

      analyzer_bctx =
        BlobContext.new(
          actor: nil,
          blob: blob(blob_id),
          operation: :analyze,
          analyzer: SomeAnalyzer
        )

      read = %Reader.Operation{blob_context: analyzer_bctx}
      assert {:ok, ^dek} = KeyGrants.unwrap_dek(metadata, read, opts)
    end

    test "download-context read with actor: nil still fails (no ephemeral fallback)",
         %{actor: actor, opts: opts} do
      blob_id = Ash.UUID.generate()
      {_dek, metadata} = finalize(opts, actor, blob_id)

      download_bctx = BlobContext.new(actor: nil, blob: blob(blob_id), operation: :download)
      read = %Reader.Operation{blob_context: download_bctx}
      assert {:error, :missing_principal} = KeyGrants.unwrap_dek(metadata, read, opts)
    end

    test "analyzer-context read with a user actor goes through the user grant",
         %{actor: actor, opts: opts} do
      blob_id = Ash.UUID.generate()
      {dek, metadata} = finalize(opts, actor, blob_id)

      analyzer_with_actor =
        BlobContext.new(
          actor: actor,
          blob: blob(blob_id),
          operation: :analyze,
          analyzer: SomeAnalyzer
        )

      read = %Reader.Operation{blob_context: analyzer_with_actor}
      assert {:ok, ^dek} = KeyGrants.unwrap_dek(metadata, read, opts)
    end

    test "expired ephemeral row surfaces :expired", %{actor: actor, opts: opts} do
      blob_id = Ash.UUID.generate()
      {_dek, metadata} = finalize(opts, actor, blob_id)

      {:ok, [eph_row]} =
        AshEnvelope.Test.Grant
        |> Ash.Query.filter(subject_id == ^blob_id and is_nil(user_id))
        |> Ash.read(domain: @domain, authorize?: false)

      past = DateTime.add(DateTime.utc_now(), -60, :second)

      {:ok, _} =
        Ash.update(eph_row, %{expires_at: past},
          action: :expire,
          domain: @domain,
          authorize?: false
        )

      analyzer_bctx =
        BlobContext.new(
          actor: nil,
          blob: blob(blob_id),
          operation: :analyze,
          analyzer: SomeAnalyzer
        )

      read = %Reader.Operation{blob_context: analyzer_bctx}
      assert {:error, :expired} = KeyGrants.unwrap_dek(metadata, read, opts)
    end
  end
end
