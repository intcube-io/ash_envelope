defmodule AshEnvelope.BlobIO.KeyManagers.KeyGrantsPoliciesTest do
  # The KeyGrants BlobIO manager against a grants resource that carries
  # the policy shape the generator scaffolds, under the manager's default
  # `authorize?: true`. The ephemeral worker paths have no actor and no
  # principal, so they must run system-side: before this was the case,
  # `finalize_wrapped_dek/3` was forbidden on every attach with
  # `expires_at_attribute` configured, and analyzer reads were filtered
  # to `:not_found` by the `user_id == ^actor(:id)` read policy.
  #
  # async: false because the seal key is resolved from Application env.
  use ExUnit.Case, async: false

  alias AshEnvelope.BlobIO.KeyManagers.KeyGrants
  alias AshEnvelope.KeyGrants, as: GrantsAPI
  alias AshEnvelope.Test.BlobIO.PoliciedGrant
  alias AshStorage.BlobIO.BlobContext
  alias AshStorage.BlobIO.Operation.PostCreate
  alias AshStorage.BlobIO.Reader
  alias AshStorage.BlobIO.Writer
  alias AshStorage.Encryption.WriteFinalization

  require Ash.Query

  @domain AshEnvelope.Test.BlobIO.Domain

  setup do
    previous = Application.get_env(:ash_envelope, :seal_key)
    Application.put_env(:ash_envelope, :seal_key, Base.encode64(:crypto.strong_rand_bytes(32)))

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ash_envelope, :seal_key, previous),
        else: Application.delete_env(:ash_envelope, :seal_key)
    end)

    {pub, priv} = AshEnvelope.generate_key_pair()
    actor = %{id: Ash.UUID.generate(), public_key: pub, private_key: priv}

    # No `authorize?:` key — the manager's default (`true`) is under test.
    opts = [
      grants_resource: PoliciedGrant,
      domain: @domain,
      actor_public_key_attribute: :public_key,
      actor_private_key_attribute: :private_key,
      subject_id_attribute: :subject_id,
      expires_at_attribute: :expires_at,
      ephemeral_ttl_seconds: 3600
    ]

    %{actor: actor, opts: opts}
  end

  defp blob(id), do: %{id: id}

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

    {dek, metadata, KeyGrants.finalize_wrapped_dek(metadata, finalization, opts)}
  end

  defp rows(blob_id) do
    PoliciedGrant
    |> Ash.Query.filter(subject_id == ^blob_id)
    |> Ash.read!(domain: @domain, authorize?: false)
  end

  test "attach succeeds although the create policy admits only rows with a principal",
       %{actor: actor, opts: opts} do
    blob_id = Ash.UUID.generate()
    {dek, _metadata, result} = finalize(opts, actor, blob_id)

    assert :ok = result

    # One user grant (policy-checked) and one principal-less ephemeral row.
    assert [_, _] = rows = rows(blob_id)
    assert Enum.any?(rows, &(&1.user_id == actor.id))
    assert Enum.any?(rows, &is_nil(&1.user_id))

    # The ephemeral row holds the same DEK.
    {:ok, config} = KeyGrants.config_from(opts)
    system_config = %{config | authorize?: false}
    assert {:ok, ^dek} = GrantsAPI.resolve_ephemeral(system_config, blob_id, @domain)
  end

  test "analyzer read with actor: nil resolves through the ephemeral row despite the actor-scoped read policy",
       %{actor: actor, opts: opts} do
    blob_id = Ash.UUID.generate()
    {dek, metadata, :ok} = finalize(opts, actor, blob_id)

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

  test "the system-side ephemeral path does not widen to non-analyzer reads",
       %{actor: actor, opts: opts} do
    blob_id = Ash.UUID.generate()
    {_dek, metadata, :ok} = finalize(opts, actor, blob_id)

    download_bctx = BlobContext.new(actor: nil, blob: blob(blob_id), operation: :download)
    read = %Reader.Operation{blob_context: download_bctx}
    assert {:error, :missing_principal} = KeyGrants.unwrap_dek(metadata, read, opts)
  end

  test "the user-grant read still goes through the resource policies",
       %{actor: actor, opts: opts} do
    blob_id = Ash.UUID.generate()
    {_dek, metadata, :ok} = finalize(opts, actor, blob_id)

    {pub, priv} = AshEnvelope.generate_key_pair()
    stranger = %{id: Ash.UUID.generate(), public_key: pub, private_key: priv}

    # A different principal in a download context: policy-scoped user
    # read, no grant row visible, no ephemeral fallback. The exact error
    # shape depends on whether the user-grant read threads the actor into
    # Ash (`:not_found` once it does, a Forbidden error while the policy
    # sees a nil actor); the property locked here is that the DEK never
    # comes back.
    read = %Reader.Operation{
      blob_context: BlobContext.new(actor: stranger, blob: blob(blob_id), operation: :download)
    }

    assert {:error, _} = KeyGrants.unwrap_dek(metadata, read, opts)
  end
end
