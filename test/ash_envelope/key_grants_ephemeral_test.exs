defmodule AshEnvelope.KeyGrantsEphemeralTest do
  # async: false because the ephemeral pathway resolves the seal key
  # through `Application.get_env(:ash_envelope, :seal_key)` inside
  # `AshEnvelope.KeyGrants`, so these tests must mutate global app env.
  # Keeping them in their own synchronous module prevents races with
  # async suites; the rest of the KeyGrants surface stays async in
  # `AshEnvelope.KeyGrantsTest`.
  use ExUnit.Case, async: false

  alias AshEnvelope.KeyGrants
  alias AshEnvelope.KeyGrants.Config

  require Ash.Query

  @domain AshEnvelope.Test.Domain

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
    dek = AshEnvelope.generate_dek()
    subject_id = Ash.UUID.generate()

    config = %Config{
      resource: AshEnvelope.Test.Grant,
      subject_id_attribute: :subject_id,
      actor_public_key_attribute: :public_key,
      actor_private_key_attribute: :private_key,
      expires_at_attribute: :expires_at,
      ephemeral_ttl_seconds: 3600
    }

    %{config: config, actor: actor, dek: dek, subject_id: subject_id}
  end

  describe "ephemeral worker grants" do
    test "create_ephemeral + resolve_ephemeral round-trips the DEK", ctx do
      {:ok, _row} = KeyGrants.create_ephemeral(ctx.config, ctx.subject_id, ctx.dek, @domain)
      assert {:ok, dek} = KeyGrants.resolve_ephemeral(ctx.config, ctx.subject_id, @domain)
      assert dek == ctx.dek
    end

    test "resolve_ephemeral returns :not_found when no row exists", ctx do
      assert {:error, :not_found} =
               KeyGrants.resolve_ephemeral(ctx.config, ctx.subject_id, @domain)
    end

    test "resolve_ephemeral returns :expired past the TTL", ctx do
      {:ok, row} = KeyGrants.create_ephemeral(ctx.config, ctx.subject_id, ctx.dek, @domain)
      past = DateTime.add(DateTime.utc_now(), -60, :second)

      {:ok, _} =
        Ash.update(row, %{expires_at: past}, action: :expire, domain: @domain, authorize?: false)

      assert {:error, :expired} =
               KeyGrants.resolve_ephemeral(ctx.config, ctx.subject_id, @domain)
    end

    test "an ephemeral row is invisible to resolve_for_actor", ctx do
      {:ok, _row} = KeyGrants.create_ephemeral(ctx.config, ctx.subject_id, ctx.dek, @domain)

      # Actor has no user grant; only an ephemeral exists for this subject.
      assert {:error, :not_found} =
               KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)
    end

    test "user grants and ephemeral grants coexist for the same subject", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      {:ok, _row} = KeyGrants.create_ephemeral(ctx.config, ctx.subject_id, ctx.dek, @domain)

      {:ok, user_dek} =
        KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)

      {:ok, eph_dek} = KeyGrants.resolve_ephemeral(ctx.config, ctx.subject_id, @domain)

      assert user_dek == ctx.dek
      assert eph_dek == ctx.dek
    end

    test "create_ephemeral raises when expires_at_attribute isn't configured", ctx do
      bare_config = %{ctx.config | expires_at_attribute: nil}

      assert_raise ArgumentError, ~r/expiring-grant attributes/, fn ->
        KeyGrants.create_ephemeral(bare_config, ctx.subject_id, ctx.dek, @domain)
      end
    end

    test "renew_ephemeral replaces an existing row with a fresh seal", ctx do
      {:ok, original} = KeyGrants.create_ephemeral(ctx.config, ctx.subject_id, ctx.dek, @domain)
      {:ok, renewed} = KeyGrants.renew_ephemeral(ctx.config, ctx.subject_id, ctx.dek, @domain)

      refute renewed.id == original.id
      # Same DEK + fresh IV inside SealKey means the sealed value
      # differs even when the plaintext is identical.
      refute renewed.wrapped_dek == original.wrapped_dek
      assert {:ok, dek} = KeyGrants.resolve_ephemeral(ctx.config, ctx.subject_id, @domain)
      assert dek == ctx.dek
    end

    test "renew_ephemeral leaves the existing row intact when sealing fails", ctx do
      {:ok, original} = KeyGrants.create_ephemeral(ctx.config, ctx.subject_id, ctx.dek, @domain)

      valid_key = Application.get_env(:ash_envelope, :seal_key)
      Application.put_env(:ash_envelope, :seal_key, "not-a-valid-key")

      assert {:error, :invalid_seal_key} =
               KeyGrants.renew_ephemeral(ctx.config, ctx.subject_id, ctx.dek, @domain)

      Application.put_env(:ash_envelope, :seal_key, valid_key)

      subject = ctx.subject_id

      {:ok, [survivor]} =
        ctx.config.resource
        |> Ash.Query.filter(subject_id == ^subject and is_nil(user_id))
        |> Ash.read(domain: @domain, authorize?: false)

      # Renewal must not degrade into pure revocation: the pre-failure
      # row is untouched and still resolves.
      assert survivor.id == original.id
      assert {:ok, dek} = KeyGrants.resolve_ephemeral(ctx.config, ctx.subject_id, @domain)
      assert dek == ctx.dek
    end

    test "renew_ephemeral creates a row when none exists", ctx do
      assert {:ok, _} = KeyGrants.renew_ephemeral(ctx.config, ctx.subject_id, ctx.dek, @domain)
      assert {:ok, dek} = KeyGrants.resolve_ephemeral(ctx.config, ctx.subject_id, @domain)
      assert dek == ctx.dek
    end

    test "renew_ephemeral_with_actor renews when the actor can resolve the DEK", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      {:ok, original} = KeyGrants.create_ephemeral(ctx.config, ctx.subject_id, ctx.dek, @domain)

      assert {:ok, renewed} =
               KeyGrants.renew_ephemeral_with_actor(
                 ctx.config,
                 ctx.subject_id,
                 ctx.actor,
                 @domain
               )

      refute renewed.id == original.id
    end

    test "renew_ephemeral_with_actor leaves existing row intact when actor has no grant",
         ctx do
      {:ok, original} = KeyGrants.create_ephemeral(ctx.config, ctx.subject_id, ctx.dek, @domain)

      assert {:error, :not_found} =
               KeyGrants.renew_ephemeral_with_actor(
                 ctx.config,
                 ctx.subject_id,
                 ctx.actor,
                 @domain
               )

      subject = ctx.subject_id

      {:ok, [survivor]} =
        ctx.config.resource
        |> Ash.Query.filter(subject_id == ^subject and is_nil(user_id))
        |> Ash.read(domain: @domain, authorize?: false)

      assert survivor.id == original.id
    end
  end
end
