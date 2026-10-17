defmodule AshEnvelope.KeyGrantsTest do
  use ExUnit.Case, async: true

  alias AshEnvelope.KeyGrants
  alias AshEnvelope.KeyGrants.Config

  require Ash.Query

  @domain AshEnvelope.Test.Domain

  setup do
    {pub, priv} = AshEnvelope.generate_key_pair()
    actor = %{id: Ash.UUID.generate(), public_key: pub, private_key: priv}
    dek = AshEnvelope.generate_dek()
    subject_id = Ash.UUID.generate()

    config = %Config{
      resource: AshEnvelope.Test.Grant,
      subject_id_attribute: :subject_id,
      actor_public_key_attribute: :public_key,
      actor_private_key_attribute: :private_key
    }

    %{config: config, actor: actor, dek: dek, subject_id: subject_id}
  end

  describe "create_for_actor/5" do
    test "creates a grant row and returns :ok", ctx do
      assert :ok =
               KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)
    end

    test "stores a wrapped DEK that can be resolved back", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      {:ok, resolved_dek} =
        KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)

      assert resolved_dek == ctx.dek
    end

    test "different actors get different wrapped DEKs for the same subject", ctx do
      {pub2, priv2} = AshEnvelope.generate_key_pair()
      actor2 = %{id: Ash.UUID.generate(), public_key: pub2, private_key: priv2}

      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, actor2, @domain)

      # Both should resolve to the same raw DEK
      {:ok, dek1} = KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)
      {:ok, dek2} = KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, actor2, @domain)

      assert dek1 == dek2
      assert dek1 == ctx.dek
    end
  end

  describe "resolve_for_actor/4" do
    test "returns {:error, :not_found} when no grant exists", ctx do
      assert {:error, :not_found} =
               KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)
    end

    test "returns the raw 32-byte DEK on success", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      {:ok, resolved} =
        KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)

      assert byte_size(resolved) == 32
      assert resolved == ctx.dek
    end

    test "wrong actor cannot resolve another actor's grant", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      {pub2, priv2} = AshEnvelope.generate_key_pair()
      wrong_actor = %{id: Ash.UUID.generate(), public_key: pub2, private_key: priv2}

      assert {:error, :not_found} =
               KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, wrong_actor, @domain)
    end
  end

  describe "share/5" do
    test "re-wraps DEK for the target actor using only their public key", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      {target_pub, target_priv} = AshEnvelope.generate_key_pair()
      target = %{id: Ash.UUID.generate(), public_key: target_pub, private_key: target_priv}

      assert :ok =
               KeyGrants.share(ctx.config, ctx.subject_id, ctx.actor, target, @domain)

      # Target can now resolve the same DEK
      {:ok, target_dek} = KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, target, @domain)
      assert target_dek == ctx.dek
    end

    test "returns error when granting actor has no grant", ctx do
      {pub2, priv2} = AshEnvelope.generate_key_pair()
      target = %{id: Ash.UUID.generate(), public_key: pub2, private_key: priv2}

      assert {:error, :not_found} =
               KeyGrants.share(ctx.config, ctx.subject_id, ctx.actor, target, @domain)
    end

    test "is idempotent when target already has a grant", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      {target_pub, target_priv} = AshEnvelope.generate_key_pair()
      target = %{id: Ash.UUID.generate(), public_key: target_pub, private_key: target_priv}

      assert :ok = KeyGrants.share(ctx.config, ctx.subject_id, ctx.actor, target, @domain)
      assert :ok = KeyGrants.share(ctx.config, ctx.subject_id, ctx.actor, target, @domain)

      # Only one grant row for the target
      {:ok, grants} =
        AshEnvelope.Test.Grant
        |> Ash.Query.filter(subject_id == ^ctx.subject_id and user_id == ^target.id)
        |> Ash.read(domain: @domain, authorize?: false)

      assert length(grants) == 1

      # And it still resolves correctly
      {:ok, resolved} = KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, target, @domain)
      assert resolved == ctx.dek
    end
  end

  describe "resolve_for_actor/4 error paths" do
    test "returns :corrupted_dek when stored DEK is not valid base64", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      {:ok, [grant]} =
        AshEnvelope.Test.Grant
        |> Ash.Query.filter(subject_id == ^ctx.subject_id and user_id == ^ctx.actor.id)
        |> Ash.read(domain: @domain, authorize?: false)

      Ash.update!(grant, %{wrapped_dek: "not-valid-base64!!!"},
        action: :corrupt_dek,
        domain: @domain
      )

      assert {:error, :corrupted_dek} =
               KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)
    end

    test "returns :decryption_failed when DEK was wrapped for a different key", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      # Replace with a valid wrapped DEK that was encrypted for a different recipient
      {other_pub, _other_priv} = AshEnvelope.generate_key_pair()
      wrong_wrapped = AshEnvelope.wrap_dek(ctx.dek, other_pub) |> Base.encode64()

      {:ok, [grant]} =
        AshEnvelope.Test.Grant
        |> Ash.Query.filter(subject_id == ^ctx.subject_id and user_id == ^ctx.actor.id)
        |> Ash.read(domain: @domain, authorize?: false)

      Ash.update!(grant, %{wrapped_dek: wrong_wrapped}, action: :corrupt_dek, domain: @domain)

      assert {:error, :decryption_failed} =
               KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)
    end

    test "returns {:error, {:missing_actor_key, _}} when a grant exists but the actor has no private key",
         ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      public_only = Map.delete(ctx.actor, :private_key)

      assert {:error, {:missing_actor_key, :private_key}} =
               KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, public_only, @domain)
    end

    test "a public-key-only actor with no grant still gets :not_found", ctx do
      public_only = Map.delete(ctx.actor, :private_key)

      assert {:error, :not_found} =
               KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, public_only, @domain)
    end
  end

  describe "actor key errors are error tuples, not exceptions" do
    test "create_for_actor returns {:error, {:missing_actor_key, _}} for an actor without a public key",
         ctx do
      keyless = %{id: Ash.UUID.generate()}

      assert {:error, {:missing_actor_key, :public_key}} =
               KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, keyless, @domain)

      assert {:ok, []} =
               AshEnvelope.Test.Grant
               |> Ash.Query.filter(subject_id == ^ctx.subject_id)
               |> Ash.read(domain: @domain, authorize?: false)
    end

    test "create_for_actor returns {:error, {:invalid_actor_key, _}} for a malformed public key",
         ctx do
      malformed = %{id: Ash.UUID.generate(), public_key: Base.encode64(<<1, 2, 3>>)}

      assert {:error, {:invalid_actor_key, :public_key}} =
               KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, malformed, @domain)
    end

    test "share returns an error tuple and creates nothing when the target has no public key",
         ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      keyless = %{id: Ash.UUID.generate()}

      assert {:error, {:missing_actor_key, :public_key}} =
               KeyGrants.share(ctx.config, ctx.subject_id, ctx.actor, keyless, @domain)

      assert {:ok, []} =
               AshEnvelope.Test.Grant
               |> Ash.Query.filter(subject_id == ^ctx.subject_id and user_id == ^keyless.id)
               |> Ash.read(domain: @domain, authorize?: false)
    end
  end

  describe "revoke/2" do
    test "deletes the grant row", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      {:ok, [grant]} =
        AshEnvelope.Test.Grant
        |> Ash.Query.filter(subject_id == ^ctx.subject_id and user_id == ^ctx.actor.id)
        |> Ash.read(domain: @domain, authorize?: false)

      assert :ok = KeyGrants.revoke(grant, @domain)

      assert {:error, :not_found} =
               KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)
    end
  end

  describe "full lifecycle" do
    test "create -> share -> revoke target -> original still works", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      {target_pub, target_priv} = AshEnvelope.generate_key_pair()
      target = %{id: Ash.UUID.generate(), public_key: target_pub, private_key: target_priv}
      :ok = KeyGrants.share(ctx.config, ctx.subject_id, ctx.actor, target, @domain)

      # Both can resolve
      {:ok, _} = KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)
      {:ok, _} = KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, target, @domain)

      # Revoke target's grant
      {:ok, [target_grant]} =
        AshEnvelope.Test.Grant
        |> Ash.Query.filter(subject_id == ^ctx.subject_id and user_id == ^target.id)
        |> Ash.read(domain: @domain, authorize?: false)

      :ok = KeyGrants.revoke(target_grant, @domain)

      # Target can no longer resolve, but original actor can
      assert {:error, :not_found} =
               KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, target, @domain)

      {:ok, resolved} =
        KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)

      assert resolved == ctx.dek
    end
  end

  describe "time-bounded user grants (expires_at)" do
    setup ctx do
      %{ctx | config: %{ctx.config | expires_at_attribute: :expires_at}}
    end

    test "create_for_actor with future :expires_at resolves normally", ctx do
      future = DateTime.add(DateTime.utc_now(), 3600, :second)

      :ok =
        KeyGrants.create_for_actor(
          ctx.config,
          ctx.subject_id,
          ctx.dek,
          ctx.actor,
          @domain,
          expires_at: future
        )

      assert {:ok, dek} =
               KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)

      assert dek == ctx.dek
    end

    test "resolve_for_actor treats an expired row as :not_found", ctx do
      past = DateTime.add(DateTime.utc_now(), -60, :second)

      :ok =
        KeyGrants.create_for_actor(
          ctx.config,
          ctx.subject_id,
          ctx.dek,
          ctx.actor,
          @domain,
          expires_at: past
        )

      assert {:error, :not_found} =
               KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)
    end

    test "permanent grants (no expires_at on the row) still resolve", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      {:ok, dek} = KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)
      assert dek == ctx.dek
    end

    test "raises when :expires_at supplied but config doesn't have the attribute set", ctx do
      bare_config = %{ctx.config | expires_at_attribute: nil}
      future = DateTime.add(DateTime.utc_now(), 3600, :second)

      assert_raise ArgumentError, ~r/expires_at_attribute is not configured/, fn ->
        KeyGrants.create_for_actor(
          bare_config,
          ctx.subject_id,
          ctx.dek,
          ctx.actor,
          @domain,
          expires_at: future
        )
      end
    end
  end

  describe "ephemeral worker grants" do
    setup ctx do
      previous = Application.get_env(:ash_envelope, :seal_key)
      Application.put_env(:ash_envelope, :seal_key, Base.encode64(:crypto.strong_rand_bytes(32)))

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ash_envelope, :seal_key, previous),
          else: Application.delete_env(:ash_envelope, :seal_key)
      end)

      ephemeral_config = %{
        ctx.config
        | expires_at_attribute: :expires_at,
          ephemeral_ttl_seconds: 3600
      }

      %{ctx | config: ephemeral_config}
    end

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

  describe "Config.ephemeral_configured?/1" do
    test "false when expires_at_attribute is nil" do
      bare = %Config{
        resource: AshEnvelope.Test.Grant,
        actor_public_key_attribute: :public_key,
        actor_private_key_attribute: :private_key
      }

      refute Config.ephemeral_configured?(bare)
    end

    test "true when expires_at_attribute is set" do
      configured = %Config{
        resource: AshEnvelope.Test.Grant,
        actor_public_key_attribute: :public_key,
        actor_private_key_attribute: :private_key,
        expires_at_attribute: :expires_at
      }

      assert Config.ephemeral_configured?(configured)
    end
  end
end
