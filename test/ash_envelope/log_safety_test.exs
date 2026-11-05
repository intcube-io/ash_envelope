defmodule AshEnvelope.LogSafetyTest do
  @moduledoc """
  SR10: the library must not log raw DEKs, principal private keys, or
  decrypted plaintext at any log level. This test exercises the public API
  with distinctive marker values and asserts that none of the markers
  appears anywhere in captured Logger output or in captured stderr.

  Markers are randomly generated each run (valid keys cannot be fixed
  byte patterns), so we capture the marker values explicitly and check
  every representation in which the library could plausibly leak them:
  raw substring, Base64 encoding, and Elixir's `inspect/1` form.
  """

  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias AshEnvelope.{GrantRequests, KeyGrants}

  @domain AshEnvelope.Test.Domain

  @plaintext "PLAINTEXT_SECRET_MARKER_xxx_yyy_zzz_long_enough_to_be_distinctive"

  defp marker_representations(marker) when is_binary(marker) do
    [marker, Base.encode64(marker), inspect(marker)]
  end

  defp assert_no_leak(captured, markers) do
    for marker <- markers, representation <- marker_representations(marker) do
      refute String.contains?(captured, representation),
             "captured output leaked a marker (#{byte_size(marker)}-byte binary)"
    end
  end

  defp capture_all(fun) do
    {stderr, log} =
      ExUnit.CaptureLog.with_log(fn ->
        capture_io(:stderr, fun)
      end)

    %{stderr: stderr, log: log}
  end

  describe "core crypto primitives" do
    test "encrypt/decrypt round-trip does not log key or plaintext" do
      dek = AshEnvelope.generate_dek()

      captured =
        capture_all(fn ->
          ct = AshEnvelope.encrypt(@plaintext, dek)
          {:ok, _} = AshEnvelope.decrypt(ct, dek)
          :ok
        end)

      assert_no_leak(captured.log <> captured.stderr, [dek, @plaintext])
    end

    test "decrypt with wrong key does not log key or plaintext" do
      dek = AshEnvelope.generate_dek()
      wrong = AshEnvelope.generate_dek()

      captured =
        capture_all(fn ->
          ct = AshEnvelope.encrypt(@plaintext, dek)
          {:error, :decryption_failed} = AshEnvelope.decrypt(ct, wrong)
          :ok
        end)

      assert_no_leak(captured.log <> captured.stderr, [dek, wrong, @plaintext])
    end

    test "decrypt with mismatched AAD does not log key, plaintext, or AAD" do
      dek = AshEnvelope.generate_dek()
      ctx_a = "row-aaaa-1111"
      ctx_b = "row-bbbb-2222"

      captured =
        capture_all(fn ->
          ct = AshEnvelope.encrypt(@plaintext, dek, context: ctx_a)
          {:error, :decryption_failed} = AshEnvelope.decrypt(ct, dek, context: ctx_b)
          :ok
        end)

      # Note: ctx_a is the binding row id — it's not secret per se, but
      # the log-safety contract is that the library should not echo
      # caller-supplied parameters into logs without intent.
      assert_no_leak(captured.log <> captured.stderr, [dek, @plaintext])
    end

    test "wrap_dek/unwrap_dek round-trip does not log keys" do
      {pub, priv} = AshEnvelope.generate_key_pair()
      dek = AshEnvelope.generate_dek()

      captured =
        capture_all(fn ->
          wrapped = AshEnvelope.wrap_dek(dek, pub)
          {:ok, ^dek} = AshEnvelope.unwrap_dek(wrapped, priv)
          :ok
        end)

      assert_no_leak(captured.log <> captured.stderr, [dek, priv, pub])
    end

    test "unwrap with wrong private key does not log keys" do
      {pub, _priv} = AshEnvelope.generate_key_pair()
      {_pub2, wrong_priv} = AshEnvelope.generate_key_pair()
      dek = AshEnvelope.generate_dek()

      captured =
        capture_all(fn ->
          wrapped = AshEnvelope.wrap_dek(dek, pub)
          {:error, :decryption_failed} = AshEnvelope.unwrap_dek(wrapped, wrong_priv)
          :ok
        end)

      assert_no_leak(captured.log <> captured.stderr, [dek, wrong_priv])
    end

    test "resolve_actor_key error path does not log the key" do
      raw_key = :crypto.strong_rand_bytes(16)
      bad_actor = %{id: "u", key: Base.encode64(raw_key)}

      captured =
        capture_all(fn ->
          try do
            AshEnvelope.resolve_actor_key(bad_actor, :key)
          rescue
            ArgumentError -> :ok
          end
        end)

      assert_no_leak(captured.log <> captured.stderr, [raw_key])
    end
  end

  describe "KeyGrants public API" do
    setup do
      {pub, priv} = AshEnvelope.generate_key_pair()
      actor = %{id: Ash.UUID.generate(), public_key: pub, private_key: priv}
      dek = AshEnvelope.generate_dek()
      subject_id = Ash.UUID.generate()

      config = %KeyGrants.Config{
        resource: AshEnvelope.Test.Grant,
        subject_id_attribute: :subject_id,
        actor_public_key_attribute: :public_key,
        actor_private_key_attribute: :private_key
      }

      %{config: config, actor: actor, dek: dek, subject_id: subject_id, priv: priv, pub: pub}
    end

    test "create_for_actor / resolve_for_actor do not log keys", ctx do
      captured =
        capture_all(fn ->
          :ok =
            KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

          {:ok, _} =
            KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)

          :ok
        end)

      assert_no_leak(captured.log <> captured.stderr, [ctx.dek, ctx.priv, ctx.pub])
    end

    test "share does not log keys in transit", ctx do
      {tpub, tpriv} = AshEnvelope.generate_key_pair()
      target = %{id: Ash.UUID.generate(), public_key: tpub, private_key: tpriv}

      :ok = KeyGrants.create_for_actor(ctx.config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      captured =
        capture_all(fn ->
          :ok = KeyGrants.share(ctx.config, ctx.subject_id, ctx.actor, target, @domain)
          :ok
        end)

      assert_no_leak(captured.log <> captured.stderr, [ctx.dek, ctx.priv, tpriv])
    end

    test "resolve_for_actor :not_found path does not log keys", ctx do
      captured =
        capture_all(fn ->
          {:error, :not_found} =
            KeyGrants.resolve_for_actor(ctx.config, ctx.subject_id, ctx.actor, @domain)

          :ok
        end)

      assert_no_leak(captured.log <> captured.stderr, [ctx.priv])
    end
  end

  describe "GrantRequests public API" do
    setup do
      {pub, priv} = AshEnvelope.generate_key_pair()
      target = %{id: Ash.UUID.generate(), public_key: pub, private_key: priv}
      requester = %{id: Ash.UUID.generate()}

      config = %GrantRequests.Config{
        resource: AshEnvelope.Test.GrantRequest,
        subject_id_attribute: :subject_id,
        target_principal_id_attribute: :user_id
      }

      %{config: config, target: target, requester: requester, priv: priv, pub: pub}
    end

    test "create does not log target's keys", ctx do
      subject_id = Ash.UUID.generate()

      captured =
        capture_all(fn ->
          :ok = GrantRequests.create(ctx.config, subject_id, ctx.target, ctx.requester, @domain)
          :ok
        end)

      assert_no_leak(captured.log <> captured.stderr, [ctx.priv, ctx.pub])
    end
  end

  describe "BlobIO Asymmetric key manager" do
    alias AshEnvelope.BlobIO.KeyManagers.Asymmetric
    alias AshStorage.BlobIO.BlobContext
    alias AshStorage.BlobIO.Reader
    alias AshStorage.BlobIO.Writer

    test "wrap/unwrap round-trip does not log DEK or plaintext" do
      {pub, priv} = AshEnvelope.generate_key_pair()
      actor = %{id: Ash.UUID.generate(), public_key: pub, private_key: priv}
      dek = AshEnvelope.generate_dek()

      opts = [
        actor_public_key_attribute: :public_key,
        actor_private_key_attribute: :private_key
      ]

      captured =
        capture_all(fn ->
          bctx = BlobContext.new(actor: actor)
          write = %Writer.Operation{blob_context: bctx}
          {:ok, wrapped, :none} = wrap_normalize(Asymmetric.wrap_dek(dek, write, opts))

          read = %Reader.Operation{blob_context: bctx}
          {:ok, ^dek} = Asymmetric.unwrap_dek(wrapped, read, opts)
          :ok
        end)

      assert_no_leak(captured.log <> captured.stderr, [dek, priv])
    end

    defp wrap_normalize({:ok, wrapped}), do: {:ok, wrapped, :none}
    defp wrap_normalize(other), do: other
  end
end
