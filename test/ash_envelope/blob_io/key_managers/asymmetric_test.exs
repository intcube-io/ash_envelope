defmodule AshEnvelope.BlobIO.KeyManagers.AsymmetricTest do
  use ExUnit.Case, async: true

  alias AshEnvelope.BlobIO.KeyManagers.Asymmetric
  alias AshStorage.BlobIO.BlobContext
  alias AshStorage.BlobIO.Reader
  alias AshStorage.BlobIO.Writer
  alias AshStorage.Encryption.RewrapOperation

  setup do
    {pub, priv} = AshEnvelope.generate_key_pair()
    actor = %{id: Ash.UUID.generate(), public_key: pub, private_key: priv}

    {pub2, priv2} = AshEnvelope.generate_key_pair()
    other = %{id: Ash.UUID.generate(), public_key: pub2, private_key: priv2}

    opts = [
      actor_public_key_attribute: :public_key,
      actor_private_key_attribute: :private_key
    ]

    %{actor: actor, other: other, opts: opts}
  end

  defp write_op(actor), do: %Writer.Operation{blob_context: BlobContext.new(actor: actor)}
  defp read_op(actor), do: %Reader.Operation{blob_context: BlobContext.new(actor: actor)}

  describe "wrap_dek/3 + unwrap_dek/3" do
    test "round-trips a DEK with the actor's key pair", %{actor: actor, opts: opts} do
      dek = AshEnvelope.generate_dek()

      assert {:ok, wrapped} = Asymmetric.wrap_dek(dek, write_op(actor), opts)
      assert wrapped["format"] == "x25519-ecies-v1"
      assert is_binary(wrapped["ciphertext"])

      assert {:ok, ^dek} = Asymmetric.unwrap_dek(wrapped, read_op(actor), opts)
    end

    test "two wraps of the same DEK produce distinct ciphertexts", %{actor: actor, opts: opts} do
      dek = AshEnvelope.generate_dek()
      {:ok, a} = Asymmetric.wrap_dek(dek, write_op(actor), opts)
      {:ok, b} = Asymmetric.wrap_dek(dek, write_op(actor), opts)
      refute a["ciphertext"] == b["ciphertext"]
    end

    test "another actor cannot unwrap", %{actor: actor, other: other, opts: opts} do
      dek = AshEnvelope.generate_dek()
      {:ok, wrapped} = Asymmetric.wrap_dek(dek, write_op(actor), opts)
      assert {:error, :decryption_failed} = Asymmetric.unwrap_dek(wrapped, read_op(other), opts)
    end

    test "rejects metadata in the wrong format", %{actor: actor, opts: opts} do
      assert {:error, {:invalid_asymmetric_key_metadata, "wrapped_dek"}} =
               Asymmetric.unwrap_dek(%{"format" => "cloak"}, read_op(actor), opts)
    end

    test "requires actor public key attribute option", %{actor: actor} do
      dek = AshEnvelope.generate_dek()

      assert {:error, {:asymmetric_key_manager_option_required, :actor_public_key_attribute}} =
               Asymmetric.wrap_dek(dek, write_op(actor),
                 actor_private_key_attribute: :private_key
               )
    end

    # An unauthenticated read (actor: nil) must surface as a clean error
    # tuple — matching the KeyGrants manager — not crash the read
    # pipeline mid-request.
    test "read with a nil actor returns :missing_principal instead of raising", %{
      actor: actor,
      opts: opts
    } do
      dek = AshEnvelope.generate_dek()
      {:ok, wrapped} = Asymmetric.wrap_dek(dek, write_op(actor), opts)

      assert {:error, :missing_principal} = Asymmetric.unwrap_dek(wrapped, read_op(nil), opts)
    end

    test "write with a nil actor returns :missing_principal instead of raising", %{opts: opts} do
      dek = AshEnvelope.generate_dek()

      assert {:error, :missing_principal} = Asymmetric.wrap_dek(dek, write_op(nil), opts)
    end

    test "actor missing the key attribute returns :missing_principal", %{opts: opts} do
      dek = AshEnvelope.generate_dek()
      keyless = %{id: Ash.UUID.generate()}

      assert {:error, :missing_principal} = Asymmetric.wrap_dek(dek, write_op(keyless), opts)

      {pub, _priv} = AshEnvelope.generate_key_pair()
      {:ok, wrapped} = Asymmetric.wrap_dek(dek, write_op(%{id: "w", public_key: pub}), opts)

      assert {:error, :missing_principal} = Asymmetric.unwrap_dek(wrapped, read_op(keyless), opts)
    end

    test "malformed actor key material returns :invalid_actor_key", %{actor: actor, opts: opts} do
      dek = AshEnvelope.generate_dek()
      # Base64 of 16 bytes — decodes, but not to a 32-byte key.
      malformed = %{id: "m", private_key: Base.encode64(:crypto.strong_rand_bytes(16))}

      {:ok, wrapped} = Asymmetric.wrap_dek(dek, write_op(actor), opts)

      assert {:error, :invalid_actor_key} =
               Asymmetric.unwrap_dek(wrapped, read_op(malformed), opts)
    end
  end

  # A degenerate (all-zero / low-order) X25519 public key on the actor
  # makes AshEnvelope.wrap_dek/2 raise. Key managers run inside the
  # BlobIO write pipeline, which scrubs exceptions to an opaque error;
  # the manager must instead report it like any other bad actor key.
  describe "degenerate recipient public key" do
    test "wrap_dek/3 returns :invalid_actor_key instead of raising", %{opts: opts} do
      dek = AshEnvelope.generate_dek()
      degenerate = %{id: "d", public_key: <<0::size(32 * 8)>>}

      assert {:error, :invalid_actor_key} = Asymmetric.wrap_dek(dek, write_op(degenerate), opts)
    end

    test "rewrap_dek/3 returns :invalid_actor_key instead of raising", %{
      actor: actor,
      opts: opts
    } do
      dek = AshEnvelope.generate_dek()
      {:ok, wrapped} = Asymmetric.wrap_dek(dek, write_op(actor), opts)
      degenerate = %{id: "d", public_key: <<0::size(32 * 8)>>}

      rewrap_op = %RewrapOperation{
        blob_context: BlobContext.new(actor: degenerate),
        call_opts: [donor_actor: actor]
      }

      assert {:error, :invalid_actor_key} = Asymmetric.rewrap_dek(wrapped, rewrap_op, opts)
    end
  end

  describe "rewrap_dek/3" do
    test "rewraps from donor to recipient without touching the DEK", %{
      actor: actor,
      other: other,
      opts: opts
    } do
      dek = AshEnvelope.generate_dek()
      {:ok, wrapped} = Asymmetric.wrap_dek(dek, write_op(actor), opts)

      rewrap_op = %RewrapOperation{
        blob_context: BlobContext.new(actor: other),
        call_opts: [donor_actor: actor]
      }

      assert {:ok, rewrapped} = Asymmetric.rewrap_dek(wrapped, rewrap_op, opts)

      assert {:ok, ^dek} = Asymmetric.unwrap_dek(rewrapped, read_op(other), opts)
      assert {:error, _} = Asymmetric.unwrap_dek(rewrapped, read_op(actor), opts)
    end
  end
end
