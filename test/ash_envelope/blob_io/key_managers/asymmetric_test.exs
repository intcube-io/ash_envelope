defmodule AshEnvelope.BlobIO.KeyManagers.AsymmetricTest do
  use ExUnit.Case, async: true

  alias AshEnvelope.BlobIO.KeyManagers.Asymmetric
  alias AshStorage.BlobIO.BlobContext
  alias AshStorage.Encryption.RewrapOperation
  alias AshStorage.BlobIO.Reader
  alias AshStorage.BlobIO.Writer

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
