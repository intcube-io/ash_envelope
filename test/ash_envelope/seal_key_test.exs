defmodule AshEnvelope.SealKeyTest do
  use ExUnit.Case, async: false

  alias AshEnvelope.SealKey

  setup do
    previous = Application.get_env(:ash_envelope, :seal_key)
    Application.put_env(:ash_envelope, :seal_key, Base.encode64(:crypto.strong_rand_bytes(32)))

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ash_envelope, :seal_key, previous),
        else: Application.delete_env(:ash_envelope, :seal_key)
    end)

    :ok
  end

  describe "seal/unseal round-trip" do
    test "without context" do
      plaintext = :crypto.strong_rand_bytes(32)
      assert {:ok, sealed} = SealKey.seal(plaintext)
      assert {:ok, ^plaintext} = SealKey.unseal(sealed)
    end

    test "with matching context" do
      plaintext = :crypto.strong_rand_bytes(32)
      context = "row:#{Ash.UUID.generate()}"
      assert {:ok, sealed} = SealKey.seal(plaintext, context: context)
      assert {:ok, ^plaintext} = SealKey.unseal(sealed, context: context)
    end

    test "produces different ciphertexts for the same plaintext (fresh IV)" do
      plaintext = :crypto.strong_rand_bytes(32)
      {:ok, a} = SealKey.seal(plaintext)
      {:ok, b} = SealKey.seal(plaintext)
      assert a != b
    end
  end

  describe "AAD binding" do
    test "unseal with different context fails" do
      {:ok, sealed} = SealKey.seal(:crypto.strong_rand_bytes(32), context: "subject-a")
      assert {:error, :decryption_failed} = SealKey.unseal(sealed, context: "subject-b")
    end

    test "unseal without context when sealed with context fails" do
      {:ok, sealed} = SealKey.seal(:crypto.strong_rand_bytes(32), context: "subject-a")
      assert {:error, :decryption_failed} = SealKey.unseal(sealed)
    end
  end

  describe "format validation" do
    test "rejects unknown version byte" do
      bogus = <<99::8, :crypto.strong_rand_bytes(64)::binary>>
      assert {:error, :unknown_seal_format} = SealKey.unseal(bogus)
    end

    test "rejects truncated ciphertext" do
      assert {:error, :unknown_seal_format} = SealKey.unseal(<<1::8, 0::8>>)
    end

    test "rejects non-binary input" do
      assert_raise FunctionClauseError, fn -> SealKey.seal(:not_a_binary) end
    end
  end

  describe "key resolution" do
    test "errors when seal key is missing" do
      Application.delete_env(:ash_envelope, :seal_key)
      assert {:error, :missing_seal_key} = SealKey.seal("payload")
    end

    test "errors when seal key is not 32 bytes after base64 decode" do
      Application.put_env(:ash_envelope, :seal_key, Base.encode64(:crypto.strong_rand_bytes(16)))
      assert {:error, :invalid_seal_key} = SealKey.seal("payload")
    end

    test "accepts a raw 32-byte binary (no base64)" do
      Application.put_env(:ash_envelope, :seal_key, :crypto.strong_rand_bytes(32))
      assert {:ok, sealed} = SealKey.seal("payload")
      assert {:ok, "payload"} = SealKey.unseal(sealed)
    end
  end

  describe "explicit :key override" do
    test "round-trips with a raw 32-byte key and no app env" do
      Application.delete_env(:ash_envelope, :seal_key)
      key = :crypto.strong_rand_bytes(32)

      assert {:ok, sealed} = SealKey.seal("payload", key: key)
      assert {:ok, "payload"} = SealKey.unseal(sealed, key: key)
    end

    test "round-trips with a base64 key" do
      key = Base.encode64(:crypto.strong_rand_bytes(32))

      assert {:ok, sealed} = SealKey.seal("payload", key: key)
      assert {:ok, "payload"} = SealKey.unseal(sealed, key: key)
    end

    test "takes precedence over the app env key" do
      key = :crypto.strong_rand_bytes(32)

      # Sealed under the explicit key; the (different) env key from the
      # module setup must not be able to open it.
      {:ok, sealed} = SealKey.seal("payload", key: key)

      assert {:error, :decryption_failed} = SealKey.unseal(sealed)
      assert {:ok, "payload"} = SealKey.unseal(sealed, key: key)
    end

    test "rejects a key that is not 32 bytes" do
      assert {:error, :invalid_seal_key} =
               SealKey.seal("payload", key: :crypto.strong_rand_bytes(16))

      assert {:error, :invalid_seal_key} =
               SealKey.seal("payload", key: Base.encode64(:crypto.strong_rand_bytes(16)))
    end

    test "rejects a non-binary key" do
      assert {:error, :invalid_seal_key} = SealKey.seal("payload", key: :not_a_key)
    end
  end

  describe "tamper resistance" do
    test "flipped bit in ciphertext fails authentication" do
      {:ok, sealed} = SealKey.seal("payload")
      <<head::binary-29, last::8, rest::binary>> = sealed
      tampered = <<head::binary, Bitwise.bxor(last, 1)::8, rest::binary>>
      assert {:error, :decryption_failed} = SealKey.unseal(tampered)
    end
  end
end
