defmodule AshEnvelopeTest do
  use ExUnit.Case, async: true

  import Bitwise

  # Flip the lowest bit of the byte at `byte_index`, leaving the rest of
  # the binary untouched — the smallest possible tamper.
  defp flip_bit(binary, byte_index) do
    <<prefix::binary-size(byte_index), byte, rest::binary>> = binary
    <<prefix::binary, bxor(byte, 1), rest::binary>>
  end

  describe "encrypt/3 and decrypt/3" do
    test "round-trips arbitrary data with no AAD" do
      key = AshEnvelope.generate_dek()
      plaintext = "hello, envelope encryption!"

      ciphertext = AshEnvelope.encrypt(plaintext, key)
      assert AshEnvelope.decrypt(ciphertext, key) == {:ok, plaintext}
    end

    test "round-trips empty binary" do
      key = AshEnvelope.generate_dek()
      ciphertext = AshEnvelope.encrypt("", key)
      assert AshEnvelope.decrypt(ciphertext, key) == {:ok, ""}
    end

    test "round-trips large binary" do
      key = AshEnvelope.generate_dek()
      plaintext = :crypto.strong_rand_bytes(1_000_000)
      ciphertext = AshEnvelope.encrypt(plaintext, key)
      assert AshEnvelope.decrypt(ciphertext, key) == {:ok, plaintext}
    end

    test "ciphertext is IV(12) + TAG(16) + encrypted data" do
      key = AshEnvelope.generate_dek()
      plaintext = "test data"
      ciphertext = AshEnvelope.encrypt(plaintext, key)
      assert byte_size(ciphertext) == 12 + 16 + byte_size(plaintext)
    end

    test "different encryptions of same data produce different ciphertexts" do
      key = AshEnvelope.generate_dek()
      ct1 = AshEnvelope.encrypt("same data", key)
      ct2 = AshEnvelope.encrypt("same data", key)
      refute ct1 == ct2
    end

    test "wrong key fails to decrypt" do
      key1 = AshEnvelope.generate_dek()
      key2 = AshEnvelope.generate_dek()
      ciphertext = AshEnvelope.encrypt("secret", key1)
      assert AshEnvelope.decrypt(ciphertext, key2) == {:error, :decryption_failed}
    end

    test "malformed ciphertext returns :malformed_blob" do
      key = AshEnvelope.generate_dek()
      assert AshEnvelope.decrypt(<<0::8>>, key) == {:error, :malformed_blob}
    end

    # Blob layout is IV(12) || TAG(16) || ciphertext. Flipping a single
    # bit anywhere must fail authentication, never return plaintext or
    # raise.
    test "single-bit tamper in IV, tag, or ciphertext fails to decrypt" do
      key = AshEnvelope.generate_dek()
      ciphertext = AshEnvelope.encrypt("tamper target", key)

      for byte_index <- [0, 12, 28] do
        tampered = flip_bit(ciphertext, byte_index)
        assert AshEnvelope.decrypt(tampered, key) == {:error, :decryption_failed}
      end
    end
  end

  describe "encrypt/3 + decrypt/3 AAD binding" do
    test "matching :context round-trips" do
      key = AshEnvelope.generate_dek()
      ct = AshEnvelope.encrypt("payload", key, context: "row-abc-123")
      assert AshEnvelope.decrypt(ct, key, context: "row-abc-123") == {:ok, "payload"}
    end

    test "mismatched :context surfaces :decryption_failed" do
      key = AshEnvelope.generate_dek()
      ct = AshEnvelope.encrypt("payload", key, context: "row-abc-123")
      assert AshEnvelope.decrypt(ct, key, context: "row-xyz-789") == {:error, :decryption_failed}
    end

    test "no-AAD ciphertext can be decrypted with no AAD (legacy wire format)" do
      key = AshEnvelope.generate_dek()
      ct = AshEnvelope.encrypt("payload", key)
      assert AshEnvelope.decrypt(ct, key) == {:ok, "payload"}
    end

    test "decrypt with no :context fails on a ciphertext written with :context" do
      key = AshEnvelope.generate_dek()
      ct = AshEnvelope.encrypt("payload", key, context: "row-abc")
      assert AshEnvelope.decrypt(ct, key) == {:error, :decryption_failed}
    end

    test "decrypt with :context fails on a ciphertext written with no AAD" do
      key = AshEnvelope.generate_dek()
      ct = AshEnvelope.encrypt("payload", key)
      assert AshEnvelope.decrypt(ct, key, context: "row-abc") == {:error, :decryption_failed}
    end
  end

  describe "generate_dek/0" do
    test "returns 32 bytes" do
      assert byte_size(AshEnvelope.generate_dek()) == 32
    end

    test "returns different values each call" do
      refute AshEnvelope.generate_dek() == AshEnvelope.generate_dek()
    end
  end

  describe "generate_key_pair/0" do
    test "returns 32-byte public and private keys" do
      {pub, priv} = AshEnvelope.generate_key_pair()
      assert byte_size(pub) == 32
      assert byte_size(priv) == 32
    end

    test "returns different key pairs each call" do
      {pub1, _} = AshEnvelope.generate_key_pair()
      {pub2, _} = AshEnvelope.generate_key_pair()
      refute pub1 == pub2
    end
  end

  describe "wrap_dek/2 and unwrap_dek/2" do
    test "round-trips a DEK with a key pair" do
      {pub, priv} = AshEnvelope.generate_key_pair()
      dek = AshEnvelope.generate_dek()

      wrapped = AshEnvelope.wrap_dek(dek, pub)
      # ephemeral_public(32) + IV(12) + TAG(16) + ciphertext(32)
      assert byte_size(wrapped) == 92

      assert AshEnvelope.unwrap_dek(wrapped, priv) == {:ok, dek}
    end

    test "wrapping only needs the public key" do
      {pub, _priv} = AshEnvelope.generate_key_pair()
      dek = AshEnvelope.generate_dek()

      wrapped = AshEnvelope.wrap_dek(dek, pub)
      assert is_binary(wrapped)
    end

    test "different wrappings produce different ciphertexts" do
      {pub, _priv} = AshEnvelope.generate_key_pair()
      dek = AshEnvelope.generate_dek()

      refute AshEnvelope.wrap_dek(dek, pub) == AshEnvelope.wrap_dek(dek, pub)
    end

    # SR3: each wrap MUST use a fresh ephemeral key pair. Two wraps of the
    # same DEK to the same recipient must therefore differ in the first 32
    # bytes (ephemeral public key prefix), not just in the IV/ciphertext
    # tail. A reuse of the ephemeral key would degrade ECIES to a
    # deterministic scheme and leak whether two records share a DEK.
    test "consecutive wraps produce distinct ephemeral public-key prefixes (SR3)" do
      {pub, _priv} = AshEnvelope.generate_key_pair()
      dek = AshEnvelope.generate_dek()

      <<eph1::binary-32, _rest1::binary>> = AshEnvelope.wrap_dek(dek, pub)
      <<eph2::binary-32, _rest2::binary>> = AshEnvelope.wrap_dek(dek, pub)

      refute eph1 == eph2
    end

    test "wrong private key fails to unwrap" do
      {pub, _priv} = AshEnvelope.generate_key_pair()
      {_pub2, wrong_priv} = AshEnvelope.generate_key_pair()
      dek = AshEnvelope.generate_dek()

      wrapped = AshEnvelope.wrap_dek(dek, pub)

      assert AshEnvelope.unwrap_dek(wrapped, wrong_priv) == {:error, :decryption_failed}
    end

    test "sharing: wrap with recipient's public key, unwrap with their private key" do
      {_sender_pub, _sender_priv} = AshEnvelope.generate_key_pair()
      {recipient_pub, recipient_priv} = AshEnvelope.generate_key_pair()

      dek = AshEnvelope.generate_dek()

      wrapped = AshEnvelope.wrap_dek(dek, recipient_pub)

      assert AshEnvelope.unwrap_dek(wrapped, recipient_priv) == {:ok, dek}
    end

    # Blob layout is ephemeral_public(32) || IV(12) || TAG(16) ||
    # ciphertext(32). Flipping a single bit anywhere — including the
    # ephemeral public-key prefix, which feeds ECDH rather than the
    # AEAD — must return an error tuple, never plaintext or a raise.
    test "single-bit tamper anywhere in the blob fails to unwrap" do
      {pub, priv} = AshEnvelope.generate_key_pair()
      dek = AshEnvelope.generate_dek()
      wrapped = AshEnvelope.wrap_dek(dek, pub)

      for byte_index <- [0, 31, 32, 44, 60] do
        tampered = flip_bit(wrapped, byte_index)
        assert AshEnvelope.unwrap_dek(tampered, priv) == {:error, :decryption_failed}
      end
    end

    test "too-short blob returns :malformed_blob" do
      {_pub, priv} = AshEnvelope.generate_key_pair()
      assert AshEnvelope.unwrap_dek(<<0::size(59 * 8)>>, priv) == {:error, :malformed_blob}
    end

    # Regression: an all-zero ephemeral public key is a degenerate
    # X25519 point for which :crypto.compute_key/4 raises. It must
    # surface as :decryption_failed — indistinguishable from tampering —
    # not as a crash.
    test "all-zero ephemeral public key fails as :decryption_failed" do
      {pub, priv} = AshEnvelope.generate_key_pair()
      dek = AshEnvelope.generate_dek()

      <<_eph::binary-32, rest::binary>> = AshEnvelope.wrap_dek(dek, pub)
      degenerate = <<0::size(32 * 8)>> <> rest

      assert AshEnvelope.unwrap_dek(degenerate, priv) == {:error, :decryption_failed}
    end

    # The wrap side of the same degenerate-point failure: wrap_dek/2
    # returns a bare binary, so it raises a clear ArgumentError instead.
    test "wrap_dek/2 raises ArgumentError for an all-zero recipient public key" do
      dek = AshEnvelope.generate_dek()

      assert_raise ArgumentError, ~r/not a valid X25519 public key/, fn ->
        AshEnvelope.wrap_dek(dek, <<0::size(32 * 8)>>)
      end
    end
  end

  describe "resolve_actor_key/2" do
    test "accepts a raw 32-byte binary" do
      raw_key = :crypto.strong_rand_bytes(32)
      actor = %{id: "user1", key: raw_key}

      assert AshEnvelope.resolve_actor_key(actor, :key) == raw_key
    end

    test "accepts a base64-encoded string" do
      raw_key = :crypto.strong_rand_bytes(32)
      b64_key = Base.encode64(raw_key)
      actor = %{id: "user1", key: b64_key}

      assert AshEnvelope.resolve_actor_key(actor, :key) == raw_key
    end

    test "raises for nil actor" do
      assert_raise ArgumentError, fn ->
        AshEnvelope.resolve_actor_key(nil, :key)
      end
    end

    test "raises for missing attribute" do
      assert_raise ArgumentError, fn ->
        AshEnvelope.resolve_actor_key(%{id: "user1"}, :key)
      end
    end

    test "raises when base64 decodes to wrong length" do
      # Base64 of a 16-byte value, not 32
      short_key = Base.encode64(:crypto.strong_rand_bytes(16))
      actor = %{id: "user1", key: short_key}

      assert_raise ArgumentError, fn ->
        AshEnvelope.resolve_actor_key(actor, :key)
      end
    end
  end

  describe "fetch_actor_key/2" do
    test "returns {:ok, key} for raw and base64 keys" do
      raw_key = :crypto.strong_rand_bytes(32)

      assert {:ok, ^raw_key} = AshEnvelope.fetch_actor_key(%{key: raw_key}, :key)
      assert {:ok, ^raw_key} = AshEnvelope.fetch_actor_key(%{key: Base.encode64(raw_key)}, :key)
    end

    test "returns {:error, {:missing_actor_key, attr}} for nil actor or nil attribute" do
      assert {:error, {:missing_actor_key, :key}} = AshEnvelope.fetch_actor_key(nil, :key)
      assert {:error, {:missing_actor_key, :key}} = AshEnvelope.fetch_actor_key(%{id: 1}, :key)
    end

    test "returns {:error, {:invalid_actor_key, attr}} without echoing the value" do
      short = :crypto.strong_rand_bytes(16)

      assert {:error, {:invalid_actor_key, :key}} =
               AshEnvelope.fetch_actor_key(%{key: Base.encode64(short)}, :key)

      assert {:error, {:invalid_actor_key, :key}} = AshEnvelope.fetch_actor_key(%{key: 42}, :key)
    end
  end

  # SR4: the HKDF helper is documented as capping output at 32 bytes (one
  # SHA-256 block) so that callers cannot silently truncate the derived
  # key. Verify the guard so a refactor cannot accidentally lift the cap.
  describe "hkdf_sha256/4 length cap (SR4)" do
    test "accepts length = 32 and returns 32 bytes" do
      out = AshEnvelope.hkdf_sha256("ikm", "salt", "ash_envelope_v1", 32)
      assert byte_size(out) == 32
    end

    test "accepts length = 1 and returns 1 byte" do
      out = AshEnvelope.hkdf_sha256("ikm", "salt", "ash_envelope_v1", 1)
      assert byte_size(out) == 1
    end

    test "raises FunctionClauseError for length > 32" do
      assert_raise FunctionClauseError, fn ->
        AshEnvelope.hkdf_sha256("ikm", "salt", "ash_envelope_v1", 33)
      end
    end

    test "raises FunctionClauseError for length = 0" do
      assert_raise FunctionClauseError, fn ->
        AshEnvelope.hkdf_sha256("ikm", "salt", "ash_envelope_v1", 0)
      end
    end
  end
end
