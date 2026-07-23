defmodule AshEnvelope.BlobIO.BackupTest do
  # async: false — mutates global Application config.
  use ExUnit.Case, async: false

  alias AshEnvelope.BlobIO.Backup

  setup do
    original_current = Application.get_env(:ash_envelope, :backup_public_key)
    original_previous = Application.get_env(:ash_envelope, :backup_public_key_previous)

    on_exit(fn ->
      restore(:backup_public_key, original_current)
      restore(:backup_public_key_previous, original_previous)
    end)

    :ok
  end

  describe "current_public_key/0" do
    test "returns nil when unset" do
      Application.delete_env(:ash_envelope, :backup_public_key)
      assert Backup.current_public_key() == nil
    end

    test "accepts a raw 32-byte binary" do
      {pub, _priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, pub)
      assert Backup.current_public_key() == pub
    end

    test "accepts a base64-encoded 32-byte binary" do
      {pub, _priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, Base.encode64(pub))
      assert Backup.current_public_key() == pub
    end

    test "raises on a wrong-size binary" do
      Application.put_env(:ash_envelope, :backup_public_key, "too short")

      assert_raise ArgumentError, ~r/must be a 32-byte/, fn ->
        Backup.current_public_key()
      end
    end
  end

  describe "key_id/1" do
    test "is stable across calls for the same key" do
      {pub, _priv} = AshEnvelope.generate_key_pair()
      assert Backup.key_id(pub) == Backup.key_id(pub)
    end

    test "differs between key pairs" do
      {pub1, _} = AshEnvelope.generate_key_pair()
      {pub2, _} = AshEnvelope.generate_key_pair()
      refute Backup.key_id(pub1) == Backup.key_id(pub2)
    end

    test "is a 16-char lowercase hex string" do
      {pub, _} = AshEnvelope.generate_key_pair()
      id = Backup.key_id(pub)
      assert String.length(id) == 16
      assert id =~ ~r/^[0-9a-f]{16}$/
    end
  end

  describe "wrap_for_backup/1 / unwrap_backup/2" do
    test "returns nil when no key configured" do
      Application.delete_env(:ash_envelope, :backup_public_key)
      assert Backup.wrap_for_backup(AshEnvelope.generate_dek()) == nil
    end

    test "round-trips a DEK" do
      {pub, priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, pub)

      dek = AshEnvelope.generate_dek()
      wrap = Backup.wrap_for_backup(dek)

      assert %{
               "format" => "x25519-ecies-v1",
               "key_id" => key_id,
               "ciphertext" => ciphertext
             } = wrap

      assert key_id == Backup.key_id(pub)
      assert is_binary(ciphertext)

      assert {:ok, ^dek} = Backup.unwrap_backup(wrap, priv)
    end

    test "another private key cannot unwrap" do
      {pub, _priv} = AshEnvelope.generate_key_pair()
      {_pub2, priv2} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, pub)

      dek = AshEnvelope.generate_dek()
      wrap = Backup.wrap_for_backup(dek)

      assert {:error, :decryption_failed} = Backup.unwrap_backup(wrap, priv2)
    end
  end

  describe "put_backup/2 + from_wrapped_dek/1" do
    test "embeds and extracts backup nested under the wrapped_dek map" do
      wrapped_dek = %{"format" => "x25519-ecies-v1", "ciphertext" => "abc"}

      backup = %{
        "format" => "x25519-ecies-v1",
        "key_id" => "deadbeefdeadbeef",
        "ciphertext" => "xyz"
      }

      with_backup = Backup.put_backup(wrapped_dek, backup)
      assert with_backup["backup"] == backup
      assert Backup.from_wrapped_dek(with_backup) == backup
    end

    test "put_backup/2 with nil removes the field" do
      wrapped_dek = %{"format" => "x", "backup" => %{}}
      assert Backup.put_backup(wrapped_dek, nil) == %{"format" => "x"}
    end

    test "from_wrapped_dek/1 returns nil when absent" do
      assert Backup.from_wrapped_dek(%{"format" => "x"}) == nil
    end
  end

  defp restore(key, nil), do: Application.delete_env(:ash_envelope, key)
  defp restore(key, value), do: Application.put_env(:ash_envelope, key, value)
end
