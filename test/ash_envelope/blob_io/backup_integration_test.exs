defmodule AshEnvelope.BlobIO.BackupIntegrationTest do
  @moduledoc """
  End-to-end coverage that the backup-key escrow path composes with both
  KeyManagers + BlobIO: write with a backup key configured, recover via
  the backup private key without going through the KeyManager, and
  rotate the backup key over an existing blob.
  """

  # async: false — mutates global Application config.
  use ExUnit.Case, async: false

  alias AshEnvelope.BlobIO.{Backup, BackupRotation}

  @domain AshEnvelope.Test.Storage.Domain
  @resource AshEnvelope.Test.Storage.EncryptedPost
  @blob_resource AshEnvelope.Test.Storage.Blob

  setup do
    AshStorage.Service.Test.start()
    AshStorage.Service.Test.reset!()

    {pub, priv} = AshEnvelope.generate_key_pair()
    actor = %{id: Ash.UUID.generate(), public_key: pub, private_key: priv}

    original_current = Application.get_env(:ash_envelope, :backup_public_key)
    original_previous = Application.get_env(:ash_envelope, :backup_public_key_previous)

    on_exit(fn ->
      restore(:backup_public_key, original_current)
      restore(:backup_public_key_previous, original_previous)
    end)

    %{actor: actor}
  end

  describe "Asymmetric KeyManager with backup configured" do
    test "embeds a backup wrap; recover_plaintext via backup priv works", %{actor: actor} do
      {backup_pub, backup_priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, backup_pub)

      post =
        @resource
        |> Ash.create!(%{title: "Recoverable"}, domain: @domain)
        |> Ash.update!(
          %{io: "for backup recovery", filename: "r.txt", content_type: "text/plain"},
          action: :attach_document,
          domain: @domain,
          actor: actor
        )

      blob = post.__metadata__[:blob]
      assert blob

      # Backup wrap is present and tagged with the current key's fingerprint.
      assert [%{"metadata" => layer_metadata}] =
               blob.metadata["ash_storage"]["blob_io"]["layers"]

      assert %{"backup" => backup} = layer_metadata["wrapped_dek"]
      assert backup["format"] == "x25519-ecies-v1"
      assert backup["key_id"] == Backup.key_id(backup_pub)

      # Caller downloads ciphertext + recovers plaintext using the backup priv.
      {:ok, ciphertext} = AshStorage.Service.Test.download(blob.key, [])

      assert {:ok, "for backup recovery"} =
               AshEnvelope.recover_plaintext(blob, ciphertext, backup_priv)
    end

    test "no backup field when backup_public_key is unset", %{actor: actor} do
      Application.delete_env(:ash_envelope, :backup_public_key)

      post =
        @resource
        |> Ash.create!(%{title: "No backup"}, domain: @domain)
        |> Ash.update!(
          %{io: "x", filename: "x.txt", content_type: "text/plain"},
          action: :attach_document,
          domain: @domain,
          actor: actor
        )

      blob = post.__metadata__[:blob]

      [%{"metadata" => layer_metadata}] = blob.metadata["ash_storage"]["blob_io"]["layers"]
      refute Map.has_key?(layer_metadata["wrapped_dek"], "backup")

      # recover_dek/2 reports the absence cleanly.
      {_pub, priv} = AshEnvelope.generate_key_pair()
      assert {:error, :no_backup_wrap} = AshEnvelope.recover_dek(blob, priv)
    end
  end

  describe "BackupRotation.rotate/2" do
    test "rewraps a blob from previous to current backup key", %{actor: actor} do
      {old_pub, old_priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, old_pub)

      post =
        @resource
        |> Ash.create!(%{title: "Rotate me"}, domain: @domain)
        |> Ash.update!(
          %{io: "rotate this", filename: "r.txt", content_type: "text/plain"},
          action: :attach_document,
          domain: @domain,
          actor: actor
        )

      blob = post.__metadata__[:blob]
      assert BackupRotation.needs_rotation?(blob) == false

      # Rotate config: new key becomes current.
      {new_pub, new_priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, new_pub)
      Application.put_env(:ash_envelope, :backup_public_key_previous, old_pub)

      # Re-read so the change above doesn't trick us with stale data.
      {:ok, blob} = Ash.get(@blob_resource, blob.id, domain: @domain)
      assert BackupRotation.needs_rotation?(blob) == true

      assert {:ok, rotated} =
               BackupRotation.rotate(blob, previous_private_key: old_priv)

      # Now the backup field is tagged with the new key's fingerprint and
      # recoverable with the new private key.
      [%{"metadata" => layer_metadata}] =
        rotated.metadata["ash_storage"]["blob_io"]["layers"]

      assert layer_metadata["wrapped_dek"]["backup"]["key_id"] == Backup.key_id(new_pub)

      {:ok, ciphertext} = AshStorage.Service.Test.download(rotated.key, [])

      assert {:ok, "rotate this"} =
               AshEnvelope.recover_plaintext(rotated, ciphertext, new_priv)

      # The old private key no longer unwraps the rotated blob.
      assert {:error, :decryption_failed} =
               AshEnvelope.recover_dek(rotated, old_priv)

      assert BackupRotation.needs_rotation?(rotated) == false
    end

    test "wrong previous private key fails cleanly and leaves the blob unchanged", %{
      actor: actor
    } do
      {old_pub, _old_priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, old_pub)

      post =
        @resource
        |> Ash.create!(%{title: "Wrong key"}, domain: @domain)
        |> Ash.update!(
          %{io: "don't clobber me", filename: "w.txt", content_type: "text/plain"},
          action: :attach_document,
          domain: @domain,
          actor: actor
        )

      blob = post.__metadata__[:blob]

      {new_pub, _new_priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, new_pub)
      Application.put_env(:ash_envelope, :backup_public_key_previous, old_pub)

      {:ok, blob} = Ash.get(@blob_resource, blob.id, domain: @domain)

      {_pub, wrong_priv} = AshEnvelope.generate_key_pair()

      assert {:error, :decryption_failed} =
               BackupRotation.rotate(blob, previous_private_key: wrong_priv)

      # Nothing was written: the stored metadata still carries the old
      # key's fingerprint and the blob still needs rotation.
      {:ok, reread} = Ash.get(@blob_resource, blob.id, domain: @domain)
      assert reread.metadata == blob.metadata

      [%{"metadata" => layer_metadata}] = reread.metadata["ash_storage"]["blob_io"]["layers"]
      assert layer_metadata["wrapped_dek"]["backup"]["key_id"] == Backup.key_id(old_pub)
      assert BackupRotation.needs_rotation?(reread) == true
    end

    test "is idempotent when the blob already uses the current key", %{actor: actor} do
      {pub, _priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, pub)

      {_pub, dummy_priv} = AshEnvelope.generate_key_pair()

      post =
        @resource
        |> Ash.create!(%{title: "Already current"}, domain: @domain)
        |> Ash.update!(
          %{io: "y", filename: "y.txt", content_type: "text/plain"},
          action: :attach_document,
          domain: @domain,
          actor: actor
        )

      blob = post.__metadata__[:blob]

      # Dummy private key would fail unwrap, but we should short-circuit
      # before attempting because the key_id already matches.
      assert {:ok, ^blob} = BackupRotation.rotate(blob, previous_private_key: dummy_priv)
    end
  end

  describe "BackupRotation.rotate_resource/2 + check_only" do
    test "reports stale count without writing in --check-only mode", %{actor: actor} do
      {old_pub, _old_priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, old_pub)

      _post =
        @resource
        |> Ash.create!(%{title: "check"}, domain: @domain)
        |> Ash.update!(
          %{io: "check this", filename: "c.txt", content_type: "text/plain"},
          action: :attach_document,
          domain: @domain,
          actor: actor
        )

      {new_pub, _new_priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, new_pub)

      assert {:ok, %{rotated: 0, remaining_stale: 1}} =
               BackupRotation.rotate_resource(@blob_resource,
                 domain: @domain,
                 check_only: true
               )
    end
  end

  defp restore(key, nil), do: Application.delete_env(:ash_envelope, key)
  defp restore(key, value), do: Application.put_env(:ash_envelope, key, value)
end
