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

    # The struct handed to rotate/2 usually comes out of a long Ash.stream!
    # pass and may be stale. Everything rotation writes must derive from
    # the row as it is *now*: if the row's envelope was replaced (new DEK,
    # new backup wrap under the previous key) after the snapshot was
    # taken, re-wrapping the snapshot's DEK would persist a backup of a
    # key the blob no longer uses — an unrecoverable blob whose key_id
    # claims it is current.
    test "re-wraps the DEK from the stored row, not from the streamed snapshot", %{
      actor: actor
    } do
      {old_pub, old_priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, old_pub)

      post =
        @resource
        |> Ash.create!(%{title: "Stale snapshot"}, domain: @domain)
        |> Ash.update!(
          %{io: "stale", filename: "s.txt", content_type: "text/plain"},
          action: :attach_document,
          domain: @domain,
          actor: actor
        )

      snapshot = post.__metadata__[:blob]
      {:ok, original_dek} = AshEnvelope.recover_dek(snapshot, old_priv)

      # Concurrent writer replaces the row's envelope with a fresh DEK,
      # still escrowed under the (then current) old backup key.
      replacement_dek = AshEnvelope.generate_dek()

      [%{"metadata" => layer_metadata} = entry] =
        snapshot.metadata["ash_storage"]["blob_io"]["layers"]

      replaced_layer_metadata =
        put_in(
          layer_metadata,
          ["wrapped_dek", "backup"],
          Backup.wrap_for_public_key(replacement_dek, old_pub)
        )

      replaced_metadata =
        put_in(snapshot.metadata, ["ash_storage", "blob_io", "layers"], [
          Map.put(entry, "metadata", replaced_layer_metadata)
        ])

      {:ok, _} =
        Ash.update(snapshot, %{metadata: replaced_metadata},
          action: :update_metadata,
          domain: @domain
        )

      {new_pub, new_priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, new_pub)
      Application.put_env(:ash_envelope, :backup_public_key_previous, old_pub)

      # Rotation is driven from the stale snapshot.
      assert {:ok, rotated} = BackupRotation.rotate(snapshot, previous_private_key: old_priv)

      assert AshEnvelope.recover_dek(rotated, new_priv) == {:ok, replacement_dek}
      refute AshEnvelope.recover_dek(rotated, new_priv) == {:ok, original_dek}
    end

    test "a stale snapshot of a row that was already rotated is a no-op", %{actor: actor} do
      {old_pub, old_priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, old_pub)

      post =
        @resource
        |> Ash.create!(%{title: "Already rotated elsewhere"}, domain: @domain)
        |> Ash.update!(
          %{io: "twice", filename: "t.txt", content_type: "text/plain"},
          action: :attach_document,
          domain: @domain,
          actor: actor
        )

      snapshot = post.__metadata__[:blob]

      {new_pub, new_priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, new_pub)
      Application.put_env(:ash_envelope, :backup_public_key_previous, old_pub)

      # Another run rotates the row first.
      {:ok, blob} = Ash.get(@blob_resource, snapshot.id, domain: @domain)
      assert {:ok, _} = BackupRotation.rotate(blob, previous_private_key: old_priv)

      # This run still holds the pre-rotation snapshot and does not even
      # hold a usable previous key; it must observe the row is current
      # rather than fail (or re-wrap) based on the snapshot.
      {_pub, unrelated_priv} = AshEnvelope.generate_key_pair()
      assert {:ok, fresh} = BackupRotation.rotate(snapshot, previous_private_key: unrelated_priv)
      assert BackupRotation.needs_rotation?(fresh) == false
      assert {:ok, _dek} = AshEnvelope.recover_dek(fresh, new_priv)
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

      assert {:ok, %{rotated: 0, remaining_stale: 1, failed: %{}}} =
               BackupRotation.rotate_resource(@blob_resource,
                 domain: @domain,
                 check_only: true
               )
    end

    # A blob whose rotation fails is still counted as stale (the CLI's
    # exit-1 gate), but the operator also needs to know *why* — a wrong
    # previous key, an authorization failure and a lost row look
    # identical as a bare "remaining_stale" count.
    test "reports per-reason failure counts instead of swallowing them", %{actor: actor} do
      {old_pub, _old_priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, old_pub)

      _post =
        @resource
        |> Ash.create!(%{title: "fail"}, domain: @domain)
        |> Ash.update!(
          %{io: "fail this", filename: "f.txt", content_type: "text/plain"},
          action: :attach_document,
          domain: @domain,
          actor: actor
        )

      {new_pub, _new_priv} = AshEnvelope.generate_key_pair()
      Application.put_env(:ash_envelope, :backup_public_key, new_pub)
      Application.put_env(:ash_envelope, :backup_public_key_previous, old_pub)

      {_pub, wrong_priv} = AshEnvelope.generate_key_pair()

      assert {:ok, %{rotated: 0, remaining_stale: 1, failed: %{decryption_failed: 1}}} =
               BackupRotation.rotate_resource(@blob_resource,
                 domain: @domain,
                 previous_private_key: wrong_priv
               )
    end
  end

  defp restore(key, nil), do: Application.delete_env(:ash_envelope, key)
  defp restore(key, value), do: Application.put_env(:ash_envelope, key, value)
end
