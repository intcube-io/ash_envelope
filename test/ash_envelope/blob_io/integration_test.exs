defmodule AshEnvelope.BlobIO.IntegrationTest do
  @moduledoc """
  End-to-end coverage that BlobIO + the AshEnvelope key managers compose
  correctly: writes encrypt before service upload, reads decrypt after
  service download, and the persisted layer metadata is enough to round-trip.
  """

  use ExUnit.Case, async: false

  alias AshStorage.BlobIO
  alias AshStorage.BlobIO.BlobContext

  @domain AshEnvelope.Test.Storage.Domain
  @resource AshEnvelope.Test.Storage.EncryptedPost

  setup do
    AshStorage.Service.Test.start()
    AshStorage.Service.Test.reset!()

    {pub, priv} = AshEnvelope.generate_key_pair()
    actor = %{id: Ash.UUID.generate(), public_key: pub, private_key: priv}

    %{actor: actor}
  end

  describe "attach -> read via Asymmetric key manager" do
    test "stored bytes are ciphertext; BlobIO.read decrypts with the actor", %{actor: actor} do
      post = Ash.create!(@resource, %{title: "My Post"}, domain: @domain)

      post =
        Ash.update!(
          post,
          %{io: "hello, encrypted world!", filename: "test.txt", content_type: "text/plain"},
          action: :attach_document,
          domain: @domain,
          actor: actor
        )

      blob = post.__metadata__[:blob]
      assert blob, "blob should be in record metadata after attach"

      {:ok, stored} = AshStorage.Service.Test.download(blob.key, [])
      refute stored == "hello, encrypted world!"

      {:ok, attachment} = AshStorage.Info.attachment(@resource, :document)

      read_bctx =
        BlobContext.new(
          resource: @resource,
          attachment: attachment,
          actor: actor,
          operation: :download
        )

      assert {:ok, "hello, encrypted world!"} = BlobIO.read(blob, read_bctx)
    end

    test "another actor cannot decrypt", %{actor: actor} do
      post = Ash.create!(@resource, %{title: "Secret"}, domain: @domain)

      post =
        Ash.update!(
          post,
          %{io: "for one recipient only", filename: "s.txt", content_type: "text/plain"},
          action: :attach_document,
          domain: @domain,
          actor: actor
        )

      blob = post.__metadata__[:blob]

      {pub2, priv2} = AshEnvelope.generate_key_pair()
      other = %{id: Ash.UUID.generate(), public_key: pub2, private_key: priv2}

      {:ok, attachment} = AshStorage.Info.attachment(@resource, :document)

      read_bctx =
        BlobContext.new(
          resource: @resource,
          attachment: attachment,
          actor: other,
          operation: :download
        )

      assert {:error, _} = BlobIO.read(blob, read_bctx)
    end
  end
end
