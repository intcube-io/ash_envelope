defmodule AshEnvelope.Test.Storage.Attachment do
  @moduledoc false

  use Ash.Resource,
    domain: AshEnvelope.Test.Storage.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshStorage.AttachmentResource]

  ets do
    private?(true)
  end

  attributes do
    uuid_primary_key :id
  end

  attachment do
    blob_resource(AshEnvelope.Test.Storage.Blob)
    belongs_to_resource(:encrypted_post, AshEnvelope.Test.Storage.EncryptedPost)
  end
end
