defmodule AshEnvelope.Test.Storage.EncryptedPost do
  @moduledoc false

  use Ash.Resource,
    domain: AshEnvelope.Test.Storage.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshStorage]

  ets do
    private?(true)
  end

  storage do
    service({AshStorage.Service.Test, []})
    blob_resource(AshEnvelope.Test.Storage.Blob)
    attachment_resource(AshEnvelope.Test.Storage.Attachment)

    layer(
      {AshStorage.Layer.Encryption,
       key_manager:
         {AshEnvelope.BlobIO.KeyManagers.Asymmetric,
          actor_public_key_attribute: :public_key, actor_private_key_attribute: :private_key}},
      metadata_key: "encrypted-post"
    )

    has_one_attached(:document)
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      accept [:title]
    end

    update :update do
      primary? true
      accept [:title]
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :title, :string do
      allow_nil? false
      public? true
    end
  end
end
