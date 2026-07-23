defmodule AshEnvelope.Test.Storage.PlainPost do
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
    attachment_resource(AshEnvelope.Test.Storage.PlainAttachment)

    has_one_attached(:document)
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
    end

    update :update do
      primary? true
    end
  end

  attributes do
    uuid_primary_key :id
  end
end
