defmodule AshEnvelope.Test.Storage.Blob do
  @moduledoc false

  use Ash.Resource,
    domain: AshEnvelope.Test.Storage.Domain,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshStorage.BlobResource]

  ets do
    private?(true)
  end

  attributes do
    uuid_primary_key :id
  end
end
