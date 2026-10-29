defmodule AshEnvelope.Test.BlobIO.Domain do
  @moduledoc false
  use Ash.Domain

  resources do
    resource AshEnvelope.Test.BlobIO.PoliciedGrant
  end
end
