defmodule AshEnvelope.Test.Storage.Domain do
  @moduledoc false
  use Ash.Domain

  resources do
    resource AshEnvelope.Test.Storage.Blob
    resource AshEnvelope.Test.Storage.Attachment
    resource AshEnvelope.Test.Storage.EncryptedPost
    resource AshEnvelope.Test.Storage.PlainAttachment
    resource AshEnvelope.Test.Storage.PlainPost
  end
end
