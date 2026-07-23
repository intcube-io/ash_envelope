defmodule AshEnvelope.BlobIO.EncryptionLayerContractTest do
  @moduledoc """
  Contract tests for `AshStorage.Layer.Encryption` callbacks that
  ash_envelope's threat model depends on. If upstream relaxes these
  contracts, these tests must fail.

  Locks:

    * **SR28 / T22** — `direct_upload/2` returns an error for encrypted
      attachments. The threat model assumes attackers cannot obtain a
      presigned URL that would let them upload attacker-chosen bytes
      under a key that maps to an encrypted attachment.

    * **SR31 / T9** — `serving/2` never emits a direct service-URL
      strategy. With `:proxy_base_url` configured, the layer forces a
      proxy serve. Without it, the layer marks the blob `:not_servable`
      rather than falling through to a service URL.
  """

  use ExUnit.Case, async: true

  alias AshStorage.BlobIO.DirectUploads
  alias AshStorage.BlobIO.Serving
  alias AshStorage.Layer.Encryption, as: EncryptionLayer

  describe "direct_upload/2 (SR28 / T22)" do
    test "rejects direct uploads with empty opts" do
      operation = %DirectUploads.Operation{}

      assert {:error, :encryption_layer_does_not_support_direct_upload} =
               EncryptionLayer.direct_upload(operation, [])
    end

    test "rejects direct uploads even when proxy and key_manager are configured" do
      operation = %DirectUploads.Operation{}

      assert {:error, :encryption_layer_does_not_support_direct_upload} =
               EncryptionLayer.direct_upload(operation,
                 proxy_base_url: "/storage",
                 key_manager:
                   {AshEnvelope.BlobIO.KeyManagers.Asymmetric,
                    actor_public_key_attribute: :public_key,
                    actor_private_key_attribute: :private_key}
               )
    end
  end

  describe "serving/2 (SR31 / T9)" do
    test "forces a proxy serve when proxy_base_url is configured" do
      operation = %Serving.Operation{call_opts: []}

      assert {:ok, %Serving.Operation{} = served} =
               EncryptionLayer.serving(operation, proxy_base_url: "/storage")

      assert served.call_opts[:serve] == :proxy,
             "expected :proxy_base_url to force :serve, :proxy in call_opts"

      assert is_nil(served.strategy),
             "layer must leave strategy nil so the framework resolves to proxy; " <>
               "a non-nil strategy here could short-circuit to a service URL"
    end

    test "marks the blob :not_servable when proxy_base_url is missing" do
      operation = %Serving.Operation{call_opts: []}

      assert {:ok, %Serving.Operation{strategy: :not_servable}} =
               EncryptionLayer.serving(operation, [])
    end

    test "marks the blob :not_servable when proxy_base_url is not a binary" do
      operation = %Serving.Operation{call_opts: []}

      assert {:ok, %Serving.Operation{strategy: :not_servable}} =
               EncryptionLayer.serving(operation, proxy_base_url: nil)

      assert {:ok, %Serving.Operation{strategy: :not_servable}} =
               EncryptionLayer.serving(operation, proxy_base_url: :proxy)
    end

    test "call_opts on the operation override layer opts but cannot select a service URL" do
      operation = %Serving.Operation{call_opts: [proxy_base_url: "/storage"]}

      assert {:ok, %Serving.Operation{} = served} =
               EncryptionLayer.serving(operation, [])

      assert served.call_opts[:serve] == :proxy
      assert is_nil(served.strategy)
    end
  end
end
