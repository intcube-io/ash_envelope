defmodule AshEnvelope.BlobIO.VariantTempCleanupTest do
  @moduledoc """
  Locks the upstream `AshStorage.VariantGenerator` contract that
  temporary files are removed on every exit path of the transform
  call, including when the transform raises.

  This is **SR29 / T21**: the variant pipeline holds the unwrapped DEK
  in process memory and the decrypted source bytes on disk for the
  duration of the transform. If the temp-file cleanup were skipped on
  crash, the decrypted plaintext would persist on disk beyond the
  transform window.

  The `try/after` block in `AshStorage.VariantGenerator.run_transform/3`
  is layer-independent — it runs the same code whether or not the
  source bytes came from an encrypted layer. The test uses an
  unencrypted attachment (`PlainPost`) so the cleanup behavior is
  isolated from key-manager dispatch. The variant generator does not
  currently pass an `actor` through to `BlobIO.read/3`, so running this
  against the encrypted `EncryptedPost` would fail at the read step
  before reaching the cleanup code under test.
  """

  use ExUnit.Case, async: false

  alias AshStorage.VariantDefinition
  alias AshStorage.VariantGenerator

  defmodule RecordingCrash do
    @moduledoc false
    @behaviour AshStorage.Variant

    @impl true
    def accept?(_content_type), do: true

    @impl true
    def transform(source_path, dest_path, opts) do
      pid = Keyword.fetch!(opts, :test_pid)
      source_existed? = File.exists?(source_path)
      File.write!(dest_path, "partial output before crash")
      send(pid, {:transform_called, source_path, dest_path, source_existed?})
      raise "boom"
    end
  end

  @domain AshEnvelope.Test.Storage.Domain
  @resource AshEnvelope.Test.Storage.PlainPost

  setup do
    AshStorage.Service.Test.start()
    AshStorage.Service.Test.reset!()
    :ok
  end

  test "removes both source and destination temp files when the transform crashes" do
    post = Ash.create!(@resource, %{}, domain: @domain)

    post =
      Ash.update!(
        post,
        %{io: "plaintext source", filename: "src.txt", content_type: "text/plain"},
        action: :attach_document,
        domain: @domain
      )

    blob = post.__metadata__[:blob]
    assert blob, "expected an attached blob"

    {:ok, attachment_def} = AshStorage.Info.attachment(@resource, :document)

    variant_def = %VariantDefinition{
      name: :crash_test,
      module: {RecordingCrash, [test_pid: self()]},
      generate: :on_demand
    }

    assert_raise RuntimeError, "boom", fn ->
      VariantGenerator.generate(blob, variant_def, @resource, attachment_def)
    end

    assert_receive {:transform_called, source_path, dest_path, source_existed?}, 1_000

    assert source_existed?,
           "expected the generator to have written the source temp file before invoking transform; " <>
             "if upstream changed the contract to stream bytes instead, this test no longer covers SR29"

    refute File.exists?(source_path),
           "source temp file #{source_path} should have been removed after the crash"

    refute File.exists?(dest_path),
           "dest temp file #{dest_path} (written by the transform before crashing) " <>
             "should have been removed by the generator's try/after cleanup"
  end
end
