defmodule Mix.Tasks.AshEnvelope.RotateBackupKeyTest do
  @moduledoc """
  This task performs destructive writes, so its option handling must be
  strict: a misspelled switch (e.g. a typo'd `--check-only`) has to abort
  instead of being silently discarded and proceeding to real writes.
  """

  use ExUnit.Case, async: false

  test "rejects unknown switches instead of silently discarding them" do
    assert_raise Mix.Error, ~r/unknown or invalid option/, fn ->
      Mix.Tasks.AshEnvelope.RotateBackupKey.run([
        "--domain",
        "MyApp.Catalog",
        "--resources",
        "MyApp.Document.Blob",
        "--check-onli"
      ])
    end
  end

  test "rejects switches with invalid values" do
    assert_raise Mix.Error, ~r/unknown or invalid option/, fn ->
      Mix.Tasks.AshEnvelope.RotateBackupKey.run([
        "--domain",
        "MyApp.Catalog",
        "--resources",
        "MyApp.Document.Blob",
        "--batch-size",
        "lots",
        "--check-only"
      ])
    end
  end
end
