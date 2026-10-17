defmodule Mix.Tasks.AshEnvelope.RotateBackupKey do
  @moduledoc """
  Rotate the BlobIO backup-key wrap on every blob in the named resources.

  Walks each resource's blobs, re-wraps the per-blob DEK from the previous
  backup public key to the currently-configured one, and persists the
  updated layer metadata via the blob's `:update_metadata` action.

  Exits with status 1 if any blob in any named resource is still wrapped
  to a key that doesn't match the configured `:backup_public_key` after
  the rotation pass. Run with `--check-only` first to see counts without
  writing.

  ## Usage

      mix ash_envelope.rotate_backup_key \\
        --domain MyApp.Catalog \\
        --resources MyApp.Document.Blob,MyApp.Photo.Blob \\
        --previous-private-key-path /secure/k1.priv \\
        [--batch-size 1000] \\
        [--check-only]

  ## Options

    * `--domain` — Ash domain hosting the blob resources (required).
    * `--resources` — comma-separated list of blob resource modules to
      walk (required). Each resource must use `AshStorage.BlobResource`
      so the `:update_metadata` action is available.
    * `--previous-private-key-path` — path to a file containing the
      32-byte previous backup private key. The file may hold raw bytes
      (exactly 32) or a base64-encoded 32-byte binary. Read into memory
      only for the duration of the task. Not required with
      `--check-only`.
    * `--batch-size` — `Ash.stream!` batch size, defaults to `1000`.
    * `--check-only` — count stale blobs without writing. Exits non-zero
      if any are stale, zero otherwise.

  ## Recommended sequence

  1. Configure both keys in runtime config:

         config :ash_envelope,
           backup_public_key: <NEW_PUBLIC_KEY>,
           backup_public_key_previous: <OLD_PUBLIC_KEY>

  2. Deploy. New writes wrap to the new key; old blobs still carry the
     old wrap.

  3. Run `mix ash_envelope.rotate_backup_key --check-only ...` to see how
     many blobs are stale.

  4. Run the same command without `--check-only` to perform the
     rewrites.

  5. Re-run with `--check-only` to confirm zero remaining stale blobs.

  6. Remove `:backup_public_key_previous` from config. Retire the
     previous key's private half (cold storage rotation).
  """

  use Mix.Task

  alias AshEnvelope.BlobIO.{Backup, BackupRotation}

  @shortdoc "Rotate BlobIO backup-key wraps across encrypted blobs."

  @switches [
    domain: :string,
    resources: :string,
    previous_private_key_path: :string,
    batch_size: :integer,
    check_only: :boolean
  ]

  @impl true
  def run(argv) do
    Mix.Task.run("app.start")

    # Strict parsing: this task performs destructive writes, so a
    # misspelled switch (e.g. a typo'd --check-only) must abort rather
    # than be silently discarded.
    opts =
      case OptionParser.parse(argv, strict: @switches) do
        {opts, _, []} ->
          opts

        {_, _, invalid} ->
          flags = Enum.map_join(invalid, ", ", &elem(&1, 0))
          Mix.raise("unknown or invalid option(s): #{flags}")
      end

    domain = parse_domain!(opts)
    resources = parse_resources!(opts)
    check_only? = Keyword.get(opts, :check_only, false)
    batch_size = Keyword.get(opts, :batch_size, 1000)

    if is_nil(Backup.current_public_key()) do
      Mix.raise("config :ash_envelope, :backup_public_key is not set; nothing to rotate to")
    end

    previous_private_key = if check_only?, do: nil, else: load_previous_private_key!(opts)

    run_opts =
      [
        domain: domain,
        batch_size: batch_size,
        check_only: check_only?
      ]
      |> maybe_put(:previous_private_key, previous_private_key)

    totals =
      Enum.reduce(
        resources,
        %{rotated: 0, skipped: %{}, failed: %{}, remaining_stale: 0},
        fn resource, acc ->
          Mix.shell().info("rotating #{inspect(resource)} ...")

          case rotate_resource(resource, run_opts) do
            {:ok, result} ->
              Mix.shell().info(
                "  #{inspect(resource)}: rotated=#{result.rotated} remaining_stale=#{result.remaining_stale} failed=#{inspect(result.failed)} skipped=#{inspect(result.skipped)}"
              )

              merge_totals(acc, result)

            {:error, reason} ->
              Mix.shell().error(
                "  #{inspect(resource)}: rotation failed: #{format_reason(reason)}"
              )

              exit({:shutdown, 1})
          end
        end
      )

    Mix.shell().info("---")
    Mix.shell().info("totals:")
    Mix.shell().info("  rotated: #{totals.rotated}")
    Mix.shell().info("  remaining_stale: #{totals.remaining_stale}")
    Mix.shell().info("  failed: #{inspect(totals.failed)}")
    Mix.shell().info("  skipped: #{inspect(totals.skipped)}")

    if totals.remaining_stale > 0 do
      Mix.shell().error(
        "#{totals.remaining_stale} blob(s) still wrapped to a non-current backup key; refusing to declare success"
      )

      exit({:shutdown, 1})
    end
  end

  # `BackupRotation.rotate_resource/2` streams via `Ash.stream!/2`, which
  # raises on failure. Convert raised errors into the `{:error, reason}`
  # shape its spec also allows, so the caller above can report cleanly
  # and exit non-zero instead of crashing with a bare exception.
  defp rotate_resource(resource, run_opts) do
    BackupRotation.rotate_resource(resource, run_opts)
  rescue
    error -> {:error, error}
  end

  defp format_reason(%{__exception__: true} = error), do: Exception.message(error)
  defp format_reason(reason), do: inspect(reason)

  defp parse_domain!(opts) do
    case Keyword.fetch(opts, :domain) do
      {:ok, value} -> Module.concat([value])
      :error -> Mix.raise("--domain is required")
    end
  end

  defp parse_resources!(opts) do
    case Keyword.fetch(opts, :resources) do
      {:ok, value} ->
        value
        |> String.split(",", trim: true)
        |> Enum.map(&Module.concat([&1]))

      :error ->
        Mix.raise("--resources is required")
    end
  end

  defp load_previous_private_key!(opts) do
    case Keyword.fetch(opts, :previous_private_key_path) do
      {:ok, path} ->
        case File.read(path) do
          {:ok, <<raw::binary-32>>} ->
            raw

          {:ok, raw} ->
            case raw |> String.trim() |> Base.decode64() do
              {:ok, <<key::binary-32>>} ->
                key

              _ ->
                Mix.raise(
                  "--previous-private-key-path #{path}: contents must be 32 raw bytes or base64-encoded 32 bytes"
                )
            end

          {:error, reason} ->
            Mix.raise(
              "could not read --previous-private-key-path #{path}: #{:file.format_error(reason)}"
            )
        end

      :error ->
        Mix.raise("--previous-private-key-path is required unless --check-only is given")
    end
  end

  defp maybe_put(opts, _key, nil), do: opts
  defp maybe_put(opts, key, value), do: Keyword.put(opts, key, value)

  defp merge_totals(acc, %{rotated: r, skipped: s, failed: f, remaining_stale: rs}) do
    %{
      rotated: acc.rotated + r,
      remaining_stale: acc.remaining_stale + rs,
      failed: Map.merge(acc.failed, f, fn _k, a, b -> a + b end),
      skipped: Map.merge(acc.skipped, s, fn _k, a, b -> a + b end)
    }
  end
end
