defmodule AshEnvelope.BlobIO.BackupRotation do
  @moduledoc """
  Rotates the backup wrap on encrypted blobs from a previous backup
  public key to the currently-configured one.

  Each blob's encryption-layer metadata embeds a `"backup"` map carrying
  the DEK wrapped to the current `:backup_public_key`. When the integrator
  rotates that key, every existing blob's `"backup"` field still points at
  the *old* key. This module re-wraps each blob's DEK with the new public
  key. The `key_id` fingerprint inside the wrap lets the caller find
  stale blobs without unwrapping anything.

  Driven by the `mix ash_envelope.rotate_backup_key` task; the functions
  here are kept module-level so integrators can write their own
  rotation jobs / tests against them.
  """

  alias AshEnvelope.BlobIO.Backup
  alias AshStorage.BlobIO.Support

  @encryption_format "aes-256-gcm"

  @typedoc "Reason a blob can be skipped or rejected by rotation."
  @type skip_reason ::
          :no_encryption_layer
          | :no_backup_wrap
          | {:unsupported_layer_chain, pos_integer()}
          | :already_current

  @doc """
  Return `true` when `blob`'s encryption layer carries a backup wrap whose
  `key_id` does not match the currently-configured public key.

  Returns `false` for blobs already wrapped to the current key, blobs with
  no backup wrap at all, and blobs whose layer chain isn't recognised. The
  rotation CLI's final verification pass treats only `true` results as
  pending work.
  """
  @spec needs_rotation?(map() | struct()) :: boolean()
  def needs_rotation?(blob_or_metadata) do
    case classify(blob_or_metadata) do
      {:ok, _layer_metadata, _backup, key_id} ->
        current_key_id = Backup.current_key_id()
        not is_nil(current_key_id) and key_id != current_key_id

      {:error, _} ->
        false
    end
  end

  @doc """
  Rotate `blob`'s backup wrap from the previous key to the current key.

  Returns `{:ok, updated_blob}` when the rotation completes (or when the
  blob was already wrapped to the current key — idempotent), or
  `{:error, reason}` for blobs that can't be rotated. The latter is the
  common case during integration; the CLI surfaces the count by reason.

  Required opts:

    * `:previous_private_key` — 32-byte X25519 private key matching the
      blob's existing backup `key_id`.

  Other opts are passed through to `Ash.update/3` as `:ash_opts`.
  """
  @spec rotate(struct(), keyword()) :: {:ok, struct()} | {:error, term()}
  def rotate(blob, opts) do
    with {:ok, previous_private_key} <- fetch_previous_private_key(opts),
         {:ok, current_public_key} <- fetch_current_public_key(),
         {:ok, _layer_index, _layer_entry, _layer_metadata, backup, _key_id} <-
           locate_layer(blob) do
      if Backup.key_id(current_public_key) == backup["key_id"] do
        {:ok, blob}
      else
        do_rotate(blob, backup, previous_private_key, current_public_key, opts)
      end
    end
  end

  @doc """
  Stream the resource's blobs and return `{rotated, skipped_by_reason,
  failed_by_reason, remaining_stale}` after a single rotation pass.

  `:check_only` skips the writes but still reports counts.

  `remaining_stale` counts every blob still wrapped to a non-current key
  after the pass, whether because of `:check_only` or because its
  rotation failed. `failed` breaks the failures down by reason (for
  example `%{decryption_failed: 3}` when `:previous_private_key` does
  not match the blobs' backup wrap); exceptions are keyed by their
  module. A failure never aborts the pass.

  `:ash_opts` are passed to the per-blob `Ash.get/3` and `Ash.update/3`
  calls; `:domain` is filled in from the required `:domain` option when
  not given.
  """
  @spec rotate_resource(module(), keyword()) ::
          {:ok,
           %{
             rotated: non_neg_integer(),
             skipped: %{skip_reason() => non_neg_integer()},
             failed: %{term() => non_neg_integer()},
             remaining_stale: non_neg_integer()
           }}
          | {:error, term()}
  def rotate_resource(resource, opts) do
    batch_size = Keyword.get(opts, :batch_size, 1000)
    domain = Keyword.fetch!(opts, :domain)
    check_only? = Keyword.get(opts, :check_only, false)

    ash_opts =
      opts
      |> Keyword.get(:ash_opts, [])
      |> Keyword.put_new(:domain, domain)

    rotate_opts = Keyword.put(opts, :ash_opts, ash_opts)

    resource
    |> Ash.Query.new()
    |> Ash.stream!(domain: domain, batch_size: batch_size)
    |> Enum.reduce(%{rotated: 0, skipped: %{}, failed: %{}, remaining_stale: 0}, fn blob, acc ->
      case classify(blob) do
        {:ok, _layer_metadata, _backup, key_id} ->
          current_key_id = Backup.current_key_id()

          cond do
            key_id == current_key_id ->
              acc

            check_only? ->
              %{acc | remaining_stale: acc.remaining_stale + 1}

            true ->
              case rotate(blob, rotate_opts) do
                {:ok, _} ->
                  %{acc | rotated: acc.rotated + 1}

                {:error, reason} ->
                  acc
                  |> bump_failed(reason)
                  |> Map.update!(:remaining_stale, &(&1 + 1))
              end
          end

        {:error, reason} ->
          bump_skipped(acc, reason)
      end
    end)
    |> then(&{:ok, &1})
  end

  # Writes back the blob's entire metadata map — an unguarded
  # read-modify-write. The blob typically arrives from a long batch
  # stream, so it is re-fetched first and *everything* — the backup wrap
  # that is unwrapped, the key_id that is compared, the metadata that is
  # rewritten — comes from that fresh row. Unwrapping the DEK from the
  # streamed snapshot and writing it into the fresh row would, if the
  # row's envelope changed in between, persist a backup wrap of a DEK
  # the blob no longer uses, i.e. an unrecoverable blob that reports
  # itself as current. The re-fetch also shrinks the clobber window for
  # concurrent metadata writers from the whole batch pass to
  # milliseconds; full protection needs optimistic locking upstream in
  # ash_storage.
  defp do_rotate(blob, _snapshot_backup, previous_private_key, current_public_key, opts) do
    ash_opts = Keyword.get(opts, :ash_opts, [])

    with {:ok, fresh_blob} <- refetch(blob, ash_opts),
         {:ok, layer_index, layer_entry, layer_metadata, backup, key_id} <-
           locate_layer(fresh_blob) do
      if key_id == Backup.key_id(current_public_key) do
        {:ok, fresh_blob}
      else
        with {:ok, dek} <- Backup.unwrap_backup(backup, previous_private_key) do
          new_backup = Backup.wrap_for_public_key(dek, current_public_key)
          wrapped_dek = Map.fetch!(layer_metadata, "wrapped_dek")
          new_wrapped_dek = Backup.put_backup(wrapped_dek, new_backup)
          new_layer_metadata = Map.put(layer_metadata, "wrapped_dek", new_wrapped_dek)

          new_layer_entry = put_entry_metadata(layer_entry, new_layer_metadata)
          layer_chain = layer_chain(fresh_blob.metadata)
          new_layer_chain = List.replace_at(layer_chain, layer_index, new_layer_entry)

          new_metadata = Support.put_layer_metadata(fresh_blob.metadata, new_layer_chain)

          Ash.update(
            fresh_blob,
            %{metadata: new_metadata},
            Keyword.merge(ash_opts, action: :update_metadata)
          )
        end
      end
    end
  end

  defp refetch(blob, ash_opts) do
    Ash.get(
      blob.__struct__,
      blob.id,
      Keyword.take(ash_opts, [:domain, :actor, :authorize?, :tenant])
    )
  end

  defp classify(%{metadata: metadata}), do: classify(metadata)

  defp classify(metadata) when is_map(metadata) do
    case layer_chain(metadata) do
      [] ->
        {:error, :no_encryption_layer}

      layers ->
        encryption_entries =
          for {entry, index} <- Enum.with_index(layers),
              %{"format" => @encryption_format} = layer_metadata <- [entry_metadata(entry)],
              do: {index, entry, layer_metadata}

        case encryption_entries do
          [{_index, _entry, layer_metadata}] ->
            classify_backup(layer_metadata)

          [] ->
            {:error, :no_encryption_layer}

          many ->
            {:error, {:unsupported_layer_chain, length(many)}}
        end
    end
  end

  defp classify(_), do: {:error, :no_encryption_layer}

  defp classify_backup(layer_metadata) do
    case layer_metadata do
      %{"wrapped_dek" => %{"backup" => %{"key_id" => key_id} = backup}} ->
        {:ok, layer_metadata, backup, key_id}

      _ ->
        {:error, :no_backup_wrap}
    end
  end

  defp locate_layer(%{metadata: metadata} = _blob) when is_map(metadata) do
    layers = layer_chain(metadata)

    encryption_entries =
      for {entry, index} <- Enum.with_index(layers),
          %{"format" => @encryption_format} = layer_metadata <- [entry_metadata(entry)],
          do: {index, entry, layer_metadata}

    case encryption_entries do
      [{index, entry, layer_metadata}] ->
        with {:ok, ^layer_metadata, backup, key_id} <- classify_backup(layer_metadata) do
          {:ok, index, entry, layer_metadata, backup, key_id}
        end

      [] ->
        {:error, :no_encryption_layer}

      many ->
        {:error, {:unsupported_layer_chain, length(many)}}
    end
  end

  defp locate_layer(_), do: {:error, :no_encryption_layer}

  defp layer_chain(metadata),
    do: get_in(metadata, ["ash_storage", "blob_io", "layers"]) || []

  defp entry_metadata(%{"metadata" => m}) when is_map(m), do: m
  defp entry_metadata(%{metadata: m}) when is_map(m), do: m
  defp entry_metadata(_), do: %{}

  defp put_entry_metadata(%{"metadata" => _} = entry, metadata),
    do: Map.put(entry, "metadata", metadata)

  defp put_entry_metadata(%{metadata: _} = entry, metadata),
    do: Map.put(entry, :metadata, metadata)

  defp put_entry_metadata(entry, metadata) when is_map(entry),
    do: Map.put(entry, "metadata", metadata)

  defp fetch_previous_private_key(opts) do
    case Keyword.get(opts, :previous_private_key) do
      <<key::binary-32>> -> {:ok, key}
      _ -> {:error, :previous_private_key_required}
    end
  end

  defp fetch_current_public_key do
    case Backup.current_public_key() do
      nil -> {:error, :backup_public_key_not_configured}
      key -> {:ok, key}
    end
  end

  defp bump_skipped(acc, reason),
    do: %{acc | skipped: Map.update(acc.skipped, reason, 1, &(&1 + 1))}

  defp bump_failed(acc, reason) do
    key = failure_key(reason)
    %{acc | failed: Map.update(acc.failed, key, 1, &(&1 + 1))}
  end

  # Collapse exception structs (Ash errors from get/update) to their
  # module so the breakdown stays countable and never carries record
  # contents into task output.
  defp failure_key(%{__exception__: true, __struct__: module}), do: module
  defp failure_key(reason) when is_atom(reason) or is_tuple(reason), do: reason
  defp failure_key(_reason), do: :unknown
end
