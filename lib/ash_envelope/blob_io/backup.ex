defmodule AshEnvelope.BlobIO.Backup do
  @moduledoc """
  Backup-key escrow for BlobIO-encrypted blobs.

  When `:backup_public_key` is configured, both `AshEnvelope.BlobIO.KeyManagers`
  embed an additional X25519 ECIES wrap of the DEK in the encryption layer's
  `wrapped_dek` metadata under the `"backup"` key. The matching private key
  lives outside the application database (cold storage, KMS, split key) and is
  only used during recovery.

  ## Configuration

      config :ash_envelope,
        backup_public_key: <32-byte binary or base64>,
        backup_public_key_previous: <32-byte binary or base64>  # only during rotation

  When `:backup_public_key` is unset, no backup wrap is written and the
  encrypted blob is unrecoverable without a principal grant. This is the
  default — backup escrow is strict opt-in.

  ## Wrap shape

      %{
        "format" => "x25519-ecies-v1",
        "key_id" => "<16-char hex>",
        "ciphertext" => "<base64 X25519-ECIES blob>"
      }

  `key_id` is the first 8 bytes of `SHA-256(public_key)`, hex-encoded — a
  short fingerprint of the public key the DEK was wrapped to. The rotation
  CLI uses it to identify blobs still wrapped to a retired key without
  needing to decrypt anything.
  """

  @format "x25519-ecies-v1"

  @doc "Current backup public key (32-byte binary) or nil if unset."
  @spec current_public_key() :: binary() | nil
  def current_public_key, do: resolve_key(:backup_public_key)

  @doc "Previous backup public key (32-byte binary) or nil if unset."
  @spec previous_public_key() :: binary() | nil
  def previous_public_key, do: resolve_key(:backup_public_key_previous)

  @doc "Short fingerprint of the configured current backup public key, or nil."
  @spec current_key_id() :: String.t() | nil
  def current_key_id, do: current_public_key() |> maybe_key_id()

  @doc "Short fingerprint of the configured previous backup public key, or nil."
  @spec previous_key_id() :: String.t() | nil
  def previous_key_id, do: previous_public_key() |> maybe_key_id()

  @doc "Short fingerprint of an X25519 public key (16 hex chars / 8 bytes)."
  @spec key_id(binary()) :: String.t()
  def key_id(public_key) when byte_size(public_key) == 32 do
    :sha256
    |> :crypto.hash(public_key)
    |> binary_part(0, 8)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Wrap `dek` with the configured current backup public key.

  Returns `nil` when no backup key is configured (caller embeds nothing in
  metadata). Returns the wrapped map otherwise.
  """
  @spec wrap_for_backup(binary()) :: map() | nil
  def wrap_for_backup(dek) when byte_size(dek) == 32 do
    case current_public_key() do
      nil -> nil
      public_key -> build_wrap(dek, public_key)
    end
  end

  @doc """
  Wrap `dek` with an explicit public key. Used by the rotation CLI when
  re-wrapping under a freshly-configured current key.
  """
  @spec wrap_for_public_key(binary(), binary()) :: map()
  def wrap_for_public_key(dek, public_key)
      when byte_size(dek) == 32 and byte_size(public_key) == 32 do
    build_wrap(dek, public_key)
  end

  @doc """
  Unwrap a backup map with the given private key. The map's `key_id` is
  informational only; the caller is responsible for choosing the right
  private key.
  """
  @spec unwrap_backup(map(), binary()) ::
          {:ok, binary()} | {:error, atom() | tuple()}
  def unwrap_backup(%{"format" => @format, "ciphertext" => ciphertext}, private_key)
      when is_binary(ciphertext) and byte_size(private_key) == 32 do
    with {:ok, decoded} <- decode_base64(ciphertext) do
      AshEnvelope.unwrap_dek(decoded, private_key)
    end
  end

  def unwrap_backup(_wrap, _private_key),
    do: {:error, {:invalid_backup_wrap_metadata, "wrapped_dek"}}

  @doc "Extract the backup map from a KeyManager `wrapped_dek` payload, or nil."
  @spec from_wrapped_dek(map()) :: map() | nil
  def from_wrapped_dek(%{"backup" => backup}) when is_map(backup), do: backup
  def from_wrapped_dek(_), do: nil

  @doc """
  Embed (or replace) the backup map inside a `wrapped_dek` payload. When
  `backup` is `nil`, the `"backup"` key is removed.
  """
  @spec put_backup(map(), map() | nil) :: map()
  def put_backup(wrapped_dek, nil) when is_map(wrapped_dek),
    do: Map.delete(wrapped_dek, "backup")

  def put_backup(wrapped_dek, %{} = backup) when is_map(wrapped_dek),
    do: Map.put(wrapped_dek, "backup", backup)

  defp build_wrap(dek, public_key) do
    %{
      "format" => @format,
      "key_id" => key_id(public_key),
      "ciphertext" => dek |> AshEnvelope.wrap_dek(public_key) |> Base.encode64()
    }
  end

  defp resolve_key(env_key) do
    case Application.get_env(:ash_envelope, env_key) do
      nil ->
        nil

      <<key::binary-32>> ->
        key

      raw when is_binary(raw) ->
        case Base.decode64(raw) do
          {:ok, <<key::binary-32>>} ->
            key

          _ ->
            raise ArgumentError,
                  "config :ash_envelope, #{inspect(env_key)} must be a 32-byte binary or base64-encoded 32-byte binary"
        end

      other ->
        raise ArgumentError,
              "config :ash_envelope, #{inspect(env_key)} must be a 32-byte binary or base64-encoded 32-byte binary (got #{inspect(other)})"
    end
  end

  defp maybe_key_id(nil), do: nil
  defp maybe_key_id(key), do: key_id(key)

  defp decode_base64(value) do
    case Base.decode64(value) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, {:invalid_backup_wrap_metadata, "ciphertext"}}
    end
  end
end
