if Code.ensure_loaded?(AshStorage.Encryption.KeyManager) do
  defmodule AshEnvelope.BlobIO.KeyManagers.Asymmetric do
    @moduledoc """
    BlobIO key manager that wraps the DEK with the actor's X25519 public key.

    Use this manager when each blob is intended for a single principal — the
    actor present on the write operation. The wrapped DEK lives in blob layer
    metadata; only the holder of the matching X25519 private key can unwrap.

    ## Configuration

        storage do
          service {AshStorage.Service.S3, bucket: "private-blobs"}
          blob_resource MyApp.DocumentBlob
          attachment_resource MyApp.DocumentAttachment

          layer {AshStorage.Layer.Encryption,
                 key_manager:
                   {AshEnvelope.BlobIO.KeyManagers.Asymmetric,
                    actor_public_key_attribute: :public_key,
                    actor_private_key_attribute: :private_key},
                 proxy_base_url: "/storage"},
                metadata_key: "documents"

          has_one_attached :file
        end

    Options:

      * `:actor_public_key_attribute` — attribute on the actor holding their
        X25519 public key (32-byte binary or base64). Required on writes.
      * `:actor_private_key_attribute` — attribute on the actor holding their
        X25519 private key. Required on reads.

    ## Rewrap

    `rewrap_dek/3` rewraps the DEK for the actor present on the rewrap
    operation. Use this to hand a blob from one recipient to another without
    re-uploading bytes: read with the donor actor, rewrap with the recipient
    actor.
    """

    @behaviour AshStorage.Encryption.KeyManager

    alias AshEnvelope.BlobIO.Backup
    alias AshStorage.BlobIO.Reader
    alias AshStorage.BlobIO.Writer
    alias AshStorage.Encryption.RewrapOperation

    @format "x25519-ecies-v1"

    @impl true
    def wrap_dek(dek, %Writer.Operation{blob_context: bctx}, opts) when is_binary(dek) do
      with {:ok, public_key} <- resolve_public_key(bctx.actor, opts),
           {:ok, ciphertext} <- wrap_for_recipient(dek, public_key) do
        {:ok,
         %{"format" => @format, "ciphertext" => ciphertext}
         |> Backup.put_backup(Backup.wrap_for_backup(dek))}
      end
    end

    @impl true
    def unwrap_dek(
          %{"format" => @format, "ciphertext" => ciphertext},
          %Reader.Operation{blob_context: bctx},
          opts
        )
        when is_binary(ciphertext) do
      with {:ok, private_key} <- resolve_private_key(bctx.actor, opts),
           {:ok, decoded} <- decode_base64(ciphertext) do
        AshEnvelope.unwrap_dek(decoded, private_key)
      end
    end

    def unwrap_dek(_wrapped_dek, %Reader.Operation{}, _opts) do
      {:error, {:invalid_asymmetric_key_metadata, "wrapped_dek"}}
    end

    @impl true
    def rewrap_dek(
          %{"format" => @format, "ciphertext" => ciphertext} = wrapped_dek,
          %RewrapOperation{blob_context: bctx, call_opts: call_opts},
          opts
        )
        when is_binary(ciphertext) do
      donor = Keyword.get(call_opts, :donor_actor, bctx.actor)

      with {:ok, donor_private_key} <- resolve_private_key(donor, opts),
           {:ok, recipient_public_key} <- resolve_public_key(bctx.actor, opts),
           {:ok, decoded} <- decode_base64(ciphertext),
           {:ok, dek} <- AshEnvelope.unwrap_dek(decoded, donor_private_key),
           {:ok, rewrapped} <- wrap_for_recipient(dek, recipient_public_key) do
        {:ok,
         %{"format" => @format, "ciphertext" => rewrapped}
         |> Backup.put_backup(Backup.from_wrapped_dek(wrapped_dek))}
      end
    end

    def rewrap_dek(_wrapped_dek, %RewrapOperation{}, _opts) do
      {:error, {:invalid_asymmetric_key_metadata, "wrapped_dek"}}
    end

    # `AshEnvelope.wrap_dek/2` raises ArgumentError when the recipient's
    # public key is a degenerate/low-order X25519 point (e.g. 32 zero
    # bytes). Inside the BlobIO pipeline that exception is caught and
    # scrubbed to an opaque `:encryption_key_manager_exception`; a
    # malformed actor key is a per-request error and belongs in the
    # same `:invalid_actor_key` channel as a wrong-length key.
    defp wrap_for_recipient(dek, public_key) do
      {:ok, dek |> AshEnvelope.wrap_dek(public_key) |> Base.encode64()}
    rescue
      ArgumentError -> {:error, :invalid_actor_key}
    end

    defp resolve_public_key(actor, opts) do
      with {:ok, attr} <- fetch_option(opts, :actor_public_key_attribute) do
        resolve_actor_key(actor, attr)
      end
    end

    defp resolve_private_key(actor, opts) do
      with {:ok, attr} <- fetch_option(opts, :actor_private_key_attribute) do
        resolve_actor_key(actor, attr)
      end
    end

    # Non-raising counterpart of `AshEnvelope.resolve_actor_key/2`. Key
    # managers run inside read/write pipelines, so a nil actor (e.g. an
    # unauthenticated read) must surface as an error tuple — matching the
    # KeyGrants manager's `:missing_principal` — rather than crash the
    # request mid-flight.
    defp resolve_actor_key(actor, attr) when is_map(actor) do
      case Map.get(actor, attr) do
        nil ->
          {:error, :missing_principal}

        <<key::binary-32>> ->
          {:ok, key}

        raw when is_binary(raw) ->
          case Base.decode64(raw) do
            {:ok, <<key::binary-32>>} -> {:ok, key}
            _ -> {:error, :invalid_actor_key}
          end

        _ ->
          {:error, :invalid_actor_key}
      end
    end

    defp resolve_actor_key(nil, _attr), do: {:error, :missing_principal}
    defp resolve_actor_key(_actor, _attr), do: {:error, :invalid_actor_key}

    defp fetch_option(opts, key) do
      case Keyword.fetch(opts, key) do
        {:ok, attr} when is_atom(attr) -> {:ok, attr}
        _ -> {:error, {:asymmetric_key_manager_option_required, key}}
      end
    end

    defp decode_base64(value) do
      case Base.decode64(value) do
        {:ok, decoded} -> {:ok, decoded}
        :error -> {:error, {:invalid_asymmetric_key_metadata, "ciphertext"}}
      end
    end
  end
end
