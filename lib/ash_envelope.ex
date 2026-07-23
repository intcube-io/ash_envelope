defmodule AshEnvelope do
  @moduledoc """
  Envelope encryption primitives for the Ash ecosystem.

  This library owns the **DEK lifecycle**: generating per-record data
  encryption keys, wrapping them under one or more recipients' X25519
  public keys, unwrapping with the matching private keys, and managing
  multi-recipient grants via `AshEnvelope.KeyGrants`. The byte-level
  AEAD over blob ciphertext is owned by `AshStorage.Layer.Encryption`,
  which `ash_envelope` plugs into via its
  `AshEnvelope.BlobIO.KeyManagers.*` implementations.

  ## Field encryption with multi-recipient grants

  `encrypt/3` and `decrypt/3` are the symmetric step of the grant
  pattern for **non-blob fields**. Each record gets a fresh DEK; that
  DEK encrypts the field once and is wrapped into a per-principal
  grant row for every recipient. Sharing or revoking is grant-row
  management — the ciphertext never moves.

      dek = AshEnvelope.generate_dek()
      ciphertext = AshEnvelope.encrypt(message.body, dek, context: to_string(message.id))
      # ... store ciphertext on the message row ...
      AshEnvelope.KeyGrants.create_for_actor(config, message.id, dek, sender, domain)
      AshEnvelope.KeyGrants.create_for_actor(config, message.id, dek, recipient, domain)

      {:ok, dek} = AshEnvelope.KeyGrants.resolve_for_actor(config, message.id, actor, domain)
      {:ok, body} = AshEnvelope.decrypt(ciphertext, dek, context: to_string(message.id))

  Pass the record id (or any stable identifier) as `:context`. It
  becomes AES-256-GCM AAD, binding the ciphertext to the row — a DBA
  who swaps ciphertexts between rows triggers `:decryption_failed`
  rather than disclosing one row's plaintext under another row's
  identity. AAD is optional; ciphertexts written with no context can
  still be decrypted with no context.

  For **single-key field encryption** (encrypt a column with one
  app-wide vault key, no per-record DEK, no multi-recipient grants),
  use [`ash_cloak`](https://hexdocs.pm/ash_cloak) — it provides Ecto
  types, a vault abstraction, and key rotation. `ash_envelope` and
  `ash_cloak` cover different use cases.

  ## DEK wrapping (X25519 + AES-256-GCM)

  Each record gets a random DEK. The DEK is wrapped with the recipient's
  X25519 public key so that only their private key can unwrap it.
  Sharing only requires the recipient's public key.

      {pub, priv} = AshEnvelope.generate_key_pair()
      dek = AshEnvelope.generate_dek()

      wrapped = AshEnvelope.wrap_dek(dek, pub)
      {:ok, ^dek} = AshEnvelope.unwrap_dek(wrapped, priv)

  ## Key Grants

  For multi-recipient envelope encryption, see `AshEnvelope.KeyGrants` which
  manages per-principal wrapped DEKs in an Ash resource table.

  ## Cryptographic primitives

  | Primitive | Used for | BSI TR-02102 horizon |
  |-----------|----------|----------------------|
  | AES-256-GCM (12-byte IV, 16-byte tag) | Inner AEAD inside X25519 ECIES wrapping; symmetric seal under `AshEnvelope.SealKey` | Recommended through 2030 |
  | X25519 (Curve25519 ECDH) | Asymmetric DEK wrapping (ECIES) | Recommended through 2030 |
  | HKDF-SHA256 (single block, ≤ 32 bytes) | Key derivation from ECDH shared secret | Recommended through 2030 |

  Algorithm choices are reviewed annually against BSI TR-02102 and
  equivalent publications; results are recorded in `CHANGELOG.md`. See
  the "Cryptographic primitives and horizon" section of the
  [security posture](documentation/topics/how-envelope-encryption-works.md)
  for the rationale and the threat model these primitives cover.
  """

  # -- Field encryption (AES-256-GCM with optional AAD) --

  @doc """
  Encrypt a field's plaintext with a 32-byte AES-256 key.

  Returns a binary blob: `IV(12) || TAG(16) || ciphertext`.

  ## Options

  - `:context` — optional AAD bound into the ciphertext. Pass a
    stable per-row identifier (typically `to_string(record.id)`) to
    bind the ciphertext to the row; `decrypt/3` must supply the same
    AAD or fail with `:decryption_failed`. Defaults to `""`, which
    matches the historical wire format and allows existing
    ciphertexts written without AAD to round-trip.

  See the moduledoc for the multi-recipient grant pattern.
  """
  @spec encrypt(binary(), binary(), keyword()) :: binary()
  def encrypt(plaintext, key, opts \\ []) when byte_size(key) == 32 do
    iv = :crypto.strong_rand_bytes(12)
    aad = Keyword.get(opts, :context, "")

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, aad, true)

    iv <> tag <> ciphertext
  end

  @doc """
  Decrypt a blob produced by `encrypt/3`.

  Expects the format `IV(12) || TAG(16) || ciphertext` and a 32-byte key.

  Returns `{:ok, plaintext}`, `{:error, :malformed_blob}` for blobs that
  don't match the expected layout, or `{:error, :decryption_failed}` when
  authentication fails (wrong key, AAD mismatch, or tampered ciphertext).

  ## Options

  - `:context` — must match the value passed to `encrypt/3`. Defaults
    to `""`. AAD mismatch surfaces as `:decryption_failed`, not as a
    distinct error, because the AEAD authentication step cannot
    distinguish "tampered ciphertext" from "wrong AAD."
  """
  @spec decrypt(binary(), binary(), keyword()) ::
          {:ok, binary()} | {:error, :malformed_blob | :decryption_failed}
  def decrypt(ciphertext, key, opts \\ [])

  def decrypt(<<iv::binary-12, tag::binary-16, ciphertext::binary>>, key, opts)
      when byte_size(key) == 32 do
    aad = Keyword.get(opts, :context, "")

    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, aad, tag, false) do
      :error -> {:error, :decryption_failed}
      plaintext when is_binary(plaintext) -> {:ok, plaintext}
    end
  end

  def decrypt(_blob, key, _opts) when byte_size(key) == 32, do: {:error, :malformed_blob}

  # -- Key generation --

  @doc """
  Generate a random 32-byte AES-256 key suitable for use as a DEK.
  """
  @spec generate_dek() :: binary()
  def generate_dek do
    :crypto.strong_rand_bytes(32)
  end

  @doc """
  Generate an X25519 key pair for envelope encryption.

  Returns `{public_key, private_key}` where both are 32-byte binaries.
  The public key can be freely shared; the private key must be kept secret.
  """
  @spec generate_key_pair() :: {public_key :: binary(), private_key :: binary()}
  def generate_key_pair do
    :crypto.generate_key(:ecdh, :x25519)
  end

  # -- DEK wrapping (X25519 ECIES) --

  @doc """
  Wrap a raw 32-byte DEK using the recipient's X25519 public key.

  Uses ECIES: generates an ephemeral X25519 key pair, computes a shared
  secret via ECDH, derives an AES-256 key via HKDF-SHA256, and encrypts
  the DEK with AES-256-GCM.

  Returns a binary blob: `ephemeral_public(32) || IV(12) || TAG(16) || ciphertext(32)`.

  Only the holder of the corresponding private key can unwrap. Wrapping
  the same DEK twice produces different ciphertexts (fresh ephemeral each time).
  """
  @spec wrap_dek(binary(), binary()) :: binary()
  def wrap_dek(raw_dek, recipient_public_key)
      when byte_size(raw_dek) == 32 and byte_size(recipient_public_key) == 32 do
    {eph_public, eph_private} = :crypto.generate_key(:ecdh, :x25519)
    shared_secret = :crypto.compute_key(:ecdh, recipient_public_key, eph_private, :x25519)
    derived_key = hkdf_sha256(shared_secret, eph_public, "ash_envelope_v1", 32)

    iv = :crypto.strong_rand_bytes(12)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, derived_key, iv, raw_dek, "", true)

    eph_public <> iv <> tag <> ciphertext
  end

  @doc """
  Unwrap a DEK blob produced by `wrap_dek/2` using the recipient's
  X25519 private key.

  Returns `{:ok, raw_dek}` (32-byte binary), `{:error, :malformed_blob}`
  if the blob doesn't match the expected layout, or
  `{:error, :decryption_failed}` if authentication fails.
  """
  @spec unwrap_dek(binary(), binary()) ::
          {:ok, binary()} | {:error, :malformed_blob | :decryption_failed}
  def unwrap_dek(
        <<eph_public::binary-32, iv::binary-12, tag::binary-16, ciphertext::binary>>,
        recipient_private_key
      )
      when byte_size(recipient_private_key) == 32 do
    shared_secret = :crypto.compute_key(:ecdh, eph_public, recipient_private_key, :x25519)
    derived_key = hkdf_sha256(shared_secret, eph_public, "ash_envelope_v1", 32)

    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           derived_key,
           iv,
           ciphertext,
           "",
           tag,
           false
         ) do
      :error -> {:error, :decryption_failed}
      plaintext -> {:ok, plaintext}
    end
  end

  def unwrap_dek(_blob, recipient_private_key)
      when byte_size(recipient_private_key) == 32 do
    {:error, :malformed_blob}
  end

  # -- Helpers --

  @doc """
  Resolve a 32-byte key from an actor struct attribute.

  Accepts a raw 32-byte binary or a base64-encoded string that decodes to
  exactly 32 bytes.
  """
  @spec resolve_actor_key(term(), atom()) :: binary()
  def resolve_actor_key(actor, attr) do
    raw = if actor, do: Map.get(actor, attr)

    case raw do
      <<key::binary-32>> ->
        key

      raw when is_binary(raw) ->
        case Base.decode64(raw) do
          {:ok, <<key::binary-32>>} -> key
          _ -> raise_invalid_actor_key!(attr, raw)
        end

      _ ->
        raise_invalid_actor_key!(attr, raw)
    end
  end

  defp raise_invalid_actor_key!(attr, raw) do
    raise ArgumentError,
          "actor attribute #{inspect(attr)} must be a 32-byte binary or base64-encoded string (got #{describe_value(raw)})"
  end

  defp describe_value(nil), do: "nil"
  defp describe_value(value) when is_binary(value), do: "#{byte_size(value)}-byte binary"
  defp describe_value(value), do: "value of type #{value |> typeof()}"

  defp typeof(value) when is_atom(value), do: "atom"
  defp typeof(value) when is_integer(value), do: "integer"
  defp typeof(value) when is_float(value), do: "float"
  defp typeof(value) when is_list(value), do: "list"
  defp typeof(value) when is_map(value), do: "map"
  defp typeof(value) when is_tuple(value), do: "tuple"
  defp typeof(_), do: "unknown"

  # Single-block HKDF: HKDF-Extract followed by one HKDF-Expand round.
  # Restricted to lengths <= 32 bytes (one SHA-256 block) so callers can't
  # accidentally truncate without realizing it.
  @doc false
  def hkdf_sha256(ikm, salt, info, length) when length > 0 and length <= 32 do
    prk = :crypto.mac(:hmac, :sha256, salt, ikm)

    :crypto.mac(:hmac, :sha256, prk, <<info::binary, 1>>)
    |> binary_part(0, length)
  end

  # -- Backup-key recovery --

  @doc """
  Recover the DEK of an encrypted blob using a backup private key.

  The blob must have been written with `:backup_public_key` configured at
  the time of encryption, and the encryption layer's `wrapped_dek`
  metadata must therefore contain a `"backup"` field. Recovery is
  KeyManager-agnostic: it bypasses the configured KeyManager entirely
  and unwraps the backup field directly with the supplied private key.

  Limited to blobs with exactly one encryption layer in the layer chain.
  Blobs with multiple encryption layers or layered transforms other than
  encryption return `{:error, {:unsupported_layer_chain, _}}` — recover
  those manually by walking the chain.

  Returns `{:ok, dek}` (32-byte binary), or `{:error, reason}`.
  """
  @spec recover_dek(map() | struct(), binary()) ::
          {:ok, binary()} | {:error, term()}
  def recover_dek(blob_or_metadata, backup_private_key)
      when byte_size(backup_private_key) == 32 do
    with {:ok, layer_metadata} <- single_encryption_layer(blob_or_metadata),
         {:ok, backup_wrap} <- fetch_backup_wrap(layer_metadata) do
      AshEnvelope.BlobIO.Backup.unwrap_backup(backup_wrap, backup_private_key)
    end
  end

  @doc """
  Recover the plaintext bytes of an encrypted blob from its ciphertext +
  the backup private key.

  Caller is responsible for downloading the ciphertext from the storage
  service (`AshStorage.Service.<adapter>.download/2`). Recovery then
  unwraps the backup-wrapped DEK from blob metadata and runs AES-256-GCM
  decryption locally.

  Same limitation as `recover_dek/2`: exactly one encryption layer, no
  other layered transforms.
  """
  @spec recover_plaintext(map() | struct(), binary(), binary()) ::
          {:ok, binary()} | {:error, term()}
  def recover_plaintext(blob, ciphertext, backup_private_key)
      when is_binary(ciphertext) and byte_size(backup_private_key) == 32 do
    with {:ok, blob_key} <- fetch_blob_key(blob),
         {:ok, layer_metadata_key, layer_metadata} <- single_encryption_layer_entry(blob),
         {:ok, backup_wrap} <- fetch_backup_wrap(layer_metadata),
         {:ok, dek} <- AshEnvelope.BlobIO.Backup.unwrap_backup(backup_wrap, backup_private_key),
         {:ok, iv} <- decode_base64(layer_metadata, "iv"),
         {:ok, tag} <- decode_base64(layer_metadata, "tag") do
      aad = aes_256_gcm_aad(blob_key, layer_metadata_key)

      case :crypto.crypto_one_time_aead(:aes_256_gcm, dek, iv, ciphertext, aad, tag, false) do
        :error -> {:error, :decryption_failed}
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
      end
    end
  end

  defp single_encryption_layer(blob_or_metadata) do
    with {:ok, _layer_metadata_key, metadata} <- single_encryption_layer_entry(blob_or_metadata) do
      {:ok, metadata}
    end
  end

  defp single_encryption_layer_entry(%{metadata: metadata}),
    do: single_encryption_layer_entry(metadata)

  defp single_encryption_layer_entry(metadata) when is_map(metadata) do
    case layer_chain(metadata) do
      [entry] ->
        case entry_metadata(entry) do
          %{"format" => "aes-256-gcm"} = layer_metadata ->
            {:ok, entry_layer_metadata_key(entry), layer_metadata}

          _other ->
            {:error, :no_encryption_layer}
        end

      [] ->
        {:error, :no_encryption_layer}

      many ->
        {:error, {:unsupported_layer_chain, length(many)}}
    end
  end

  defp single_encryption_layer_entry(_), do: {:error, :no_encryption_layer}

  defp layer_chain(metadata),
    do: get_in(metadata, ["ash_storage", "blob_io", "layers"]) || []

  defp entry_metadata(%{"metadata" => m}) when is_map(m), do: m
  defp entry_metadata(%{metadata: m}) when is_map(m), do: m
  defp entry_metadata(_), do: %{}

  defp entry_layer_metadata_key(%{"layer_metadata_key" => key}) when is_binary(key), do: key
  defp entry_layer_metadata_key(%{layer_metadata_key: key}) when is_binary(key), do: key
  defp entry_layer_metadata_key(_), do: ""

  defp fetch_blob_key(%{key: key}) when is_binary(key), do: {:ok, key}
  defp fetch_blob_key(%{"key" => key}) when is_binary(key), do: {:ok, key}
  defp fetch_blob_key(_), do: {:error, :missing_blob_key}

  # AAD must match AshStorage.Layer.Encryption — length-prefixed
  # format name, layer metadata key, and blob key, in that order.
  defp aes_256_gcm_aad(blob_key, layer_metadata_key) do
    length_prefixed("aes-256-gcm") <>
      length_prefixed(layer_metadata_key) <>
      length_prefixed(blob_key)
  end

  defp length_prefixed(value) when is_binary(value),
    do: <<byte_size(value)::32, value::binary>>

  defp fetch_backup_wrap(%{"wrapped_dek" => %{"backup" => backup}}) when is_map(backup),
    do: {:ok, backup}

  defp fetch_backup_wrap(_), do: {:error, :no_backup_wrap}

  defp decode_base64(metadata, key) do
    case Map.fetch(metadata, key) do
      {:ok, value} when is_binary(value) ->
        case Base.decode64(value) do
          {:ok, decoded} -> {:ok, decoded}
          :error -> {:error, {:invalid_encryption_layer_metadata, key}}
        end

      _ ->
        {:error, {:invalid_encryption_layer_metadata, key}}
    end
  end
end
