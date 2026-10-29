defmodule AshEnvelope.SealKey do
  @moduledoc """
  Symmetric seal/unseal under an operator-managed key.

  Used by `AshEnvelope.KeyGrants` to seal the DEK stored on ephemeral
  worker grant rows at rest (AAD = subject id; the worker-pathway use
  case). The seal key never decrypts a blob directly — it only opens
  the sealed DEK on an ephemeral row, and that DEK decrypts the blob.
  Together with `expires_at` TTL purge, this bounds the worker
  pathway's blast radius to "blobs whose analyzer pipeline is
  currently in flight."

  ## Key resolution

  An explicit `opts[:key]` takes precedence; otherwise the key is read
  from `Application.get_env(:ash_envelope, :seal_key)`. Wire the latter
  in `runtime.exs`:

      config :ash_envelope,
        seal_key: System.fetch_env!("ASH_ENVELOPE_SEAL_KEY")

  Either way the value must be exactly 32 raw bytes or base64 of
  exactly 32 random bytes (AES-256). The `:key` override is dependency
  injection for callers that manage their own key material — tests in
  particular, where mutating global application env would race
  concurrently running suites.

  ## Format

  `<<1::8, iv::12-binary, tag::16-binary, ciphertext::binary>>`

  The leading version byte is the rotation hatch — multi-version
  resolution is deferred to a follow-up.

  ## Associated data

  `opts[:context]` binds the ciphertext to a context (e.g. the subject
  id). Decryption fails if a sealed value is moved to a different
  context. Defaults to `""`.

  ## Errors

  * `{:error, :missing_seal_key}` — no `:key` opt and application env
    not configured
  * `{:error, :invalid_seal_key}` — key (from either source) is not 32
    raw bytes or base64 of 32 bytes
  * `{:error, :unknown_seal_format}` — ciphertext doesn't match the
    expected layout or version
  * `{:error, :decryption_failed}` — authentication failed (wrong key,
    AAD mismatch, or tampered ciphertext)
  """

  @version 1

  @spec seal(binary(), keyword()) :: {:ok, binary()} | {:error, term()}
  def seal(plaintext, opts \\ []) when is_binary(plaintext) do
    with {:ok, key} <- fetch_key(opts) do
      iv = :crypto.strong_rand_bytes(12)
      aad = Keyword.get(opts, :context, "")

      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, aad, true)

      {:ok, <<@version::8, iv::binary, tag::binary, ciphertext::binary>>}
    end
  end

  @spec unseal(binary(), keyword()) :: {:ok, binary()} | {:error, term()}
  def unseal(ciphertext, opts \\ [])

  def unseal(<<@version::8, iv::binary-12, tag::binary-16, ciphertext::binary>>, opts) do
    with {:ok, key} <- fetch_key(opts) do
      aad = Keyword.get(opts, :context, "")

      case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, aad, tag, false) do
        :error -> {:error, :decryption_failed}
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
      end
    end
  end

  def unseal(_other, _opts), do: {:error, :unknown_seal_format}

  defp fetch_key(opts) do
    case Keyword.get(opts, :key) do
      nil -> fetch_env_key()
      key -> validate_key(key)
    end
  end

  defp fetch_env_key do
    case Application.get_env(:ash_envelope, :seal_key) do
      nil -> {:error, :missing_seal_key}
      key -> validate_key(key)
    end
  end

  defp validate_key(<<key::binary-32>>), do: {:ok, key}

  defp validate_key(raw) when is_binary(raw) do
    case Base.decode64(raw) do
      {:ok, <<key::binary-32>>} -> {:ok, key}
      _ -> {:error, :invalid_seal_key}
    end
  end

  defp validate_key(_other), do: {:error, :invalid_seal_key}
end
