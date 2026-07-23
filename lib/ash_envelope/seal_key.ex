defmodule AshEnvelope.SealKey do
  @moduledoc """
  Symmetric seal/unseal under an operator-managed key.

  Used by `AshEnvelope.KeyGrants` to seal per-row ephemeral X25519
  private keys at rest (the worker-pathway use case). The seal key
  never decrypts a blob directly — it only unlocks ephemeral private
  keys, which in turn unwrap a wrapped DEK from the grant row.
  Together with `expires_at` TTL purge, this bounds the worker
  pathway's blast radius to "blobs whose analyzer pipeline is
  currently in flight."

  ## Key resolution

  Reads from `Application.get_env(:ash_envelope, :seal_key)`. Wire it
  in `runtime.exs`:

      config :ash_envelope,
        seal_key: System.fetch_env!("ASH_ENVELOPE_SEAL_KEY")

  The value must be base64 of exactly 32 random bytes (AES-256).

  ## Format

  `<<1::8, iv::12-binary, tag::16-binary, ciphertext::binary>>`

  The leading version byte is the rotation hatch — multi-version
  resolution is deferred to a follow-up.

  ## Associated data

  `opts[:context]` binds the ciphertext to a context (e.g. the subject
  id). Decryption fails if a sealed value is moved to a different
  context. Defaults to `""`.

  ## Errors

  * `{:error, :missing_seal_key}` — application env not configured
  * `{:error, :invalid_seal_key}` — env value not base64 of 32 bytes
  * `{:error, :unknown_seal_format}` — ciphertext doesn't match the
    expected layout or version
  * `{:error, :decryption_failed}` — authentication failed (wrong key,
    AAD mismatch, or tampered ciphertext)
  """

  @version 1

  @spec seal(binary(), keyword()) :: {:ok, binary()} | {:error, term()}
  def seal(plaintext, opts \\ []) when is_binary(plaintext) do
    with {:ok, key} <- fetch_key() do
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
    with {:ok, key} <- fetch_key() do
      aad = Keyword.get(opts, :context, "")

      case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, aad, tag, false) do
        :error -> {:error, :decryption_failed}
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
      end
    end
  end

  def unseal(_other, _opts), do: {:error, :unknown_seal_format}

  defp fetch_key do
    case Application.get_env(:ash_envelope, :seal_key) do
      nil ->
        {:error, :missing_seal_key}

      <<key::binary-32>> ->
        {:ok, key}

      raw when is_binary(raw) ->
        case Base.decode64(raw) do
          {:ok, <<key::binary-32>>} -> {:ok, key}
          _ -> {:error, :invalid_seal_key}
        end

      _ ->
        {:error, :invalid_seal_key}
    end
  end
end
