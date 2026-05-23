defmodule ConfigManager.Forwarding.Encryption do
  @moduledoc """
  AES-256-GCM encryption helpers for forwarding sink secrets.

  Production must provide `RAVENWIRE_SINK_ENCRYPTION_KEY` as a Base64-encoded
  32-byte key. Development and test may fall back to the endpoint
  `secret_key_base` to keep local setup friction low.
  """

  require Logger

  @aad "ravenwire_sink_secret_v1"
  @iv_bytes 12
  @tag_bytes 16
  @key_bytes 32

  def encrypt(plaintext) when is_binary(plaintext) do
    with {:ok, key} <- key() do
      iv = :crypto.strong_rand_bytes(@iv_bytes)

      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, @aad, true)

      {:ok, Base.encode64(iv <> tag <> ciphertext)}
    end
  end

  def encrypt(plaintext), do: encrypt(to_string(plaintext))

  def decrypt(ciphertext_b64) when is_binary(ciphertext_b64) do
    with {:ok, key} <- key(),
         {:ok, payload} <- decode_ciphertext(ciphertext_b64),
         <<iv::binary-size(@iv_bytes), tag::binary-size(@tag_bytes), ciphertext::binary>> <-
           payload,
         plaintext when is_binary(plaintext) <-
           :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, @aad, tag, false) do
      {:ok, plaintext}
    else
      {:error, reason} ->
        {:error, reason}

      _error ->
        Logger.warning("Failed to decrypt forwarding sink secret")
        {:error, :decryption_failed}
    end
  end

  def decrypt(_ciphertext), do: {:error, :decryption_failed}

  def key_available? do
    match?({:ok, _key}, key())
  end

  def last_four(value) do
    value
    |> to_string()
    |> String.slice(-4, 4)
  end

  def mask(value) do
    value = to_string(value)

    if String.length(value) >= 4 do
      "********" <> last_four(value)
    else
      String.duplicate("*", max(String.length(value), 1))
    end
  end

  def mask_last_four(last_four) do
    "********" <> to_string(last_four)
  end

  defp decode_ciphertext(ciphertext_b64) do
    case Base.decode64(ciphertext_b64) do
      {:ok, payload} when byte_size(payload) > @iv_bytes + @tag_bytes ->
        {:ok, payload}

      {:ok, _short_payload} ->
        {:error, :decryption_failed}

      :error ->
        {:error, :decryption_failed}
    end
  end

  defp key do
    case System.get_env("RAVENWIRE_SINK_ENCRYPTION_KEY") do
      nil ->
        fallback_key()

      encoded ->
        decode_key(encoded)
    end
  end

  defp decode_key(encoded) do
    case Base.decode64(encoded) do
      {:ok, key} when byte_size(key) == @key_bytes ->
        {:ok, key}

      _invalid ->
        {:error, :key_unavailable}
    end
  end

  defp fallback_key do
    if runtime_env() in [:dev, :test] do
      secret_key_base =
        :config_manager
        |> Application.get_env(ConfigManagerWeb.Endpoint, [])
        |> Keyword.get(:secret_key_base)

      if is_binary(secret_key_base) and secret_key_base != "" do
        {:ok, :crypto.hash(:sha256, secret_key_base)}
      else
        {:error, :key_unavailable}
      end
    else
      {:error, :key_unavailable}
    end
  end

  defp runtime_env do
    if Code.ensure_loaded?(Mix) and function_exported?(Mix, :env, 0) do
      Mix.env()
    else
      :prod
    end
  end
end
