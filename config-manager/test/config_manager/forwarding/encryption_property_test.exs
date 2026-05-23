defmodule ConfigManager.Forwarding.EncryptionPropertyTest do
  use ExUnit.Case, async: false
  use PropCheck

  alias ConfigManager.Forwarding.Encryption

  setup do
    previous = System.get_env("RAVENWIRE_SINK_ENCRYPTION_KEY")
    System.put_env("RAVENWIRE_SINK_ENCRYPTION_KEY", Base.encode64(:crypto.strong_rand_bytes(32)))

    on_exit(fn ->
      if previous do
        System.put_env("RAVENWIRE_SINK_ENCRYPTION_KEY", previous)
      else
        System.delete_env("RAVENWIRE_SINK_ENCRYPTION_KEY")
      end
    end)

    :ok
  end

  property "Property 3: Secret encryption round-trip",
           [:verbose, numtests: 80] do
    forall code <- integer(1, 100_000) do
      plaintext = secret_value(code)

      {:ok, ciphertext_a} = Encryption.encrypt(plaintext)
      {:ok, ciphertext_b} = Encryption.encrypt(plaintext)
      {:ok, decrypted} = Encryption.decrypt(ciphertext_a)

      decrypted == plaintext and ciphertext_a != plaintext and ciphertext_a != ciphertext_b
    end
  end

  property "Property 12: Secret masking shows only last 4 characters",
           [:verbose, numtests: 80] do
    forall code <- integer(1, 100_000) do
      plaintext = secret_value(code)
      mask = Encryption.mask(plaintext)
      last_four = Encryption.last_four(plaintext)

      cond do
        String.length(plaintext) >= 4 ->
          String.ends_with?(mask, last_four) and
            not String.contains?(String.trim_trailing(mask, last_four), plaintext)

        true ->
          mask == String.duplicate("*", String.length(plaintext))
      end
    end
  end

  defp secret_value(code), do: "secret-#{code}-#{:crypto.strong_rand_bytes(8) |> Base.encode16()}"
end
