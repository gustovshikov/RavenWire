defmodule ConfigManager.Auth.PasswordTest do
  use ExUnit.Case, async: true

  alias ConfigManager.Auth.Password

  test "hashes and verifies passwords with Argon2id" do
    password = "correct horse battery staple"
    hash = Password.hash_password(password)

    assert String.starts_with?(hash, "$argon2id$")
    assert Password.verify_password(password, hash)
    refute Password.verify_password("wrong password", hash)
    refute String.contains?(hash, password)
  end

  test "validates minimum length and username mismatch" do
    assert {:error, _} = Password.validate_password("short", "admin")
    assert {:error, _} = Password.validate_password("admin", "admin")
    assert :ok = Password.validate_password("long-enough-password", "admin")
  end

  test "password validation rejects every length below the minimum" do
    for length <- 0..(Password.min_length() - 1) do
      password = String.duplicate("a", length)
      assert {:error, _reason} = Password.validate_password(password, "operator")
    end
  end

  test "password validation rejects case-insensitive username matches" do
    for {username, password} <- [{"operator", "OPERATOR"}, {"RavenWire", "ravenwire"}] do
      assert {:error, _reason} = Password.validate_password(password, username)
    end
  end

  test "valid generated passwords hash without preserving plaintext" do
    for suffix <- 1..8 do
      password = "long-enough-password-#{suffix}"

      assert :ok = Password.validate_password(password, "operator")

      hash = Password.hash_password(password)
      assert String.starts_with?(hash, "$argon2id$")
      assert Password.verify_password(password, hash)
      refute String.contains?(hash, password)
    end
  end
end
