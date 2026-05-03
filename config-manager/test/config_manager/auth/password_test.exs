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
end
