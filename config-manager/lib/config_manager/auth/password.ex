defmodule ConfigManager.Auth.Password do
  @moduledoc "Password hashing and validation helpers for local users."

  @min_length 12
  @random_password_bytes 18

  def min_length, do: @min_length

  def hash_password(password) when is_binary(password), do: Argon2.hash_pwd_salt(password)

  def verify_password(password, password_hash)
      when is_binary(password) and is_binary(password_hash) do
    Argon2.verify_pass(password, password_hash)
  end

  def verify_password(_password, _password_hash) do
    Argon2.no_user_verify()
    false
  end

  def validate_password(password, username) when is_binary(password) and is_binary(username) do
    cond do
      String.length(password) < @min_length ->
        {:error, "password must be at least #{@min_length} characters"}

      String.downcase(password) == String.downcase(username) ->
        {:error, "password must not match username"}

      true ->
        :ok
    end
  end

  def validate_password(_password, _username), do: {:error, "password is required"}

  def generate_random_password do
    @random_password_bytes
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
    |> binary_part(0, 24)
  end
end
