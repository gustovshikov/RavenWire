defmodule ConfigManager.Auth.User do
  @moduledoc "Local Config Manager user account."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Auth.{Password, Policy}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "users" do
    field(:username, :string)
    field(:password_hash, :string, redact: true)
    field(:display_name, :string)
    field(:role, :string, default: "viewer")
    field(:active, :boolean, default: true)
    field(:must_change_password, :boolean, default: false)
    field(:password, :string, virtual: true, redact: true)

    timestamps()
  end

  def create_changeset(user, attrs) do
    user
    |> cast(attrs, [:username, :display_name, :role, :active, :must_change_password, :password])
    |> normalize_username()
    |> validate_required([:username, :role, :password])
    |> validate_length(:username, min: 1, max: 128)
    |> validate_role()
    |> validate_and_hash_password()
    |> unique_constraint(:username)
  end

  def update_changeset(user, attrs) do
    user
    |> cast(attrs, [:display_name, :role, :active, :must_change_password])
    |> validate_required([:role])
    |> validate_role()
  end

  def password_changeset(user, attrs) do
    user
    |> cast(attrs, [:password, :must_change_password])
    |> validate_required([:password])
    |> validate_and_hash_password()
  end

  defp normalize_username(changeset) do
    update_change(changeset, :username, fn username ->
      username |> to_string() |> String.trim() |> String.downcase()
    end)
  end

  defp validate_role(changeset) do
    validate_change(changeset, :role, fn :role, role ->
      if Policy.valid_role?(role), do: [], else: [role: "is not a valid role"]
    end)
  end

  defp validate_and_hash_password(changeset) do
    password = get_change(changeset, :password)
    username = get_field(changeset, :username) || ""

    case Password.validate_password(password, username) do
      :ok ->
        changeset
        |> put_change(:password_hash, Password.hash_password(password))
        |> delete_change(:password)

      {:error, reason} ->
        add_error(changeset, :password, reason)
    end
  end
end
