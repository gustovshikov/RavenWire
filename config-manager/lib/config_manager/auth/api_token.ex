defmodule ConfigManager.Auth.ApiToken do
  @moduledoc "Scoped bearer API token metadata. Raw tokens are never stored."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Auth.{Policy, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "api_tokens" do
    field(:name, :string)
    field(:token_hash, :string, redact: true)
    field(:permissions, :string, default: "[]")
    field(:expires_at, :utc_datetime_usec)
    field(:revoked_at, :utc_datetime_usec)

    belongs_to(:user, User)

    timestamps()
  end

  def changeset(token, attrs) do
    token
    |> cast(attrs, [:name, :token_hash, :user_id, :permissions, :expires_at, :revoked_at])
    |> validate_required([:name, :token_hash, :user_id, :permissions])
    |> validate_length(:name, min: 1, max: 128)
    |> validate_length(:token_hash, is: 64)
    |> validate_permissions()
    |> unique_constraint(:token_hash)
  end

  def permissions_list(%__MODULE__{permissions: permissions}), do: permissions_list(permissions)

  def permissions_list(permissions) when is_binary(permissions) do
    case Jason.decode(permissions) do
      {:ok, permissions} when is_list(permissions) ->
        normalize_permissions(permissions)

      _ ->
        []
    end
  end

  def permissions_list(permissions) when is_list(permissions),
    do: normalize_permissions(permissions)

  def permissions_list(_permissions), do: []

  def encode_permissions(permissions) do
    permissions = permissions_list(permissions)

    cond do
      permissions == [] ->
        {:error, "must include at least one permission"}

      Enum.all?(permissions, &Policy.valid_permission?/1) ->
        {:ok, Jason.encode!(permissions)}

      true ->
        {:error, "contains invalid permissions"}
    end
  end

  defp validate_permissions(changeset) do
    permissions = get_field(changeset, :permissions)

    case encode_permissions(permissions) do
      {:ok, _json} -> changeset
      {:error, reason} -> add_error(changeset, :permissions, reason)
    end
  end

  defp normalize_permissions(permissions) do
    permissions
    |> Enum.map(&to_string/1)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end
end
