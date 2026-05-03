defmodule ConfigManager.Auth.ApiToken do
  @moduledoc "Scoped bearer API token metadata. Raw tokens are never stored."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Auth.User

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
    |> unique_constraint(:token_hash)
  end
end
