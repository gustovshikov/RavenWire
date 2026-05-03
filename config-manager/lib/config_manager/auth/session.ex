defmodule ConfigManager.Auth.Session do
  @moduledoc "Server-side browser session record."

  use Ecto.Schema
  import Ecto.Changeset

  alias ConfigManager.Auth.User

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "sessions" do
    field(:token_hash, :string, redact: true)
    field(:last_active_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)

    belongs_to(:user, User)

    timestamps(updated_at: false)
  end

  def changeset(session, attrs) do
    session
    |> cast(attrs, [:user_id, :token_hash, :last_active_at, :expires_at])
    |> validate_required([:user_id, :token_hash, :last_active_at, :expires_at])
    |> unique_constraint(:token_hash)
  end

  def touch_changeset(session, now) do
    change(session, last_active_at: now)
  end
end
