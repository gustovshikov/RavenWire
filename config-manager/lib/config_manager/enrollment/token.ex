defmodule ConfigManager.Enrollment.Token do
  @moduledoc "Ecto schema for one-time enrollment tokens."

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "enrollment_tokens" do
    field :token, :string
    field :created_by, :string
    field :consumed_at, :utc_datetime
    field :expires_at, :utc_datetime

    timestamps()
  end

  def create_changeset(token, attrs) do
    token
    |> cast(attrs, [:token, :created_by, :expires_at])
    |> validate_required([:token, :expires_at])
    |> unique_constraint(:token)
  end

  def consume_changeset(token) do
    change(token, consumed_at: DateTime.utc_now() |> DateTime.truncate(:second))
  end

  def create(attrs) do
    %__MODULE__{}
    |> create_changeset(attrs)
    |> ConfigManager.Repo.insert()
  end
end
