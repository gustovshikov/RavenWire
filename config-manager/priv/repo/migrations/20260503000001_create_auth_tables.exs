defmodule ConfigManager.Repo.Migrations.CreateAuthTables do
  use Ecto.Migration

  def change do
    create table(:users, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:username, :string, null: false)
      add(:password_hash, :string, null: false)
      add(:display_name, :string)
      add(:role, :string, null: false, default: "viewer")
      add(:active, :boolean, null: false, default: true)
      add(:must_change_password, :boolean, null: false, default: false)

      timestamps()
    end

    create(unique_index(:users, [:username]))
    create(index(:users, [:role]))

    create table(:sessions, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false)
      add(:token_hash, :string, null: false)
      add(:last_active_at, :utc_datetime_usec, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)

      timestamps(updated_at: false)
    end

    create(index(:sessions, [:user_id]))
    create(unique_index(:sessions, [:token_hash]))
    create(index(:sessions, [:expires_at]))

    create table(:api_tokens, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:name, :string, null: false)
      add(:token_hash, :string, null: false)
      add(:user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false)
      add(:permissions, :text, null: false, default: "[]")
      add(:expires_at, :utc_datetime_usec)
      add(:revoked_at, :utc_datetime_usec)

      timestamps()
    end

    create(index(:api_tokens, [:user_id]))
    create(unique_index(:api_tokens, [:token_hash]))
  end
end
