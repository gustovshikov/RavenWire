defmodule ConfigManager.Repo.Migrations.CreateRevokedCerts do
  use Ecto.Migration

  def change do
    create table(:revoked_certs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :serial, :string, null: false
      add :reason, :string, null: false, default: "unspecified"
      add :revoked_at, :utc_datetime, null: false

      timestamps()
    end

    create unique_index(:revoked_certs, [:serial])
  end
end
