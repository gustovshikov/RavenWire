defmodule ConfigManager.Repo.Migrations.CreateSensorPods do
  use Ecto.Migration

  def change do
    create table(:sensor_pods, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :pool_id, references(:sensor_pools, type: :binary_id, on_delete: :nilify_all)
      add :status, :string, null: false, default: "pending"
      add :cert_serial, :string
      add :cert_expires_at, :utc_datetime
      add :last_seen_at, :utc_datetime
      add :enrolled_at, :utc_datetime
      add :enrolled_by, :string
      add :public_key_pem, :text
      add :key_fingerprint, :string

      timestamps()
    end

    create unique_index(:sensor_pods, [:name])
    create index(:sensor_pods, [:pool_id])
    create index(:sensor_pods, [:status])
  end
end
