defmodule ConfigManager.Repo.Migrations.CreateSensorPools do
  use Ecto.Migration

  def change do
    create table(:sensor_pools, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :capture_mode, :string, null: false, default: "alert_driven"
      add :config_version, :integer, null: false, default: 1
      add :config_updated_at, :utc_datetime
      add :config_updated_by, :string

      timestamps()
    end

    create unique_index(:sensor_pools, [:name])
  end
end
