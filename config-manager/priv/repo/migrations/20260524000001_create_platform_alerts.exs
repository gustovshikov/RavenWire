defmodule ConfigManager.Repo.Migrations.CreatePlatformAlerts do
  use Ecto.Migration

  def change do
    create table(:alert_rules, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:alert_type, :text, null: false)
      add(:description, :text, null: false)
      add(:severity, :text, null: false)
      add(:enabled, :boolean, null: false, default: true)
      add(:threshold_value, :real, null: false)
      add(:threshold_unit, :text, null: false)
      add(:builtin, :boolean, null: false, default: true)

      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:alert_rules, [:alert_type]))
    create(index(:alert_rules, [:enabled]))

    create table(:alerts, primary_key: false) do
      add(:id, :binary_id, primary_key: true)
      add(:alert_type, :text, null: false)
      add(:sensor_pod_id, :text, null: false)
      add(:sensor_pod_db_id, references(:sensor_pods, type: :binary_id, on_delete: :nilify_all))
      add(:severity, :text, null: false)
      add(:status, :text, null: false)
      add(:message, :text, null: false)
      add(:threshold_value, :real)
      add(:observed_value, :real)
      add(:fired_at, :utc_datetime_usec, null: false)
      add(:acknowledged_at, :utc_datetime_usec)
      add(:acknowledged_by, :text)
      add(:resolved_at, :utc_datetime_usec)
      add(:resolved_by, :text)
      add(:note, :text)

      timestamps(type: :utc_datetime_usec)
    end

    create(index(:alerts, [:alert_type]))
    create(index(:alerts, [:sensor_pod_id]))
    create(index(:alerts, [:sensor_pod_db_id]))
    create(index(:alerts, [:status]))
    create(index(:alerts, [:fired_at]))
    create(index(:alerts, [:severity]))
    create(index(:alerts, [:alert_type, :sensor_pod_id, :status]))
  end
end
