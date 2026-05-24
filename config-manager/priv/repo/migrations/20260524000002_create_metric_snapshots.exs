defmodule ConfigManager.Repo.Migrations.CreateMetricSnapshots do
  use Ecto.Migration

  def change do
    create table(:metric_snapshots, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:sensor_pod_id, references(:sensor_pods, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:metric_type, :text, null: false)
      add(:series_key, :text, null: false, default: "default")
      add(:value, :real, null: false)
      add(:recorded_at, :utc_datetime_usec, null: false)
      add(:metadata, :text, null: false, default: "{}")

      timestamps(type: :utc_datetime_usec)
    end

    create(index(:metric_snapshots, [:recorded_at]))
    create(index(:metric_snapshots, [:metric_type, :recorded_at]))

    create(
      unique_index(:metric_snapshots, [:sensor_pod_id, :metric_type, :series_key, :recorded_at],
        name: :metric_snapshots_unique_sample_index
      )
    )
  end
end
