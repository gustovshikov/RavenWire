defmodule ConfigManager.Repo.Migrations.CreateHealthBaselines do
  use Ecto.Migration

  def change do
    create table(:health_baselines, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:sensor_pod_id, references(:sensor_pods, type: :binary_id, on_delete: :delete_all),
        null: true
      )

      add(:pool_id, references(:sensor_pools, type: :binary_id, on_delete: :delete_all),
        null: true
      )

      add(:metric_type, :text, null: false)
      add(:series_key, :text, null: false, default: "default")
      add(:mean, :real, null: false)
      add(:stddev, :real, null: false)
      add(:p5, :real, null: false)
      add(:p95, :real, null: false)
      add(:min_value, :real, null: false)
      add(:max_value, :real, null: false)
      add(:sample_count, :integer, null: false)
      add(:window_start, :utc_datetime_usec, null: false)
      add(:window_end, :utc_datetime_usec, null: false)
      add(:computed_at, :utc_datetime_usec, null: false)

      timestamps(type: :utc_datetime_usec)
    end

    create(index(:health_baselines, [:sensor_pod_id]))
    create(index(:health_baselines, [:pool_id]))
    create(index(:health_baselines, [:metric_type, :computed_at]))

    create(
      unique_index(:health_baselines, [:sensor_pod_id, :metric_type, :series_key],
        name: :health_baselines_sensor_unique_index,
        where: "sensor_pod_id IS NOT NULL"
      )
    )

    create(
      unique_index(:health_baselines, [:pool_id, :metric_type, :series_key],
        name: :health_baselines_pool_unique_index,
        where: "pool_id IS NOT NULL"
      )
    )
  end
end
