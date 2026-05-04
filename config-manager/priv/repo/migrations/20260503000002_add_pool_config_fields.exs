defmodule ConfigManager.Repo.Migrations.AddPoolConfigFields do
  use Ecto.Migration

  def up do
    alter table(:sensor_pools) do
      add(:description, :text)
      add(:pcap_ring_size_mb, :integer, null: false, default: 4096)
      add(:pre_alert_window_sec, :integer, null: false, default: 60)
      add(:post_alert_window_sec, :integer, null: false, default: 30)
      add(:alert_severity_threshold, :integer, null: false, default: 2)
    end

    execute("DROP INDEX IF EXISTS sensor_pools_name_index")

    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS sensor_pools_name_nocase_index
    ON sensor_pools(name COLLATE NOCASE)
    """)
  end

  def down do
    execute("DROP INDEX IF EXISTS sensor_pools_name_nocase_index")
    create(unique_index(:sensor_pools, [:name], name: :sensor_pools_name_index))

    alter table(:sensor_pools) do
      remove(:alert_severity_threshold)
      remove(:post_alert_window_sec)
      remove(:pre_alert_window_sec)
      remove(:pcap_ring_size_mb)
      remove(:description)
    end
  end
end
