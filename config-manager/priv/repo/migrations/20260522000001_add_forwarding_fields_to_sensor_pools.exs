defmodule ConfigManager.Repo.Migrations.AddForwardingFieldsToSensorPools do
  use Ecto.Migration

  def change do
    alter table(:sensor_pools) do
      add(:schema_mode, :text, null: false, default: "raw")
      add(:forwarding_config_version, :integer, null: false, default: 0)
      add(:forwarding_config_updated_at, :utc_datetime_usec)
      add(:forwarding_config_updated_by, :text)
    end
  end
end
