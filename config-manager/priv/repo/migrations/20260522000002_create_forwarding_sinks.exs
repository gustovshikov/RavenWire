defmodule ConfigManager.Repo.Migrations.CreateForwardingSinks do
  use Ecto.Migration

  def change do
    create table(:forwarding_sinks, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:pool_id, references(:sensor_pools, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:name, :text, null: false)
      add(:normalized_name, :text, null: false)
      add(:sink_type, :text, null: false)
      add(:config, :text, null: false)
      add(:enabled, :boolean, null: false, default: true)
      add(:last_test_result, :text)
      add(:last_test_at, :utc_datetime_usec)

      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:forwarding_sinks, [:pool_id, :normalized_name]))
    create(index(:forwarding_sinks, [:pool_id]))
  end
end
