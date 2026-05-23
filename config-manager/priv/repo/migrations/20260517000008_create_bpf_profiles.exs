defmodule ConfigManager.Repo.Migrations.CreateBpfProfiles do
  use Ecto.Migration

  def change do
    create table(:bpf_profiles, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:pool_id, references(:sensor_pools, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:version, :integer, null: false, default: 1)
      add(:last_deployed_version, :integer)
      add(:raw_expression, :text)
      add(:composition_mode, :text, null: false, default: "append")
      add(:compiled_expression, :text)
      add(:updated_by, :text)

      timestamps(type: :utc_datetime_usec)
    end

    create(unique_index(:bpf_profiles, [:pool_id]))
  end
end
