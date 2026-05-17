defmodule ConfigManager.Repo.Migrations.CreateDeployments do
  use Ecto.Migration

  def change do
    create table(:deployments, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:pool_id, references(:sensor_pools, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:status, :string, null: false, default: "pending")
      add(:operator, :string, null: false)
      add(:operator_type, :string, null: false)
      add(:config_version, :integer, null: false)
      add(:forwarding_config_version, :integer)
      add(:bpf_version, :integer)
      add(:config_snapshot, :map, null: false)
      add(:diff_summary, :map)

      add(
        :rollback_of_deployment_id,
        references(:deployments, type: :binary_id, on_delete: :nilify_all)
      )

      add(
        :source_deployment_id,
        references(:deployments, type: :binary_id, on_delete: :nilify_all)
      )

      add(:started_at, :utc_datetime_usec)
      add(:completed_at, :utc_datetime_usec)
      add(:failure_reason, :text)

      timestamps()
    end

    create(index(:deployments, [:pool_id]))
    create(index(:deployments, [:status]))
    create(index(:deployments, [:inserted_at]))
    create(index(:deployments, [:pool_id, :status]))
    create(index(:deployments, [:rollback_of_deployment_id]))
    create(index(:deployments, [:source_deployment_id]))
  end
end
