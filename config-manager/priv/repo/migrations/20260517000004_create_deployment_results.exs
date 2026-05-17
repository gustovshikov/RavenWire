defmodule ConfigManager.Repo.Migrations.CreateDeploymentResults do
  use Ecto.Migration

  def change do
    create table(:deployment_results, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:deployment_id, references(:deployments, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:sensor_pod_id, references(:sensor_pods, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:status, :string, null: false, default: "pending")
      add(:message, :text)
      add(:started_at, :utc_datetime_usec)
      add(:completed_at, :utc_datetime_usec)

      timestamps()
    end

    create(index(:deployment_results, [:deployment_id]))
    create(index(:deployment_results, [:sensor_pod_id]))
    create(index(:deployment_results, [:status]))
  end
end
