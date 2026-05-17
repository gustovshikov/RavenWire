defmodule ConfigManager.Repo.Migrations.AddDriftFieldsToSensorPods do
  use Ecto.Migration

  def change do
    alter table(:sensor_pods) do
      add(:last_deployed_config_version, :integer)
      add(:last_deployed_forwarding_version, :integer)
      add(:last_deployed_bpf_version, :integer)
      add(:last_deployed_at, :utc_datetime_usec)
      add(:last_deployment_id, references(:deployments, type: :binary_id, on_delete: :nilify_all))
    end

    create(index(:sensor_pods, [:last_deployment_id]))
  end
end
