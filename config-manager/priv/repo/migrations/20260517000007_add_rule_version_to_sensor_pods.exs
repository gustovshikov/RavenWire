defmodule ConfigManager.Repo.Migrations.AddRuleVersionToSensorPods do
  use Ecto.Migration

  def change do
    alter table(:sensor_pods) do
      add(:last_deployed_rule_version, :integer)
    end
  end
end
