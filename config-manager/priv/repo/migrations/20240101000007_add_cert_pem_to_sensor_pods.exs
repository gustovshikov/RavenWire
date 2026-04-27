defmodule ConfigManager.Repo.Migrations.AddCertPemToSensorPods do
  use Ecto.Migration

  def change do
    alter table(:sensor_pods) do
      add :cert_pem, :text
      add :ca_chain_pem, :text
    end
  end
end
