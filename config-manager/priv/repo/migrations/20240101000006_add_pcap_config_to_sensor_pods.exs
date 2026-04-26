defmodule ConfigManager.Repo.Migrations.AddPcapConfigToSensorPods do
  use Ecto.Migration

  def change do
    alter table(:sensor_pods) do
      add :control_api_host, :string
      add :pcap_ring_size_mb, :integer, default: 4096
      add :pre_alert_window_sec, :integer, default: 60
      add :post_alert_window_sec, :integer, default: 30
      add :alert_severity_threshold, :integer, default: 2
    end
  end
end
