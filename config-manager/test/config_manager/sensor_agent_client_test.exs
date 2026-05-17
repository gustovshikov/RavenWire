defmodule ConfigManager.SensorAgentClientTest do
  use ExUnit.Case, async: true

  alias ConfigManager.SensorAgentClient

  @pod_without_host %{name: "sensor-01", control_api_host: nil}
  @pod_with_empty_host %{name: "sensor-01", control_api_host: ""}

  test "control actions fail locally when pod has no control API host" do
    for pod <- [@pod_without_host, @pod_with_empty_host] do
      assert {:error, :no_control_api_host} = SensorAgentClient.validate_config(pod)
      assert {:error, :no_control_api_host} = SensorAgentClient.reload_zeek(pod)
      assert {:error, :no_control_api_host} = SensorAgentClient.reload_suricata(pod)
      assert {:error, :no_control_api_host} = SensorAgentClient.restart_vector(pod)
      assert {:error, :no_control_api_host} = SensorAgentClient.request_support_bundle(pod)

      assert {:error, :no_control_api_host} =
               SensorAgentClient.download_support_bundle(pod, "/tmp/bundle.tar.gz")

      assert {:error, :no_control_api_host} =
               SensorAgentClient.switch_capture_mode(pod, %{
                 pcap_ring_size_mb: 4096,
                 pre_alert_window_sec: 60,
                 post_alert_window_sec: 30,
                 alert_severity_threshold: 2
               })

      assert {:error, :no_control_api_host} =
               SensorAgentClient.push_rule_bundle(pod, %{
                 "local.rules" => "alert tcp any any -> any any (sid:1;)"
               })
    end
  end
end
