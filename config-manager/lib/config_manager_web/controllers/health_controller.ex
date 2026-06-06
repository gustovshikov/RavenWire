defmodule ConfigManagerWeb.HealthController do
  use ConfigManagerWeb, :controller

  alias ConfigManager.Health.Registry

  def show(conn, %{"pod_id" => pod_id}) do
    case Registry.get_pod(pod_id) do
      nil ->
        conn
        |> put_status(404)
        |> json(%{error: %{code: "NOT_FOUND", message: "Sensor pod not found"}})

      pod ->
        json(conn, health_report_json(pod))
    end
  end

  defp health_report_json(%Health.HealthReport{} = report) do
    %{
      sensor_pod_id: report.sensor_pod_id,
      timestamp_unix_ms: report.timestamp_unix_ms,
      containers: Enum.map(report.containers || [], &container_json/1),
      capture: capture_json(report.capture),
      storage: storage_json(report.storage),
      clock: clock_json(report.clock),
      system: system_json(report.system)
    }
  end

  defp container_json(%Health.ContainerHealth{} = container) do
    %{
      name: container.name,
      state: container.state,
      uptime_seconds: container.uptime_seconds,
      cpu_percent: container.cpu_percent,
      memory_bytes: container.memory_bytes
    }
  end

  defp capture_json(nil), do: nil

  defp capture_json(%Health.CaptureStats{} = capture) do
    %{
      consumers:
        (capture.consumers || %{})
        |> Enum.map(fn {name, stats} -> {name, consumer_json(stats)} end)
        |> Map.new()
    }
  end

  defp consumer_json(%Health.ConsumerStats{} = stats) do
    %{
      packets_received: stats.packets_received,
      packets_dropped: stats.packets_dropped,
      drop_percent: stats.drop_percent,
      throughput_bps: stats.throughput_bps,
      process_throughput_bps: stats.process_throughput_bps,
      process_packets_per_sec: stats.process_packets_per_sec,
      process_drop_percent: stats.process_drop_percent,
      process_telemetry_source: stats.process_telemetry_source,
      bpf_restart_pending: stats.bpf_restart_pending,
      packets_written: stats.packets_written,
      bytes_written: stats.bytes_written,
      wrap_count: stats.wrap_count,
      socket_drops: stats.socket_drops,
      socket_freeze_queue_drops: stats.socket_freeze_queue_drops,
      overwrite_risk: stats.overwrite_risk,
      drop_alert: stats.drop_alert
    }
  end

  defp storage_json(nil), do: nil

  defp storage_json(%Health.StorageStats{} = storage) do
    %{
      path: storage.path,
      total_bytes: storage.total_bytes,
      used_bytes: storage.used_bytes,
      available_bytes: storage.available_bytes,
      used_percent: storage.used_percent
    }
  end

  defp clock_json(nil), do: nil

  defp clock_json(%Health.ClockStats{} = clock) do
    %{
      offset_ms: clock.offset_ms,
      synchronized: clock.synchronized,
      source: clock.source
    }
  end

  defp system_json(nil), do: nil

  defp system_json(%Health.SystemStats{} = system) do
    %{
      uptime_seconds: system.uptime_seconds,
      cpu_percent: system.cpu_percent,
      cpu_count: system.cpu_count,
      memory_total_bytes: system.memory_total_bytes,
      memory_used_bytes: system.memory_used_bytes,
      memory_available_bytes: system.memory_available_bytes,
      memory_used_percent: system.memory_used_percent,
      disk_path: system.disk_path,
      disk_total_bytes: system.disk_total_bytes,
      disk_used_bytes: system.disk_used_bytes,
      disk_available_bytes: system.disk_available_bytes,
      disk_used_percent: system.disk_used_percent,
      load1: system.load1,
      load5: system.load5,
      load15: system.load15,
      health: system.health,
      kernel_release: system.kernel_release,
      capture_interface: system.capture_interface,
      nic_driver: system.nic_driver,
      af_packet_available: system.af_packet_available
    }
  end
end
