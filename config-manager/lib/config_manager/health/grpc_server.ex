defmodule ConfigManager.Health.GrpcServer do
  @moduledoc """
  gRPC server that accepts persistent bidirectional health streams from Sensor_Agents.

  Sensor_Agents connect on port 9090 (mTLS) and stream `HealthReport` protobuf
  messages. Each received report is deserialized and forwarded to the in-memory
  Sensor Registry for real-time dashboard updates.

  The server sends back a `HealthAck` for each received report so the Sensor_Agent
  can confirm delivery and manage its local buffer.
  """

  use GRPC.Server, service: Health.HealthService.Service

  require Logger

  @doc """
  Handles the bidirectional StreamHealth RPC.

  Reads HealthReport messages from the incoming stream, updates the registry,
  and sends HealthAck responses back to the Sensor_Agent.
  """
  def stream_health(request_stream, server) do
    Enum.each(request_stream, fn report ->
      handle_report(report, server)
    end)
  end

  # ── Private ─────────────────────────────────────────────────────────────────

  defp handle_report(%Health.HealthReport{} = report, server) do
    pod_id = report.sensor_pod_id

    if pod_id == "" do
      Logger.warning("[GrpcServer] Received HealthReport with empty sensor_pod_id — ignoring")
    else
      Logger.debug("[GrpcServer] Received HealthReport from pod=#{pod_id}")

      ConfigManager.Health.Registry.update(pod_id, report)

      ack = %Health.HealthAck{
        sensor_pod_id: pod_id,
        ack_timestamp_unix_ms: System.system_time(:millisecond)
      }

      GRPC.Server.send_reply(server, ack)
    end
  end

  defp handle_report(other, _server) do
    Logger.warning("[GrpcServer] Received unexpected message type: #{inspect(other)}")
  end
end
