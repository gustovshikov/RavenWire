defmodule ConfigManager.Pcap.StatusPoller do
  @moduledoc "Background polling for Sensor Agent PCAP carve status."

  require Logger

  alias ConfigManager.{Pcap, Repo, SensorAgentClient}
  alias ConfigManager.Pcap.CarveRequest

  @default_interval_ms 5_000
  @default_timeout_ms 5 * 60 * 1_000

  @spec start(CarveRequest.t() | String.t(), keyword()) :: DynamicSupervisor.on_start_child()
  def start(request, opts \\ [])

  def start(%CarveRequest{id: id}, opts), do: start(id, opts)

  def start(request_id, opts) when is_binary(request_id) do
    Task.Supervisor.start_child(ConfigManager.Pcap.TaskSupervisor, fn ->
      poll_loop(request_id, opts)
    end)
  end

  defp poll_loop(request_id, opts) do
    client = Keyword.get(opts, :client, SensorAgentClient)
    interval_ms = Keyword.get(opts, :interval_ms, poll_interval_ms())
    timeout_ms = Keyword.get(opts, :timeout_ms, timeout_ms())

    case fetch_request(request_id) do
      nil ->
        :ok

      %CarveRequest{} = request ->
        cond do
          CarveRequest.terminal?(request) ->
            :ok

          dispatched_timeout?(request, timeout_ms) ->
            {:ok, failed} = Pcap.update_status(request, "failed", %{error_reason: "timeout"})
            broadcast(failed)

          true ->
            poll_once(request, client)
            Process.sleep(interval_ms)
            poll_loop(request_id, opts)
        end
    end
  end

  defp poll_once(%CarveRequest{} = request, client) do
    request = Repo.preload(request, :sensor_pod)

    case client.get_pcap_carve_status(request.sensor_pod, request.id) do
      {:ok, response} ->
        status = response |> response_value("status") |> agent_status()
        metadata = status_metadata(response)

        case Pcap.update_status(request, status, metadata) do
          {:ok, updated} -> broadcast(updated)
          {:error, reason} -> Logger.warning("PCAP status update failed: #{inspect(reason)}")
        end

      {:error, reason} ->
        Logger.warning("PCAP status polling failed for #{request.id}: #{inspect(reason)}")
    end
  end

  defp fetch_request(request_id), do: Pcap.get_request(request_id)

  defp dispatched_timeout?(
         %CarveRequest{status: "dispatched", updated_at: updated_at},
         timeout_ms
       ) do
    timestamp = updated_at || DateTime.utc_now()
    DateTime.diff(DateTime.utc_now(), timestamp, :millisecond) > timeout_ms
  end

  defp dispatched_timeout?(_request, _timeout_ms), do: false

  defp broadcast(%CarveRequest{} = request) do
    Phoenix.PubSub.broadcast(
      ConfigManager.PubSub,
      "pcap_request:#{request.id}",
      {:pcap_request, request}
    )
  end

  defp response_value(map, key) when is_map(map),
    do: Map.get(map, key) || Map.get(map, String.to_atom(key))

  defp response_value(_map, _key), do: nil

  defp agent_status(nil), do: "dispatched"
  defp agent_status("queued"), do: "dispatched"
  defp agent_status("dispatched"), do: "dispatched"
  defp agent_status("carving"), do: "carving"
  defp agent_status("completed"), do: "completed"
  defp agent_status("failed"), do: "failed"
  defp agent_status(_status), do: "dispatched"

  defp status_metadata(response) when is_map(response) do
    %{
      file_path: response_value(response, "file_path"),
      file_size_bytes: response_value(response, "file_size_bytes"),
      sha256: response_value(response, "sha256"),
      packet_count: response_value(response, "packet_count"),
      time_span_start: response_value(response, "time_span_start"),
      time_span_end: response_value(response, "time_span_end"),
      error_reason: response_value(response, "error")
    }
    |> Enum.reject(fn {_key, value} -> is_nil(value) or value == "" end)
    |> Map.new()
  end

  defp status_metadata(_response), do: %{}

  defp poll_interval_ms do
    env_int("RAVENWIRE_PCAP_POLL_INTERVAL_MS", @default_interval_ms)
  end

  defp timeout_ms do
    env_int("RAVENWIRE_PCAP_DISPATCH_TIMEOUT_MS", @default_timeout_ms)
  end

  defp env_int(key, default) do
    case System.get_env(key) do
      nil ->
        default

      value ->
        case Integer.parse(value) do
          {integer, ""} when integer > 0 -> integer
          _other -> default
        end
    end
  end
end
