defmodule ConfigManager.Metrics.Sampler do
  @moduledoc "Periodically snapshots latest HealthReport data into historical metrics."

  use GenServer

  require Logger

  import Ecto.Query

  alias ConfigManager.{Metrics, Repo, SensorPod}
  alias ConfigManager.Health.Registry

  @default_sample_interval_ms 60_000
  @default_prune_interval_ms 15 * 60_000
  @default_prune_batch_size 1_000
  @default_retention_hours 72

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  def sample_once(pid \\ __MODULE__), do: GenServer.call(pid, :sample_once)
  def prune_once(pid \\ __MODULE__), do: GenServer.call(pid, :prune_once)

  def init(opts) do
    state = %{
      sample_interval_ms: config(:metrics_sample_interval_ms, @default_sample_interval_ms, opts),
      prune_interval_ms: config(:metrics_prune_interval_ms, @default_prune_interval_ms, opts),
      retention_hours: validated_retention_hours(config(:metrics_retention_hours, @default_retention_hours, opts)),
      prune_batch_size: config(:metrics_prune_batch_size, @default_prune_batch_size, opts),
      previous_reports: %{},
      schedule?: Keyword.get(opts, :schedule?, true)
    }

    if state.schedule? do
      Process.send_after(self(), :sample, state.sample_interval_ms)
      Process.send_after(self(), :prune, state.prune_interval_ms)
    end

    {:ok, state}
  end

  def validated_retention_hours(value, env \\ Application.get_env(:config_manager, :env, :dev)) do
    hours = to_integer(value, @default_retention_hours)
    if env == :test, do: max(hours, 1), else: max(hours, @default_retention_hours)
  end

  def series_key(prefix, value) do
    sanitized =
      value
      |> to_string()
      |> String.downcase()
      |> String.replace(~r/[^a-z0-9_.:-]+/, "-")
      |> String.trim("-")

    "#{prefix}:#{if sanitized == "", do: "unknown", else: sanitized}"
  end

  def extract_snapshots(%SensorPod{} = pod, report, previous_report \\ nil, recorded_at \\ nil) do
    {recorded_at, timestamp_metadata} = recorded_at_with_metadata(report, recorded_at)

    []
    |> maybe_add_storage(pod, report, recorded_at, timestamp_metadata)
    |> maybe_add_clock(pod, report, recorded_at, timestamp_metadata)
    |> add_container_metrics(pod, report, recorded_at, timestamp_metadata)
    |> maybe_add_drop_percent(pod, report, recorded_at, timestamp_metadata)
    |> maybe_add_packets_rate(pod, report, previous_report, recorded_at, timestamp_metadata)
    |> Enum.reverse()
  end

  def aggregate_drop_percent(%{capture: %{consumers: consumers}}) when is_map(consumers) do
    values = Map.values(consumers)
    received = Enum.sum(Enum.map(values, &(Map.get(&1, :packets_received) || 0)))
    dropped = Enum.sum(Enum.map(values, &(Map.get(&1, :packets_dropped) || 0)))

    cond do
      received + dropped > 0 ->
        {:ok, dropped / (received + dropped) * 100.0, %{"drop_percent_method" => "weighted"}}

      values != [] ->
        percentages = Enum.map(values, &(Map.get(&1, :drop_percent) || 0.0))
        {:ok, Enum.sum(percentages) / length(percentages), %{"drop_percent_method" => "unweighted"}}

      true ->
        :skip
    end
  end

  def aggregate_drop_percent(_report), do: :skip

  def packets_received_rate(_current, nil), do: :skip

  def packets_received_rate(current, previous) do
    with {:ok, current_at} <- report_datetime(current),
         {:ok, previous_at} <- report_datetime(previous),
         true <- DateTime.compare(current_at, previous_at) == :gt,
         current_count when is_integer(current_count) <- total_packets_received(current),
         previous_count when is_integer(previous_count) <- total_packets_received(previous),
         true <- current_count >= previous_count do
      elapsed = DateTime.diff(current_at, previous_at, :millisecond) / 1000.0

      if elapsed > 0 do
        {:ok, (current_count - previous_count) / elapsed}
      else
        :skip
      end
    else
      _error -> :skip
    end
  end

  def handle_call(:sample_once, _from, state) do
    {:reply, :ok, do_sample(state)}
  end

  def handle_call(:prune_once, _from, state) do
    {:reply, do_prune(state), state}
  end

  def handle_info(:sample, state) do
    state = do_sample(state)
    if state.schedule?, do: Process.send_after(self(), :sample, state.sample_interval_ms)
    {:noreply, state}
  end

  def handle_info(:prune, state) do
    do_prune(state)
    if state.schedule?, do: Process.send_after(self(), :prune, state.prune_interval_ms)
    {:noreply, state}
  end

  defp do_sample(state) do
    reports = Registry.list_pods()
    pods = pods_by_name(reports)

    {snapshots, previous_reports} =
      Enum.reduce(reports, {[], state.previous_reports}, fn report, {acc, previous_reports} ->
        sensor_name = Map.get(report, :sensor_pod_id)

        case Map.get(pods, sensor_name) do
          %SensorPod{} = pod ->
            previous = Map.get(previous_reports, pod.id)
            pod_snapshots = extract_snapshots(pod, report, previous)
            {[pod_snapshots | acc], Map.put(previous_reports, pod.id, report)}

          nil ->
            {acc, previous_reports}
        end
      end)

    snapshots = List.flatten(snapshots)

    case Metrics.write_snapshots(snapshots) do
      {:ok, count} ->
        if count > 0 do
          snapshots
          |> Enum.map(& &1.sensor_pod_id)
          |> Enum.uniq()
          |> Enum.each(&broadcast_metrics_updated/1)
        end

      {:error, reason} ->
        Logger.warning("Historical metrics sample failed: #{inspect(reason)}")
    end

    %{state | previous_reports: previous_reports}
  rescue
    error ->
      Logger.warning("Historical metrics sampler error: #{Exception.message(error)}")
      state
  end

  defp do_prune(state) do
    cutoff =
      DateTime.utc_now()
      |> DateTime.add(-state.retention_hours * 60 * 60, :second)
      |> DateTime.truncate(:microsecond)

    case Metrics.prune_before(cutoff, state.prune_batch_size) do
      {:ok, deleted} ->
        Logger.info("Historical metrics pruned #{deleted} old snapshot(s)")
        {:ok, deleted}

      {:error, reason} ->
        Logger.warning("Historical metrics prune failed: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    error ->
      Logger.warning("Historical metrics prune error: #{Exception.message(error)}")
      {:error, error}
  end

  defp pods_by_name(reports) do
    names =
      reports
      |> Enum.map(&Map.get(&1, :sensor_pod_id))
      |> Enum.reject(&is_nil/1)

    SensorPod
    |> where([p], p.name in ^names)
    |> Repo.all()
    |> Map.new(&{&1.name, &1})
  end

  defp maybe_add_storage(snapshots, pod, %{storage: %{used_percent: value}}, recorded_at, metadata)
       when is_number(value) do
    [snapshot(pod, "pcap_disk_used_percent", "default", value, recorded_at, metadata) | snapshots]
  end

  defp maybe_add_storage(snapshots, _pod, _report, _recorded_at, _metadata), do: snapshots

  defp maybe_add_clock(snapshots, pod, %{clock: %{offset_ms: value}}, recorded_at, metadata)
       when is_integer(value) do
    [snapshot(pod, "clock_offset_ms", "default", value, recorded_at, metadata) | snapshots]
  end

  defp maybe_add_clock(snapshots, _pod, _report, _recorded_at, _metadata), do: snapshots

  defp add_container_metrics(snapshots, pod, %{containers: containers}, recorded_at, metadata)
       when is_list(containers) do
    Enum.reduce(containers, snapshots, fn container, acc ->
      key = series_key("container", Map.get(container, :name))
      metadata = Map.put(metadata, "container_name", Map.get(container, :name, "unknown"))

      acc
      |> add_if_number(pod, "cpu_percent", key, Map.get(container, :cpu_percent), recorded_at, metadata)
      |> add_if_number(pod, "memory_bytes", key, Map.get(container, :memory_bytes), recorded_at, metadata)
    end)
  end

  defp add_container_metrics(snapshots, _pod, _report, _recorded_at, _metadata), do: snapshots

  defp maybe_add_drop_percent(snapshots, pod, report, recorded_at, metadata) do
    case aggregate_drop_percent(report) do
      {:ok, value, drop_metadata} ->
        [snapshot(pod, "drop_percent", "default", value, recorded_at, Map.merge(metadata, drop_metadata)) | snapshots]

      :skip ->
        snapshots
    end
  end

  defp maybe_add_packets_rate(snapshots, pod, report, previous, recorded_at, metadata) do
    case packets_received_rate(report, previous) do
      {:ok, value} -> [snapshot(pod, "packets_received_rate", "default", value, recorded_at, metadata) | snapshots]
      :skip -> snapshots
    end
  end

  defp add_if_number(snapshots, pod, metric_type, series_key, value, recorded_at, metadata)
       when is_number(value) do
    [snapshot(pod, metric_type, series_key, value, recorded_at, metadata) | snapshots]
  end

  defp add_if_number(snapshots, _pod, _metric_type, _series_key, _value, _recorded_at, _metadata),
    do: snapshots

  defp snapshot(pod, metric_type, series_key, value, recorded_at, metadata) do
    %{
      sensor_pod_id: pod.id,
      metric_type: metric_type,
      series_key: series_key,
      value: value / 1,
      recorded_at: recorded_at,
      metadata: metadata
    }
  end

  defp recorded_at_with_metadata(report, nil) do
    case report_datetime(report) do
      {:ok, datetime} -> {datetime, %{"timestamp_source" => "health_report"}}
      :error -> {DateTime.utc_now() |> DateTime.truncate(:microsecond), %{"timestamp_source" => "sampler"}}
    end
  end

  defp recorded_at_with_metadata(_report, recorded_at), do: {recorded_at, %{"timestamp_source" => "test"}}

  defp report_datetime(%{timestamp_unix_ms: unix_ms}) when is_integer(unix_ms) and unix_ms > 0 do
    case DateTime.from_unix(unix_ms, :millisecond) do
      {:ok, datetime} -> {:ok, DateTime.truncate(datetime, :microsecond)}
      {:error, _reason} -> :error
    end
  end

  defp report_datetime(_report), do: :error

  defp total_packets_received(%{capture: %{consumers: consumers}}) when is_map(consumers) do
    consumers |> Map.values() |> Enum.map(&(Map.get(&1, :packets_received) || 0)) |> Enum.sum()
  end

  defp total_packets_received(_report), do: nil

  defp broadcast_metrics_updated(sensor_pod_id) do
    Phoenix.PubSub.broadcast(
      ConfigManager.PubSub,
      "sensor_metrics:#{sensor_pod_id}",
      {:metrics_updated, sensor_pod_id}
    )
  end

  defp config(key, default, opts), do: Keyword.get(opts, key, Application.get_env(:config_manager, key, default))

  defp to_integer(value, _fallback) when is_integer(value), do: value

  defp to_integer(value, fallback) when is_binary(value) do
    case Integer.parse(value) do
      {integer, ""} -> integer
      _error -> fallback
    end
  end

  defp to_integer(_value, fallback), do: fallback
end
