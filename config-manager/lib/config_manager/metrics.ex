defmodule ConfigManager.Metrics do
  @moduledoc "Historical sensor health metric persistence and query API."

  import Ecto.Query

  alias ConfigManager.{Pools, Repo}
  alias ConfigManager.Metrics.MetricSnapshot

  @time_ranges %{
    "1h" => 60 * 60,
    "6h" => 6 * 60 * 60,
    "24h" => 24 * 60 * 60,
    "72h" => 72 * 60 * 60
  }

  @chart_order ~w(
    packets_received_rate
    drop_percent
    cpu_percent
    memory_bytes
    pcap_disk_used_percent
    clock_offset_ms
    vector_records_per_sec
    sink_buffer_used_percent
  )

  @future_types ~w(vector_records_per_sec sink_buffer_used_percent)

  def valid_metric_types, do: MetricSnapshot.valid_metric_types()
  def chart_order, do: @chart_order
  def valid_time_ranges, do: Map.keys(@time_ranges)
  def future_types, do: @future_types
  def protobuf_available_types, do: valid_metric_types() -- @future_types
  def protobuf_available?(metric_type), do: metric_type in protobuf_available_types()

  def chart_point_limit do
    Application.get_env(:config_manager, :metrics_chart_point_limit, 1_000)
  end

  def write_snapshots([]), do: {:ok, 0}

  def write_snapshots(snapshots) when is_list(snapshots) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    with {:ok, rows} <- build_insert_rows(snapshots, now) do
      {inserted, _result} =
        Repo.insert_all(MetricSnapshot, rows,
          on_conflict: :nothing,
          conflict_target: [:sensor_pod_id, :metric_type, :series_key, :recorded_at]
        )

      {:ok, inserted}
    end
  end

  def list_snapshots(sensor_pod_id, metric_type, time_range, opts \\ []) do
    with {:ok, {start_at, end_at}} <- parse_time_range(time_range, Keyword.get(opts, :now)) do
      point_limit = Keyword.get(opts, :point_limit, chart_point_limit())
      series_key = Keyword.get(opts, :series_key)

      snapshots =
        MetricSnapshot
        |> where([s], s.sensor_pod_id == ^sensor_pod_id)
        |> where([s], s.metric_type == ^metric_type)
        |> where([s], s.recorded_at >= ^start_at and s.recorded_at <= ^end_at)
        |> maybe_filter_series(series_key)
        |> order_by([s], asc: s.recorded_at)
        |> Repo.all()
        |> downsample(point_limit)

      {:ok, snapshots}
    end
  end

  def list_snapshots_for_pool(pool_id, metric_type, time_range, opts \\ []) do
    with {:ok, {start_at, end_at}} <- parse_time_range(time_range, Keyword.get(opts, :now)) do
      members = Pools.list_pool_sensors(pool_id)
      member_ids = Enum.map(members, & &1.id)
      point_limit = Keyword.get(opts, :point_limit, chart_point_limit())

      snapshots =
        MetricSnapshot
        |> where([s], s.sensor_pod_id in ^member_ids)
        |> where([s], s.metric_type == ^metric_type)
        |> where([s], s.recorded_at >= ^start_at and s.recorded_at <= ^end_at)
        |> order_by([s], asc: s.sensor_pod_id, asc: s.series_key, asc: s.recorded_at)
        |> Repo.all()
        |> Enum.group_by(&{&1.sensor_pod_id, &1.series_key})
        |> Map.new(fn {key, values} -> {key, downsample(values, point_limit)} end)

      {:ok, %{members: members, snapshots: snapshots}}
    end
  end

  def available_metric_types(sensor_pod_id) do
    MetricSnapshot
    |> where([s], s.sensor_pod_id == ^sensor_pod_id)
    |> select([s], s.metric_type)
    |> Repo.all()
    |> Enum.uniq()
    |> Enum.sort()
  end

  def latest_snapshot(sensor_pod_id, metric_type, opts \\ []) do
    series_key = Keyword.get(opts, :series_key)

    MetricSnapshot
    |> where([s], s.sensor_pod_id == ^sensor_pod_id and s.metric_type == ^metric_type)
    |> maybe_filter_series(series_key)
    |> order_by([s], desc: s.recorded_at)
    |> limit(1)
    |> Repo.one()
  end

  def latest_snapshots(sensor_pod_id, metric_type, opts \\ []) do
    limit_count = Keyword.get(opts, :limit, 25)

    MetricSnapshot
    |> where([s], s.sensor_pod_id == ^sensor_pod_id and s.metric_type == ^metric_type)
    |> order_by([s], desc: s.recorded_at)
    |> limit(^limit_count)
    |> Repo.all()
    |> Enum.reverse()
  end

  def prune_before(cutoff, batch_size) do
    batch_size = max(to_integer(batch_size, 1000), 1)
    do_prune_before(cutoff, batch_size, 0)
  end

  def parse_time_range(range, now \\ nil)

  def parse_time_range(range, now) when is_binary(range) do
    case Map.fetch(@time_ranges, range) do
      {:ok, seconds} ->
        now = now || DateTime.utc_now()
        end_at = DateTime.truncate(now, :microsecond)
        {:ok, {DateTime.add(end_at, -seconds, :second), end_at}}

      :error ->
        {:error, :invalid_range}
    end
  end

  def parse_time_range(_range, _now), do: {:error, :invalid_range}

  def default_range, do: "6h"

  def range_or_default(range) do
    if Map.has_key?(@time_ranges, to_string(range)), do: to_string(range), else: default_range()
  end

  def metric_label("packets_received_rate"), do: "Packets received rate"
  def metric_label("drop_percent"), do: "Drop percent"
  def metric_label("cpu_percent"), do: "CPU percent"
  def metric_label("memory_bytes"), do: "Memory usage"
  def metric_label("pcap_disk_used_percent"), do: "PCAP disk used"
  def metric_label("clock_offset_ms"), do: "Clock offset"
  def metric_label("vector_records_per_sec"), do: "Vector records per second"
  def metric_label("sink_buffer_used_percent"), do: "Sink buffer used"

  def metric_label(metric_type) do
    metric_type |> to_string() |> String.replace("_", " ") |> String.capitalize()
  end

  def metric_unit("packets_received_rate"), do: "pps"
  def metric_unit("drop_percent"), do: "%"
  def metric_unit("cpu_percent"), do: "%"
  def metric_unit("memory_bytes"), do: "bytes"
  def metric_unit("pcap_disk_used_percent"), do: "%"
  def metric_unit("clock_offset_ms"), do: "ms"
  def metric_unit("vector_records_per_sec"), do: "rec/s"
  def metric_unit("sink_buffer_used_percent"), do: "%"
  def metric_unit(_metric_type), do: ""

  def decode_metadata(%MetricSnapshot{metadata: metadata}), do: decode_metadata(metadata)
  def decode_metadata(nil), do: %{}

  def decode_metadata(metadata) when is_binary(metadata) do
    case Jason.decode(metadata) do
      {:ok, decoded} when is_map(decoded) -> decoded
      _error -> %{}
    end
  end

  def downsample(snapshots, limit) when is_integer(limit) and limit > 0 do
    snapshots
    |> Enum.group_by(& &1.series_key)
    |> Enum.flat_map(fn {_series_key, values} -> downsample_series(values, limit) end)
    |> Enum.sort_by(& &1.recorded_at, DateTime)
  end

  def downsample(snapshots, _limit), do: snapshots

  defp build_insert_rows(snapshots, now) do
    snapshots
    |> Enum.reduce_while({:ok, []}, fn attrs, {:ok, rows} ->
      changeset = MetricSnapshot.changeset(%MetricSnapshot{}, attrs)

      case Ecto.Changeset.apply_action(changeset, :insert) do
        {:ok, snapshot} ->
          row =
            snapshot
            |> Map.take([:id, :sensor_pod_id, :metric_type, :series_key, :value, :recorded_at, :metadata])
            |> Map.put(:id, snapshot.id || Ecto.UUID.generate())
            |> Map.put(:inserted_at, now)
            |> Map.put(:updated_at, now)

          {:cont, {:ok, [row | rows]}}

        {:error, changeset} ->
          {:halt, {:error, changeset}}
      end
    end)
    |> case do
      {:ok, rows} -> {:ok, Enum.reverse(rows)}
      {:error, changeset} -> {:error, changeset}
    end
  end

  defp maybe_filter_series(query, nil), do: query
  defp maybe_filter_series(query, ""), do: query
  defp maybe_filter_series(query, series_key), do: where(query, [s], s.series_key == ^series_key)

  defp do_prune_before(cutoff, batch_size, total_deleted) do
    ids =
      MetricSnapshot
      |> where([s], s.recorded_at < ^cutoff)
      |> order_by([s], asc: s.recorded_at)
      |> limit(^batch_size)
      |> select([s], s.id)
      |> Repo.all()

    if ids == [] do
      {:ok, total_deleted}
    else
      {deleted, _result} =
        MetricSnapshot
        |> where([s], s.id in ^ids)
        |> Repo.delete_all()

      if deleted < batch_size do
        {:ok, total_deleted + deleted}
      else
        do_prune_before(cutoff, batch_size, total_deleted + deleted)
      end
    end
  end

  defp downsample_series(values, limit) do
    values = Enum.sort_by(values, & &1.recorded_at, DateTime)

    if length(values) <= limit do
      values
    else
      chunk_size = values |> length() |> Kernel./(limit) |> Float.ceil() |> trunc()

      values
      |> Enum.chunk_every(chunk_size)
      |> Enum.map(&average_chunk/1)
    end
  end

  defp average_chunk([first | _rest] = chunk) do
    average = Enum.sum(Enum.map(chunk, & &1.value)) / length(chunk)
    metadata = first |> decode_metadata() |> Map.put("downsampled", true) |> Jason.encode!()
    %{first | value: average, metadata: metadata}
  end

  defp to_integer(value, _fallback) when is_integer(value), do: value

  defp to_integer(value, fallback) when is_binary(value) do
    case Integer.parse(value) do
      {integer, ""} -> integer
      _error -> fallback
    end
  end

  defp to_integer(_value, fallback), do: fallback
end
