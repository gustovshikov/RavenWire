defmodule ConfigManager.Baselines do
  @moduledoc "Health baseline persistence, computation, anomaly evaluation, and forecasts."

  import Ecto.Query

  alias ConfigManager.Baselines.{HealthBaseline, Statistics}
  alias ConfigManager.Metrics
  alias ConfigManager.Metrics.MetricSnapshot
  alias ConfigManager.{Pools, Repo, SensorPod, SensorPool}

  @capacity_metrics ~w(pcap_disk_used_percent cpu_percent memory_bytes drop_percent)
  @default_baseline_window_hours 48
  @default_exclusion_minutes 10
  @default_min_samples 240
  @default_forecast_window_hours 6
  @default_forecast_horizon_hours 24
  @default_forecast_min_samples 12
  @default_sigma 3.0
  @default_cooldown_minutes 15

  def capacity_metrics, do: @capacity_metrics

  def upsert_baseline(attrs) do
    changeset = HealthBaseline.changeset(%HealthBaseline{}, attrs)

    with {:ok, baseline} <- Ecto.Changeset.apply_action(changeset, :insert) do
      baseline
      |> baseline_lookup()
      |> case do
        nil ->
          %HealthBaseline{} |> HealthBaseline.changeset(attrs) |> Repo.insert()

        %HealthBaseline{} = existing ->
          existing |> HealthBaseline.changeset(attrs) |> Repo.update()
      end
    end
  end

  def list_baselines_for_sensor(sensor_pod_id) do
    HealthBaseline
    |> where([b], b.sensor_pod_id == ^sensor_pod_id)
    |> order_by([b], asc: b.metric_type, asc: b.series_key)
    |> Repo.all()
  end

  def list_baselines_for_pool(pool_id) do
    HealthBaseline
    |> where([b], b.pool_id == ^pool_id)
    |> order_by([b], asc: b.metric_type, asc: b.series_key)
    |> Repo.all()
  end

  def get_baseline(sensor_pod_id, metric_type, series_key \\ "default") do
    Repo.get_by(HealthBaseline,
      sensor_pod_id: sensor_pod_id,
      metric_type: metric_type,
      series_key: series_key
    )
  end

  def get_pool_baseline(pool_id, metric_type, series_key \\ "default") do
    Repo.get_by(HealthBaseline,
      pool_id: pool_id,
      metric_type: metric_type,
      series_key: series_key
    )
  end

  def compute_sensor_baseline(sensor_pod_id, metric_type, series_key \\ "default", opts \\ []) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:microsecond))
    {start_at, end_at} = baseline_window(now, opts)
    min_samples = Keyword.get(opts, :min_samples, baseline_min_samples())

    snapshots =
      MetricSnapshot
      |> where([s], s.sensor_pod_id == ^sensor_pod_id)
      |> where([s], s.metric_type == ^metric_type and s.series_key == ^series_key)
      |> where([s], s.recorded_at >= ^start_at and s.recorded_at <= ^end_at)
      |> order_by([s], asc: s.recorded_at)
      |> Repo.all()

    snapshots
    |> Enum.map(& &1.value)
    |> Statistics.compute_profile(min_samples)
    |> attach_window(start_at, end_at)
  end

  def compute_pool_baseline(pool_id, metric_type, series_key \\ "default", opts \\ []) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:microsecond))
    {start_at, end_at} = baseline_window(now, opts)
    min_samples = Keyword.get(opts, :min_samples, baseline_min_samples())
    members = Pools.list_pool_sensors(pool_id)

    member_values =
      Enum.map(members, fn member ->
        values =
          MetricSnapshot
          |> where([s], s.sensor_pod_id == ^member.id)
          |> where([s], s.metric_type == ^metric_type and s.series_key == ^series_key)
          |> where([s], s.recorded_at >= ^start_at and s.recorded_at <= ^end_at)
          |> select([s], s.value)
          |> Repo.all()

        {member.id, values}
      end)

    qualifying_values =
      member_values
      |> Enum.filter(fn {_member_id, values} -> length(values) >= min_samples end)
      |> Enum.flat_map(fn {_member_id, values} -> values end)

    cond do
      length(qualifying_values) == 0 ->
        {:error, :insufficient_data}

      member_values |> Enum.count(fn {_member_id, values} -> length(values) >= min_samples end) <
          2 ->
        {:error, :insufficient_sensors}

      true ->
        qualifying_values
        |> Statistics.compute_profile(min_samples)
        |> attach_window(start_at, end_at)
    end
  end

  def compute_all_sensor_baselines(opts \\ []) do
    SensorPod
    |> where([p], p.status == "enrolled")
    |> Repo.all()
    |> Enum.flat_map(fn pod ->
      Metrics.protobuf_available_types()
      |> Enum.flat_map(&compute_existing_sensor_series(pod, &1, opts))
    end)
  end

  def compute_all_pool_baselines(opts \\ []) do
    SensorPool
    |> Repo.all()
    |> Enum.flat_map(fn pool ->
      Metrics.protobuf_available_types()
      |> Enum.flat_map(&compute_existing_pool_series(pool, &1, opts))
    end)
  end

  def evaluate_anomaly(value, %HealthBaseline{} = baseline, opts \\ []) do
    sigma = Keyword.get(opts, :sigma, sigma_for_metric(baseline.metric_type))
    min_delta = Keyword.get(opts, :min_delta, min_delta_for_metric(baseline.metric_type))

    case Statistics.classify(value, baseline, sigma, min_delta) do
      {:anomaly, score} ->
        {:anomaly, score,
         %{
           metric_type: baseline.metric_type,
           series_key: baseline.series_key,
           current_value: value,
           baseline_mean: baseline.mean,
           baseline_stddev: baseline.stddev,
           baseline_p5: baseline.p5,
           baseline_p95: baseline.p95
         }}

      :normal ->
        :normal
    end
  end

  def compute_forecast(sensor_pod_id, metric_type, series_key \\ "default", opts \\ []) do
    with threshold when is_number(threshold) <- capacity_threshold(metric_type, opts),
         {:ok, points} <- forecast_points(sensor_pod_id, metric_type, series_key, opts),
         {:ok, regression} <-
           Statistics.linear_regression(
             points,
             Keyword.get(opts, :min_samples, forecast_min_samples())
           ) do
      now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:microsecond))
      now_unix = DateTime.to_unix(now)
      horizon_seconds = forecast_horizon_hours() * 3600
      projected_at = now_unix + horizon_seconds
      projected_value = Statistics.project(regression, projected_at)
      current_value = points |> List.last() |> elem(1)
      breach = Statistics.time_to_threshold(regression, threshold, now_unix, horizon_seconds)

      if projected_value >= threshold do
        {:ok,
         %{
           metric_type: metric_type,
           series_key: series_key,
           current_value: current_value,
           projected_value: projected_value,
           threshold: threshold,
           projected_at: DateTime.from_unix!(projected_at),
           breach_at: breach_at_datetime(breach),
           r_squared: regression.r_squared
         }}
      else
        {:error, :no_breach}
      end
    else
      nil -> {:error, :not_capacity_metric}
      {:error, reason} -> {:error, reason}
    end
  end

  def capacity_threshold(metric_type, opts \\ [])

  def capacity_threshold("pcap_disk_used_percent", _opts), do: 95.0
  def capacity_threshold("cpu_percent", _opts), do: 95.0
  def capacity_threshold("drop_percent", _opts), do: 10.0

  def capacity_threshold("memory_bytes", opts) do
    case Keyword.get(opts, :total_memory_bytes) do
      value when is_number(value) and value > 0 -> value * 0.90
      _value -> nil
    end
  end

  def capacity_threshold(_metric_type, _opts), do: nil

  def baseline_window_hours,
    do: positive_int_config(:baseline_window_hours, @default_baseline_window_hours)

  def baseline_min_samples, do: positive_int_config(:baseline_min_samples, @default_min_samples)

  def baseline_recompute_interval_ms,
    do: positive_int_config(:baseline_recompute_interval_ms, 3_600_000)

  def default_sigma, do: positive_float_config(:anomaly_default_sigma, @default_sigma)

  def cooldown_minutes,
    do: positive_int_config(:anomaly_cooldown_minutes, @default_cooldown_minutes)

  def forecast_horizon_hours,
    do: positive_int_config(:capacity_forecast_horizon_hours, @default_forecast_horizon_hours)

  def forecast_interval_ms, do: positive_int_config(:capacity_forecast_interval_ms, 900_000)

  def forecast_min_samples,
    do: positive_int_config(:capacity_min_forecast_samples, @default_forecast_min_samples)

  def sigma_for_metric(metric_type) do
    overrides = Application.get_env(:config_manager, :anomaly_sigma_by_metric, %{})
    override = Map.get(overrides, metric_type) || Map.get(overrides, String.to_atom(metric_type))

    case override do
      value when is_number(value) and value > 0 -> value / 1
      _value -> default_sigma()
    end
  end

  def min_delta_for_metric(metric_type) do
    overrides = Application.get_env(:config_manager, :anomaly_min_delta_by_metric, %{})
    value = Map.get(overrides, metric_type) || Map.get(overrides, String.to_atom(metric_type))

    if is_number(value) and value >= 0, do: value / 1, else: 0.0
  end

  def delete_baselines_for_sensor(sensor_pod_id) do
    HealthBaseline
    |> where([b], b.sensor_pod_id == ^sensor_pod_id)
    |> Repo.delete_all()
  end

  def latest_value(sensor_pod_id, metric_type, series_key \\ "default") do
    case Metrics.latest_snapshot(sensor_pod_id, metric_type, series_key: series_key) do
      nil -> nil
      snapshot -> snapshot.value
    end
  end

  def outliers_from_pool_baseline(pool_baseline, sensor_values, sigma \\ 2.0) do
    Enum.filter(sensor_values, fn {_sensor_id, value} ->
      Statistics.classify(
        value,
        pool_baseline,
        sigma,
        min_delta_for_metric(pool_baseline.metric_type)
      ) != :normal
    end)
  end

  defp compute_existing_sensor_series(pod, metric_type, opts) do
    existing_series(pod.id, metric_type)
    |> Enum.flat_map(fn series_key ->
      case compute_sensor_baseline(pod.id, metric_type, series_key, opts) do
        {:ok, profile} ->
          attrs =
            baseline_attrs(profile, %{
              sensor_pod_id: pod.id,
              metric_type: metric_type,
              series_key: series_key
            })

          case upsert_baseline(attrs) do
            {:ok, baseline} -> [baseline]
            {:error, _reason} -> []
          end

        {:error, _reason} ->
          []
      end
    end)
  end

  defp compute_existing_pool_series(pool, metric_type, opts) do
    existing_pool_series(pool.id, metric_type)
    |> Enum.flat_map(fn series_key ->
      case compute_pool_baseline(pool.id, metric_type, series_key, opts) do
        {:ok, profile} ->
          attrs =
            baseline_attrs(profile, %{
              pool_id: pool.id,
              metric_type: metric_type,
              series_key: series_key
            })

          case upsert_baseline(attrs) do
            {:ok, baseline} -> [baseline]
            {:error, _reason} -> []
          end

        {:error, _reason} ->
          []
      end
    end)
  end

  defp baseline_attrs(profile, scope) do
    Map.merge(scope, %{
      mean: profile.mean,
      stddev: profile.stddev,
      p5: profile.p5,
      p95: profile.p95,
      min_value: profile.min_value,
      max_value: profile.max_value,
      sample_count: profile.sample_count,
      window_start: profile.window_start,
      window_end: profile.window_end,
      computed_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    })
  end

  defp existing_series(sensor_pod_id, metric_type) do
    MetricSnapshot
    |> where([s], s.sensor_pod_id == ^sensor_pod_id and s.metric_type == ^metric_type)
    |> select([s], s.series_key)
    |> Repo.all()
    |> Enum.uniq()
  end

  defp existing_pool_series(pool_id, metric_type) do
    member_ids = pool_id |> Pools.list_pool_sensors() |> Enum.map(& &1.id)

    MetricSnapshot
    |> where([s], s.sensor_pod_id in ^member_ids and s.metric_type == ^metric_type)
    |> select([s], s.series_key)
    |> Repo.all()
    |> Enum.uniq()
  end

  defp baseline_lookup(%HealthBaseline{sensor_pod_id: sensor_pod_id, pool_id: nil} = baseline) do
    get_baseline(sensor_pod_id, baseline.metric_type, baseline.series_key)
  end

  defp baseline_lookup(%HealthBaseline{pool_id: pool_id, sensor_pod_id: nil} = baseline) do
    get_pool_baseline(pool_id, baseline.metric_type, baseline.series_key)
  end

  defp baseline_window(now, opts) do
    window_hours = Keyword.get(opts, :window_hours, baseline_window_hours())
    exclusion_minutes = Keyword.get(opts, :exclusion_minutes, @default_exclusion_minutes)
    end_at = DateTime.add(now, -exclusion_minutes * 60, :second)
    start_at = DateTime.add(end_at, -window_hours * 3600, :second)
    {DateTime.truncate(start_at, :microsecond), DateTime.truncate(end_at, :microsecond)}
  end

  defp attach_window({:ok, profile}, start_at, end_at) do
    {:ok, profile |> Map.put(:window_start, start_at) |> Map.put(:window_end, end_at)}
  end

  defp attach_window({:error, reason}, _start_at, _end_at), do: {:error, reason}

  defp forecast_points(sensor_pod_id, metric_type, series_key, opts) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:microsecond))
    start_at = DateTime.add(now, -@default_forecast_window_hours * 3600, :second)

    points =
      MetricSnapshot
      |> where([s], s.sensor_pod_id == ^sensor_pod_id)
      |> where([s], s.metric_type == ^metric_type and s.series_key == ^series_key)
      |> where([s], s.recorded_at >= ^start_at and s.recorded_at <= ^now)
      |> order_by([s], asc: s.recorded_at)
      |> Repo.all()
      |> Enum.map(fn snapshot -> {DateTime.to_unix(snapshot.recorded_at), snapshot.value} end)

    if points == [], do: {:error, :insufficient_data}, else: {:ok, points}
  end

  defp breach_at_datetime({:ok, timestamp}), do: DateTime.from_unix!(trunc(timestamp))
  defp breach_at_datetime({:error, _reason}), do: nil

  defp positive_int_config(key, fallback) do
    value = Application.get_env(:config_manager, key, fallback)
    if is_integer(value) and value > 0, do: value, else: fallback
  end

  defp positive_float_config(key, fallback) do
    value = Application.get_env(:config_manager, key, fallback)
    if is_number(value) and value > 0, do: value / 1, else: fallback
  end
end
