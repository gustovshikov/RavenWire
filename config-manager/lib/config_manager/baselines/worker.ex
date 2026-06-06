defmodule ConfigManager.Baselines.Worker do
  @moduledoc "Periodically computes baselines and evaluates metric anomalies."

  use GenServer

  require Logger

  import Ecto.Query

  alias ConfigManager.Alerts
  alias ConfigManager.Alerts.AlertRule
  alias ConfigManager.Baselines
  alias ConfigManager.Baselines.HealthBaseline
  alias ConfigManager.Metrics.MetricSnapshot
  alias ConfigManager.{Repo, SensorPod}

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  def recompute_once(pid \\ __MODULE__), do: GenServer.call(pid, :recompute_once, 60_000)
  def forecast_once(pid \\ __MODULE__), do: GenServer.call(pid, :forecast_once, 60_000)

  def get_forecasts(pid \\ __MODULE__, sensor_pod_id),
    do: GenServer.call(pid, {:get_forecasts, sensor_pod_id})

  def get_anomaly_status(pid \\ __MODULE__, sensor_pod_id),
    do: GenServer.call(pid, {:get_anomaly_status, sensor_pod_id})

  @impl true
  def init(opts) do
    if Keyword.get(opts, :subscribe?, true) do
      subscribe_to_sensors()
      Phoenix.PubSub.subscribe(ConfigManager.PubSub, "sensor_pods")
      Phoenix.PubSub.subscribe(ConfigManager.PubSub, "alert_rules")
    end

    state = %{
      baselines: load_baseline_cache(),
      rules: load_enabled_rules(),
      forecasts: %{},
      anomalies: %{},
      cooldowns: %{},
      schedule?: Keyword.get(opts, :schedule?, true),
      recompute_interval_ms:
        Keyword.get(opts, :recompute_interval_ms, Baselines.baseline_recompute_interval_ms()),
      forecast_interval_ms:
        Keyword.get(opts, :forecast_interval_ms, Baselines.forecast_interval_ms())
    }

    if state.schedule? do
      Process.send_after(self(), :recompute_baselines, 1_000)
      Process.send_after(self(), :recompute_forecasts, 2_000)
    end

    {:ok, state}
  end

  @impl true
  def handle_call(:recompute_once, _from, state) do
    state = recompute_baselines(state)
    {:reply, :ok, state}
  end

  def handle_call(:forecast_once, _from, state) do
    state = recompute_forecasts(state)
    {:reply, :ok, state}
  end

  def handle_call({:get_forecasts, sensor_pod_id}, _from, state) do
    {:reply, Map.get(state.forecasts, sensor_pod_id, %{}), state}
  end

  def handle_call({:get_anomaly_status, sensor_pod_id}, _from, state) do
    {:reply, Map.get(state.anomalies, sensor_pod_id, %{}), state}
  end

  @impl true
  def handle_info(:recompute_baselines, state) do
    state = recompute_baselines(state)

    if state.schedule?,
      do: Process.send_after(self(), :recompute_baselines, state.recompute_interval_ms)

    {:noreply, state}
  end

  def handle_info(:recompute_forecasts, state) do
    state = recompute_forecasts(state)

    if state.schedule?,
      do: Process.send_after(self(), :recompute_forecasts, state.forecast_interval_ms)

    {:noreply, state}
  end

  def handle_info({:metrics_updated, sensor_pod_id}, state) do
    {:noreply, evaluate_sensor(sensor_pod_id, state)}
  end

  def handle_info({:pod_enrolled, _pod_id}, state) do
    subscribe_to_sensors()
    {:noreply, state}
  end

  def handle_info({:pod_updated, _pod_id}, state) do
    subscribe_to_sensors()
    {:noreply, state}
  end

  def handle_info({:rules_updated}, state) do
    {:noreply, %{state | rules: load_enabled_rules()}}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp recompute_baselines(state) do
    sensor_baselines = Baselines.compute_all_sensor_baselines()
    pool_baselines = Baselines.compute_all_pool_baselines()

    Phoenix.PubSub.broadcast(ConfigManager.PubSub, "baselines", {:baselines_updated})
    Enum.each(sensor_baselines, &broadcast_sensor_baselines/1)
    Enum.each(pool_baselines, &broadcast_pool_baselines/1)

    %{state | baselines: load_baseline_cache()}
  rescue
    error ->
      Logger.warning("Health baseline recompute failed: #{Exception.message(error)}")
      state
  end

  defp recompute_forecasts(state) do
    forecasts =
      SensorPod
      |> where([p], p.status == "enrolled")
      |> Repo.all()
      |> Map.new(fn pod ->
        pod_forecasts =
          Baselines.capacity_metrics()
          |> Enum.flat_map(&forecast_existing_series(pod, &1))
          |> Map.new(fn forecast -> {{forecast.metric_type, forecast.series_key}, forecast} end)

        maybe_fire_capacity_alerts(pod, pod_forecasts, state.rules)
        {pod.id, pod_forecasts}
      end)

    Enum.each(forecasts, fn {sensor_pod_id, _forecasts} ->
      Phoenix.PubSub.broadcast(
        ConfigManager.PubSub,
        "baselines:sensor:#{sensor_pod_id}",
        {:forecasts_updated, sensor_pod_id}
      )
    end)

    %{state | forecasts: forecasts}
  rescue
    error ->
      Logger.warning("Health baseline forecast failed: #{Exception.message(error)}")
      state
  end

  defp evaluate_sensor(sensor_pod_id, state) do
    {anomalies, evaluated?, anomaly?} =
      sensor_pod_id
      |> latest_snapshots_for_sensor()
      |> Enum.reduce({%{}, false, false}, fn snapshot, {acc, evaluated?, anomaly?} ->
        key = {snapshot.metric_type, snapshot.series_key}

        case Map.get(
               state.baselines,
               {:sensor, sensor_pod_id, snapshot.metric_type, snapshot.series_key}
             ) do
          nil ->
            {acc, evaluated?, anomaly?}

          baseline ->
            case Baselines.evaluate_anomaly(snapshot.value, baseline) do
              {:anomaly, score, details} ->
                maybe_fire_anomaly_alert(snapshot, baseline, score, details, state.rules)

                {Map.put(acc, key, %{score: score, value: snapshot.value, status: :anomaly}),
                 true, true}

              :normal ->
                {Map.put(acc, key, %{score: 0.0, value: snapshot.value, status: :normal}), true,
                 anomaly?}
            end
        end
      end)

    if evaluated? and not anomaly? do
      maybe_resolve_alert("baseline_anomaly", sensor_label(sensor_pod_id))
    end

    Phoenix.PubSub.broadcast(
      ConfigManager.PubSub,
      "baselines:sensor:#{sensor_pod_id}",
      {:anomaly_status, sensor_pod_id, anomalies}
    )

    put_in(state, [:anomalies, sensor_pod_id], anomalies)
  end

  defp maybe_fire_anomaly_alert(snapshot, baseline, score, details, rules) do
    case Map.get(rules, "baseline_anomaly") do
      %AlertRule{} = rule ->
        Alerts.fire_alert(%{
          alert_type: "baseline_anomaly",
          sensor_pod_id: sensor_label(snapshot),
          sensor_pod_db_id: snapshot.sensor_pod_id,
          severity: rule.severity,
          threshold_value: Baselines.sigma_for_metric(snapshot.metric_type),
          observed_value: score,
          message:
            "#{snapshot.metric_type} #{snapshot.series_key} is #{Float.round(score / 1, 2)} sigma from baseline " <>
              "(current #{Float.round(snapshot.value / 1, 2)}, baseline #{Float.round(baseline.mean / 1, 2)}).",
          detail: details
        })

      nil ->
        :ok
    end
  end

  defp maybe_fire_capacity_alerts(pod, forecasts, rules) do
    case Map.get(rules, "capacity_warning") do
      %AlertRule{} = rule ->
        if map_size(forecasts) == 0 do
          maybe_resolve_alert("capacity_warning", pod.name)
        else
          Enum.each(forecasts, fn {{metric_type, series_key}, forecast} ->
            Alerts.fire_alert(%{
              alert_type: "capacity_warning",
              sensor_pod_id: pod.name,
              sensor_pod_db_id: pod.id,
              severity: rule.severity,
              threshold_value: forecast.threshold,
              observed_value: forecast.projected_value,
              message:
                "#{metric_type} #{series_key} is projected to reach #{Float.round(forecast.projected_value / 1, 2)} " <>
                  "within #{Baselines.forecast_horizon_hours()} hours."
            })
          end)
        end

      nil ->
        maybe_resolve_alert("capacity_warning", pod.name)
    end
  end

  defp maybe_resolve_alert(alert_type, sensor_pod_id) do
    case Alerts.active_alert_for(alert_type, sensor_pod_id) do
      nil -> :ok
      alert -> Alerts.auto_resolve_alert(alert)
    end
  end

  defp forecast_existing_series(pod, metric_type) do
    pod.id
    |> existing_series(metric_type)
    |> Enum.flat_map(fn series_key ->
      case Baselines.compute_forecast(pod.id, metric_type, series_key) do
        {:ok, forecast} -> [forecast]
        {:error, _reason} -> []
      end
    end)
  end

  defp latest_snapshots_for_sensor(sensor_pod_id) do
    MetricSnapshot
    |> where([s], s.sensor_pod_id == ^sensor_pod_id)
    |> order_by([s], desc: s.recorded_at)
    |> Repo.all()
    |> Enum.group_by(&{&1.metric_type, &1.series_key})
    |> Enum.map(fn {_key, [snapshot | _rest]} -> snapshot end)
  end

  defp existing_series(sensor_pod_id, metric_type) do
    MetricSnapshot
    |> where([s], s.sensor_pod_id == ^sensor_pod_id and s.metric_type == ^metric_type)
    |> select([s], s.series_key)
    |> Repo.all()
    |> Enum.uniq()
  end

  defp load_baseline_cache do
    HealthBaseline
    |> Repo.all()
    |> Map.new(fn baseline ->
      key =
        if baseline.sensor_pod_id do
          {:sensor, baseline.sensor_pod_id, baseline.metric_type, baseline.series_key}
        else
          {:pool, baseline.pool_id, baseline.metric_type, baseline.series_key}
        end

      {key, baseline}
    end)
  end

  defp load_enabled_rules do
    Alerts.seed_default_rules()

    AlertRule
    |> where([r], r.enabled == true)
    |> Repo.all()
    |> Map.new(&{&1.alert_type, &1})
  end

  defp subscribe_to_sensors do
    SensorPod
    |> select([p], p.id)
    |> Repo.all()
    |> Enum.each(&Phoenix.PubSub.subscribe(ConfigManager.PubSub, "sensor_metrics:#{&1}"))
  end

  defp broadcast_sensor_baselines(%HealthBaseline{sensor_pod_id: sensor_pod_id})
       when is_binary(sensor_pod_id) do
    Phoenix.PubSub.broadcast(
      ConfigManager.PubSub,
      "baselines:sensor:#{sensor_pod_id}",
      {:baselines_updated, sensor_pod_id}
    )
  end

  defp broadcast_sensor_baselines(_baseline), do: :ok

  defp broadcast_pool_baselines(%HealthBaseline{pool_id: pool_id}) when is_binary(pool_id) do
    Phoenix.PubSub.broadcast(
      ConfigManager.PubSub,
      "baselines:pool:#{pool_id}",
      {:baselines_updated, pool_id}
    )
  end

  defp broadcast_pool_baselines(_baseline), do: :ok

  defp sensor_label(%MetricSnapshot{} = snapshot) do
    sensor_label(snapshot.sensor_pod_id)
  end

  defp sensor_label(sensor_pod_id) do
    case Repo.get(SensorPod, sensor_pod_id) do
      %SensorPod{name: name} -> name
      nil -> sensor_pod_id
    end
  end
end
