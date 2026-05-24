defmodule ConfigManager.Alerts.AlertEngine do
  @moduledoc "Evaluates platform alert rules against health reports and system events."

  use GenServer

  import Ecto.Query

  alias ConfigManager.Alerts
  alias ConfigManager.Alerts.AlertRule
  alias ConfigManager.Health.Registry
  alias ConfigManager.{Repo, SensorPod}

  @check_interval_ms 10_000
  @health_rule_types ~w(clock_drift packet_drops_high disk_critical)
  @system_event_types ~w(
    rule_deploy_failed
    rule_deploy_success
    bpf_validation_failed
    pcap_prune_failed
    vector_sink_down
  )

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  def evaluate_health_rule(%AlertRule{enabled: false}, _report, _pod_id), do: :noop

  def evaluate_health_rule(%AlertRule{alert_type: alert_type} = rule, report, _pod_id)
      when alert_type in @health_rule_types do
    case observed_value(alert_type, report) do
      nil ->
        :noop

      observed ->
        if exceeds_threshold?(alert_type, observed, rule.threshold_value),
          do: :fire,
          else: :resolve
    end
  end

  def evaluate_health_rule(_rule, _report, _pod_id), do: :noop

  def check_offline(nil, _threshold_sec, _now), do: :noop

  def check_offline(last_seen, threshold_sec, now) do
    if DateTime.diff(now, last_seen, :second) > threshold_sec, do: :fire, else: :resolve
  end

  def check_cert_expiring(nil, _threshold_hours, _now), do: :noop

  def check_cert_expiring(cert_expires_at, threshold_hours, now) do
    expires_in_seconds = DateTime.diff(cert_expires_at, now, :second)

    cond do
      expires_in_seconds < 0 -> :fire
      expires_in_seconds <= trunc(threshold_hours * 3600) -> :fire
      true -> :resolve
    end
  end

  @impl true
  def init(opts) do
    Alerts.seed_default_rules()

    if Keyword.get(opts, :subscribe?, true) do
      Phoenix.PubSub.subscribe(ConfigManager.PubSub, "sensor_pods")
      Phoenix.PubSub.subscribe(ConfigManager.PubSub, "system_events")
      Phoenix.PubSub.subscribe(ConfigManager.PubSub, "alert_rules")
    end

    state = %{
      rules: load_enabled_rules(),
      active_alerts: Alerts.active_alert_index(),
      last_seen: load_last_seen()
    }

    if Keyword.get(opts, :schedule?, true), do: schedule_check()
    {:ok, state}
  end

  @impl true
  def handle_info({:pod_updated, pod_id}, state) do
    report = Registry.get(pod_id)

    state =
      if report do
        seen_at = report_seen_at(report)

        state
        |> put_in([:last_seen, pod_id], seen_at)
        |> evaluate_health_report(pod_id, report)
      else
        state
      end

    {:noreply, state}
  end

  def handle_info({:system_event, event_type, pod_id, detail}, state) do
    event_type = to_string(event_type)

    state =
      if event_type in @system_event_types,
        do: evaluate_system_event(state, event_type, to_string(pod_id), detail || %{}),
        else: state

    {:noreply, state}
  end

  def handle_info({:rules_updated}, state) do
    {:noreply, %{state | rules: load_enabled_rules()}}
  end

  def handle_info(:check_periodic, state) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    state =
      SensorPod
      |> where([p], p.status == "enrolled")
      |> Repo.all()
      |> Enum.reduce(state, fn pod, state ->
        state
        |> check_sensor_offline(pod, now)
        |> check_sensor_cert(pod, now)
      end)

    schedule_check()
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp evaluate_health_report(state, pod_id, report) do
    Enum.reduce(@health_rule_types, state, fn alert_type, state ->
      case Map.get(state.rules, alert_type) do
        nil -> maybe_resolve(state, alert_type, pod_id)
        rule -> evaluate_health_condition(state, rule, pod_id, report)
      end
    end)
  end

  defp evaluate_health_condition(state, rule, pod_id, report) do
    case evaluate_health_rule(rule, report, pod_id) do
      :fire ->
        observed = observed_value(rule.alert_type, report)

        fire(state, rule, pod_id, %{
          observed_value: observed,
          message: health_message(rule.alert_type, pod_id, observed, rule.threshold_value)
        })

      :resolve ->
        maybe_resolve(state, rule.alert_type, pod_id)

      :noop ->
        state
    end
  end

  defp check_sensor_offline(state, pod, now) do
    case Map.get(state.rules, "sensor_offline") do
      nil ->
        maybe_resolve(state, "sensor_offline", pod.name)

      rule ->
        last_seen = Map.get(state.last_seen, pod.name) || pod.last_seen_at

        case check_offline(last_seen, rule.threshold_value, now) do
          :fire ->
            observed = if last_seen, do: DateTime.diff(now, last_seen, :second), else: nil

            fire(state, rule, pod.name, %{
              sensor_pod_db_id: pod.id,
              observed_value: observed,
              message:
                "Sensor #{pod.name} has not reported health for #{observed || "unknown"} seconds."
            })

          :resolve ->
            maybe_resolve(state, "sensor_offline", pod.name)

          :noop ->
            state
        end
    end
  end

  defp check_sensor_cert(state, pod, now) do
    case Map.get(state.rules, "cert_expiring") do
      nil ->
        maybe_resolve(state, "cert_expiring", pod.name)

      rule ->
        case check_cert_expiring(pod.cert_expires_at, rule.threshold_value, now) do
          :fire ->
            observed =
              if pod.cert_expires_at,
                do: DateTime.diff(pod.cert_expires_at, now, :hour),
                else: nil

            fire(state, rule, pod.name, %{
              sensor_pod_db_id: pod.id,
              observed_value: observed,
              message:
                "Sensor #{pod.name} certificate expires within #{rule.threshold_value} hours."
            })

          :resolve ->
            maybe_resolve(state, "cert_expiring", pod.name)

          :noop ->
            state
        end
    end
  end

  defp evaluate_system_event(state, event_type, pod_id, detail) do
    if String.ends_with?(event_type, "_success") do
      alert_type = String.replace_suffix(event_type, "_success", "_failed")
      maybe_resolve(state, alert_type, pod_id)
    else
      evaluate_system_failure_event(state, event_type, pod_id, detail)
    end
  end

  defp evaluate_system_failure_event(state, event_type, pod_id, detail) do
    case Map.get(state.rules, event_type) do
      nil ->
        state

      rule ->
        sensor_db_id = detail[:sensor_pod_db_id] || detail["sensor_pod_db_id"]
        reason = detail[:reason] || detail["reason"] || detail[:message] || detail["message"]

        fire(state, rule, pod_id, %{
          sensor_pod_db_id: sensor_db_id,
          observed_value: 1.0,
          message: system_event_message(event_type, pod_id, reason)
        })
    end
  end

  defp fire(state, rule, pod_id, attrs) do
    key = {rule.alert_type, pod_id}

    if MapSet.member?(state.active_alerts, key) do
      state
    else
      attrs =
        attrs
        |> Map.put(:alert_type, rule.alert_type)
        |> Map.put(:sensor_pod_id, pod_id)
        |> Map.put(:severity, rule.severity)
        |> Map.put(:threshold_value, rule.threshold_value)

      case Alerts.fire_alert(attrs) do
        {:ok, _alert} -> %{state | active_alerts: MapSet.put(state.active_alerts, key)}
        {:error, :duplicate} -> %{state | active_alerts: MapSet.put(state.active_alerts, key)}
        {:error, _reason} -> state
      end
    end
  end

  defp maybe_resolve(state, alert_type, pod_id) do
    key = {alert_type, pod_id}

    if MapSet.member?(state.active_alerts, key) do
      case Alerts.active_alert_for(alert_type, pod_id) do
        nil ->
          %{state | active_alerts: MapSet.delete(state.active_alerts, key)}

        alert ->
          case Alerts.auto_resolve_alert(alert) do
            {:ok, _alert} -> %{state | active_alerts: MapSet.delete(state.active_alerts, key)}
            {:error, _reason} -> state
          end
      end
    else
      state
    end
  end

  defp observed_value("clock_drift", report) do
    case get_in(report, [Access.key(:clock), Access.key(:offset_ms)]) do
      nil -> nil
      value -> abs(value)
    end
  end

  defp observed_value("packet_drops_high", report) do
    report
    |> get_in([Access.key(:capture), Access.key(:consumers)])
    |> case do
      consumers when is_map(consumers) ->
        consumers
        |> Map.values()
        |> Enum.map(&(Map.get(&1, :drop_percent) || 0.0))
        |> Enum.max(fn -> nil end)

      _other ->
        nil
    end
  end

  defp observed_value("disk_critical", report) do
    get_in(report, [Access.key(:storage), Access.key(:used_percent)])
  end

  defp observed_value(_alert_type, _report), do: nil

  defp exceeds_threshold?("clock_drift", observed, threshold), do: observed > threshold
  defp exceeds_threshold?("packet_drops_high", observed, threshold), do: observed > threshold
  defp exceeds_threshold?("disk_critical", observed, threshold), do: observed > threshold

  defp health_message("clock_drift", pod_id, observed, threshold) do
    "Sensor #{pod_id} clock drift is #{observed} ms, above #{threshold} ms."
  end

  defp health_message("packet_drops_high", pod_id, observed, threshold) do
    "Sensor #{pod_id} packet drops are #{Float.round(observed, 2)}%, above #{threshold}%."
  end

  defp health_message("disk_critical", pod_id, observed, threshold) do
    "Sensor #{pod_id} storage usage is #{Float.round(observed, 2)}%, above #{threshold}%."
  end

  defp system_event_message("rule_deploy_failed", pod_id, nil) do
    "Rule deployment failed for sensor #{pod_id}."
  end

  defp system_event_message("rule_deploy_failed", pod_id, reason) do
    "Rule deployment failed for sensor #{pod_id}: #{reason}"
  end

  defp system_event_message(event_type, pod_id, nil),
    do: "#{event_type} reported for sensor #{pod_id}."

  defp system_event_message(event_type, pod_id, reason),
    do: "#{event_type} reported for sensor #{pod_id}: #{reason}"

  defp load_enabled_rules do
    Alerts.enabled_rules()
    |> Map.new(&{&1.alert_type, &1})
  end

  defp load_last_seen do
    SensorPod
    |> where([p], p.status == "enrolled")
    |> select([p], {p.name, p.last_seen_at})
    |> Repo.all()
    |> Enum.reject(fn {_name, seen_at} -> is_nil(seen_at) end)
    |> Map.new()
  end

  defp report_seen_at(%{timestamp_unix_ms: unix_ms}) when is_integer(unix_ms) and unix_ms > 0 do
    case DateTime.from_unix(unix_ms, :millisecond) do
      {:ok, seen_at} -> DateTime.truncate(seen_at, :second)
      {:error, _reason} -> DateTime.utc_now() |> DateTime.truncate(:second)
    end
  end

  defp report_seen_at(_report), do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp schedule_check, do: Process.send_after(self(), :check_periodic, @check_interval_ms)
end
