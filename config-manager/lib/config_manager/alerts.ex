defmodule ConfigManager.Alerts do
  @moduledoc "Platform alert rule, alert lifecycle, query, and event helpers."

  import Ecto.Query

  alias ConfigManager.Alerts.{Alert, AlertRule}
  alias ConfigManager.{Audit, Repo, SensorPod}
  alias Ecto.Multi

  @active_statuses ~w(firing acknowledged)
  @default_page_size 25

  @default_rules [
    %{
      alert_type: "sensor_offline",
      description: "Sensor stopped reporting health data.",
      severity: "critical",
      enabled: true,
      threshold_value: 60.0,
      threshold_unit: "seconds"
    },
    %{
      alert_type: "packet_drops_high",
      description: "Capture consumer packet drop percentage is above threshold.",
      severity: "warning",
      enabled: true,
      threshold_value: 5.0,
      threshold_unit: "percent"
    },
    %{
      alert_type: "clock_drift",
      description: "Sensor clock offset is above threshold.",
      severity: "warning",
      enabled: true,
      threshold_value: 100.0,
      threshold_unit: "milliseconds"
    },
    %{
      alert_type: "disk_critical",
      description: "Sensor PCAP storage usage is above threshold.",
      severity: "critical",
      enabled: true,
      threshold_value: 90.0,
      threshold_unit: "percent"
    },
    %{
      alert_type: "vector_sink_down",
      description: "Forwarding sink runtime telemetry reports an unhealthy sink.",
      severity: "critical",
      enabled: false,
      threshold_value: 0.0,
      threshold_unit: "boolean"
    },
    %{
      alert_type: "rule_deploy_failed",
      description: "Rule deployment failed for a sensor.",
      severity: "warning",
      enabled: true,
      threshold_value: 0.0,
      threshold_unit: "boolean"
    },
    %{
      alert_type: "cert_expiring",
      description: "Sensor certificate expires within the configured threshold.",
      severity: "warning",
      enabled: true,
      threshold_value: 72.0,
      threshold_unit: "hours"
    },
    %{
      alert_type: "bpf_validation_failed",
      description: "BPF validation failed during a deployment workflow.",
      severity: "warning",
      enabled: false,
      threshold_value: 0.0,
      threshold_unit: "boolean"
    },
    %{
      alert_type: "pcap_prune_failed",
      description: "PCAP retention pruning failed on a sensor.",
      severity: "critical",
      enabled: false,
      threshold_value: 0.0,
      threshold_unit: "boolean"
    }
  ]

  def default_rules, do: @default_rules
  def active_statuses, do: @active_statuses

  def seed_default_rules do
    Enum.each(@default_rules, fn attrs ->
      unless Repo.get_by(AlertRule, alert_type: attrs.alert_type) do
        attrs = Map.put(attrs, :builtin, true)
        %AlertRule{} |> AlertRule.create_changeset(attrs) |> Repo.insert!()
      end
    end)

    :ok
  end

  def list_rules do
    AlertRule
    |> order_by([r], asc: r.alert_type)
    |> Repo.all()
  end

  def enabled_rules do
    AlertRule
    |> where([r], r.enabled == true)
    |> order_by([r], asc: r.alert_type)
    |> Repo.all()
  end

  def get_rule!(id), do: Repo.get!(AlertRule, id)

  def update_rule(%AlertRule{} = rule, attrs, actor) do
    before = %{
      severity: rule.severity,
      enabled: rule.enabled,
      threshold_value: rule.threshold_value
    }

    multi =
      Multi.new()
      |> Multi.update(:rule, AlertRule.update_changeset(rule, attrs))
      |> Audit.append_multi(fn %{rule: updated} ->
        audit_attrs(actor, "alert_rule_updated", "alert_rule", updated.id, %{
          alert_type: updated.alert_type,
          before: before,
          after: %{
            severity: updated.severity,
            enabled: updated.enabled,
            threshold_value: updated.threshold_value
          }
        })
      end)

    case Repo.transaction(multi) do
      {:ok, %{rule: updated}} ->
        Phoenix.PubSub.broadcast(ConfigManager.PubSub, "alert_rules", {:rules_updated})
        {:ok, updated}

      {:error, :rule, changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  def fire_alert(attrs) do
    attrs = normalize_fire_attrs(attrs)

    if active_alert_exists?(attrs.alert_type, attrs.sensor_pod_id) do
      {:error, :duplicate}
    else
      multi =
        Multi.new()
        |> Multi.insert(:alert, Alert.fire_changeset(%Alert{}, attrs))
        |> Audit.append_multi(fn %{alert: alert} ->
          audit_attrs("system", "alert_fired", "alert", alert.id, %{
            alert_type: alert.alert_type,
            sensor_pod_id: alert.sensor_pod_id,
            sensor_pod_db_id: alert.sensor_pod_db_id,
            severity: alert.severity,
            threshold_value: alert.threshold_value,
            observed_value: alert.observed_value
          })
        end)

      case Repo.transaction(multi) do
        {:ok, %{alert: alert}} ->
          alert = preload_alert(alert)
          broadcast_alert(:alert_fired, alert)
          {:ok, alert}

        {:error, :alert, changeset, _changes} ->
          {:error, changeset}

        {:error, _step, reason, _changes} ->
          {:error, reason}
      end
    end
  end

  def auto_resolve_alert(%Alert{} = alert) do
    transition_alert(alert, "system", :resolve, note: "condition cleared")
  end

  def acknowledge_alert(%Alert{} = alert, actor, opts \\ []) do
    transition_alert(alert, actor, :acknowledge, opts)
  end

  def resolve_alert(%Alert{} = alert, actor, opts \\ []) do
    transition_alert(alert, actor, :resolve, opts)
  end

  def bulk_acknowledge(alert_ids, actor, opts \\ []),
    do: bulk_transition(alert_ids, actor, :acknowledge, opts)

  def bulk_resolve(alert_ids, actor, opts \\ []),
    do: bulk_transition(alert_ids, actor, :resolve, opts)

  def get_alert!(id), do: Alert |> Repo.get!(id) |> preload_alert()

  def list_alerts(filters \\ %{}, pagination \\ %{}) do
    page = positive_int(Map.get(pagination, :page) || Map.get(pagination, "page"), 1)

    page_size =
      positive_int(
        Map.get(pagination, :page_size) || Map.get(pagination, "page_size"),
        @default_page_size
      )

    filtered =
      Alert
      |> apply_alert_filters(filters)

    total_count = Repo.aggregate(filtered, :count, :id)

    alerts =
      filtered
      |> order_by([a], desc: a.fired_at, desc: a.id)
      |> limit(^page_size)
      |> offset(^((page - 1) * page_size))
      |> preload(:sensor_pod)
      |> Repo.all()

    meta = %{
      page: page,
      page_size: page_size,
      total_count: total_count,
      total_pages: max(ceil_div(total_count, page_size), 1)
    }

    {alerts, meta}
  end

  def alert_status_counts do
    counts =
      Alert
      |> group_by([a], a.status)
      |> select([a], {a.status, count(a.id)})
      |> Repo.all()
      |> Map.new()

    %{
      firing: Map.get(counts, "firing", 0),
      acknowledged: Map.get(counts, "acknowledged", 0),
      resolved: Map.get(counts, "resolved", 0)
    }
  end

  def firing_alert_count do
    Alert
    |> where([a], a.status == "firing")
    |> Repo.aggregate(:count, :id)
  end

  def active_alerts_for_sensor(sensor_pod_id) do
    Alert
    |> where([a], a.sensor_pod_id == ^sensor_pod_id and a.status in ^@active_statuses)
    |> order_by([a], desc: a.fired_at, desc: a.id)
    |> preload(:sensor_pod)
    |> Repo.all()
  end

  def active_alert_index do
    Alert
    |> where([a], a.status in ^@active_statuses)
    |> select([a], {a.alert_type, a.sensor_pod_id})
    |> Repo.all()
    |> MapSet.new()
  end

  def active_alert_for(alert_type, sensor_pod_id) do
    Alert
    |> where(
      [a],
      a.alert_type == ^to_string(alert_type) and a.sensor_pod_id == ^to_string(sensor_pod_id) and
        a.status in ^@active_statuses
    )
    |> order_by([a], asc: a.fired_at)
    |> limit(1)
    |> Repo.one()
  end

  def publish_system_event(event_type, sensor_pod_id, detail \\ %{}) do
    Phoenix.PubSub.broadcast(
      ConfigManager.PubSub,
      "system_events",
      {:system_event, event_type, sensor_pod_id, detail}
    )
  end

  def alert_type_label(type) do
    type |> to_string() |> String.replace("_", " ") |> String.capitalize()
  end

  def severity_class("critical"), do: "bg-red-100 text-red-800"
  def severity_class("warning"), do: "bg-yellow-100 text-yellow-900"
  def severity_class("info"), do: "bg-blue-100 text-blue-800"
  def severity_class(_), do: "bg-gray-100 text-gray-800"

  def status_class("firing"), do: "bg-red-100 text-red-800"
  def status_class("acknowledged"), do: "bg-yellow-100 text-yellow-900"
  def status_class("resolved"), do: "bg-green-100 text-green-800"
  def status_class(_), do: "bg-gray-100 text-gray-800"

  defp transition_alert(%Alert{} = alert, actor, action, opts) do
    changeset =
      case action do
        :acknowledge -> Alert.acknowledge_changeset(alert, actor, opts)
        :resolve -> Alert.resolve_changeset(alert, actor, opts)
      end

    audit_action =
      case action do
        :acknowledge -> "alert_acknowledged"
        :resolve -> "alert_resolved"
      end

    multi =
      Multi.new()
      |> Multi.update(:alert, changeset)
      |> Audit.append_multi(fn %{alert: updated} ->
        audit_attrs(actor, audit_action, "alert", updated.id, %{
          alert_type: updated.alert_type,
          sensor_pod_id: updated.sensor_pod_id,
          status: updated.status,
          note: updated.note
        })
      end)

    case Repo.transaction(multi) do
      {:ok, %{alert: updated}} ->
        updated = preload_alert(updated)
        broadcast_alert(alert_event_for(updated), updated)
        {:ok, updated}

      {:error, :alert, changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  defp bulk_transition(alert_ids, actor, action, opts) do
    alert_ids = Enum.uniq(Enum.map(alert_ids, &to_string/1))

    alerts =
      Alert
      |> where([a], a.id in ^alert_ids)
      |> Repo.all()

    multi =
      Enum.reduce(alerts, Multi.new(), fn alert, multi ->
        transition_name = {:alert, alert.id}
        audit_name = {:audit, alert.id}

        changeset =
          case action do
            :acknowledge -> Alert.acknowledge_changeset(alert, actor, opts)
            :resolve -> Alert.resolve_changeset(alert, actor, opts)
          end

        audit_action =
          case action do
            :acknowledge -> "alert_acknowledged"
            :resolve -> "alert_resolved"
          end

        multi
        |> Multi.update(transition_name, changeset)
        |> Audit.append_multi(audit_name, fn changes ->
          updated = Map.fetch!(changes, transition_name)

          audit_attrs(actor, audit_action, "alert", updated.id, %{
            alert_type: updated.alert_type,
            sensor_pod_id: updated.sensor_pod_id,
            status: updated.status
          })
        end)
      end)

    case Repo.transaction(multi) do
      {:ok, changes} ->
        updated =
          changes
          |> Enum.filter(fn {key, _value} -> match?({:alert, _id}, key) end)
          |> Enum.map(fn {_key, alert} -> preload_alert(alert) end)

        Enum.each(updated, &broadcast_alert(alert_event_for(&1), &1))
        {:ok, length(updated)}

      {:error, _step, %Ecto.Changeset{} = changeset, _changes} ->
        {:error, changeset}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  defp normalize_fire_attrs(attrs) do
    attrs = Map.new(attrs)
    sensor_pod_id = to_string(Map.get(attrs, :sensor_pod_id) || Map.get(attrs, "sensor_pod_id"))

    pod =
      find_sensor(
        sensor_pod_id,
        Map.get(attrs, :sensor_pod_db_id) || Map.get(attrs, "sensor_pod_db_id")
      )

    attrs
    |> stringify_keys()
    |> Map.put_new(:status, "firing")
    |> Map.put(:sensor_pod_id, sensor_pod_id)
    |> Map.put(:sensor_pod_db_id, pod && pod.id)
  end

  defp stringify_keys(attrs) do
    Enum.reduce(attrs, %{}, fn {key, value}, acc ->
      Map.put(acc, key |> to_string() |> String.to_atom(), value)
    end)
  end

  defp find_sensor(sensor_pod_id, nil) do
    Repo.get_by(SensorPod, name: sensor_pod_id)
  end

  defp find_sensor(_sensor_pod_id, sensor_pod_db_id) do
    Repo.get(SensorPod, sensor_pod_db_id)
  end

  defp active_alert_exists?(alert_type, sensor_pod_id) do
    Alert
    |> where(
      [a],
      a.alert_type == ^alert_type and a.sensor_pod_id == ^sensor_pod_id and
        a.status in ^@active_statuses
    )
    |> Repo.exists?()
  end

  defp apply_alert_filters(query, filters) do
    filters
    |> Map.new(fn {key, value} -> {to_string(key), normalize_filter(value)} end)
    |> Enum.reduce(query, fn
      {_key, ""}, query ->
        query

      {"severity", severity}, query ->
        where(query, [a], a.severity == ^severity)

      {"alert_type", alert_type}, query ->
        where(query, [a], a.alert_type == ^alert_type)

      {"status", status}, query ->
        where(query, [a], a.status == ^status)

      {"sensor_pod_id", sensor_pod_id}, query ->
        where(query, [a], a.sensor_pod_id == ^sensor_pod_id)

      {"search", search}, query ->
        pattern = "%#{search}%"
        where(query, [a], like(a.message, ^pattern) or like(a.sensor_pod_id, ^pattern))

      {_unknown, _value}, query ->
        query
    end)
  end

  defp normalize_filter(nil), do: ""
  defp normalize_filter(value) when is_binary(value), do: String.trim(value)
  defp normalize_filter(value), do: to_string(value)

  defp preload_alert(alert), do: Repo.preload(alert, :sensor_pod)

  defp broadcast_alert(event, alert) do
    Phoenix.PubSub.broadcast(ConfigManager.PubSub, "alerts", {event, alert})

    Phoenix.PubSub.broadcast(
      ConfigManager.PubSub,
      "alert:sensor:#{alert.sensor_pod_id}",
      {event, alert}
    )
  end

  defp alert_event_for(%Alert{status: "resolved"}), do: :alert_resolved
  defp alert_event_for(_alert), do: :alert_updated

  defp audit_attrs(actor, action, target_type, target_id, detail) do
    %{
      actor: actor_name(actor),
      actor_type: actor_type(actor),
      action: action,
      target_type: target_type,
      target_id: target_id,
      result: "success",
      detail: detail
    }
  end

  defp actor_name(%{username: username}) when is_binary(username) and username != "", do: username
  defp actor_name(actor) when is_binary(actor) and actor != "", do: actor
  defp actor_name(_actor), do: "system"

  defp actor_type(%{username: _username}), do: "user"
  defp actor_type("system"), do: "system"
  defp actor_type(actor) when is_binary(actor), do: "user"
  defp actor_type(_actor), do: "system"

  defp positive_int(value, _fallback) when is_integer(value) and value > 0, do: value

  defp positive_int(value, fallback) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} when int > 0 -> int
      _ -> fallback
    end
  end

  defp positive_int(_value, fallback), do: fallback

  defp ceil_div(0, _denominator), do: 0
  defp ceil_div(numerator, denominator), do: div(numerator + denominator - 1, denominator)
end
