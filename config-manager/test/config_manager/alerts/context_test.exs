defmodule ConfigManager.Alerts.ContextTest do
  use ConfigManager.DataCase, async: false
  use PropCheck

  alias ConfigManager.Alerts
  alias ConfigManager.Alerts.{Alert, AlertRule}
  alias ConfigManager.{AuditEntry, Repo, SensorPod}

  setup do
    Repo.delete_all(Alert)
    Repo.delete_all(AlertRule)
    Alerts.seed_default_rules()
    :ok
  end

  test "seed_default_rules creates enabled supported rules and disabled deferred rules" do
    rules = Alerts.list_rules()
    assert length(rules) == 9

    assert Repo.get_by!(AlertRule, alert_type: "sensor_offline").enabled
    assert Repo.get_by!(AlertRule, alert_type: "packet_drops_high").enabled
    assert Repo.get_by!(AlertRule, alert_type: "clock_drift").enabled
    assert Repo.get_by!(AlertRule, alert_type: "disk_critical").enabled
    assert Repo.get_by!(AlertRule, alert_type: "rule_deploy_failed").enabled
    assert Repo.get_by!(AlertRule, alert_type: "cert_expiring").enabled

    refute Repo.get_by!(AlertRule, alert_type: "vector_sink_down").enabled
    refute Repo.get_by!(AlertRule, alert_type: "bpf_validation_failed").enabled
    refute Repo.get_by!(AlertRule, alert_type: "pcap_prune_failed").enabled

    Alerts.seed_default_rules()
    assert Repo.aggregate(AlertRule, :count, :id) == 9
  end

  test "update_rule persists threshold and writes audit" do
    rule = Repo.get_by!(AlertRule, alert_type: "packet_drops_high")

    assert {:ok, updated} =
             Alerts.update_rule(
               rule,
               %{"severity" => "critical", "enabled" => "true", "threshold_value" => "7.5"},
               "tester"
             )

    assert updated.severity == "critical"
    assert updated.threshold_value == 7.5

    audit = Repo.get_by!(AuditEntry, action: "alert_rule_updated", target_id: rule.id)
    assert audit.actor == "tester"
    assert audit.target_type == "alert_rule"
  end

  test "fire, deduplicate, acknowledge, resolve, query, and count alerts" do
    pod = insert_sensor!("alert-context-sensor")

    attrs = %{
      alert_type: "disk_critical",
      sensor_pod_id: pod.name,
      sensor_pod_db_id: pod.id,
      severity: "critical",
      message: "Storage critical",
      threshold_value: 90.0,
      observed_value: 95.0
    }

    assert {:ok, alert} = Alerts.fire_alert(attrs)
    assert {:error, :duplicate} = Alerts.fire_alert(attrs)

    assert alert.status == "firing"
    assert Repo.get_by!(AuditEntry, action: "alert_fired", target_id: alert.id)

    assert {:ok, acked} = Alerts.acknowledge_alert(alert, "operator", note: "working it")
    assert acked.status == "acknowledged"
    assert acked.note == "working it"

    assert {:ok, resolved} = Alerts.resolve_alert(acked, "operator")
    assert resolved.status == "resolved"
    assert resolved.resolved_by == "operator"

    {alerts, meta} = Alerts.list_alerts(%{"severity" => "critical", "search" => "Storage"}, %{})
    assert Enum.map(alerts, & &1.id) == [alert.id]
    assert meta.total_count == 1

    assert Alerts.alert_status_counts().resolved == 1
    assert Alerts.firing_alert_count() == 0
    assert Alerts.active_alerts_for_sensor(pod.name) == []
  end

  test "bulk transitions update multiple alerts" do
    pod = insert_sensor!("alert-bulk-sensor")
    first = fire!(pod, "clock_drift", "Clock drift", 150.0)
    second = fire!(pod, "packet_drops_high", "Packet drops", 10.0)

    assert {:ok, 2} = Alerts.bulk_acknowledge([first.id, second.id], "bulk-user")
    assert Repo.get!(Alert, first.id).status == "acknowledged"
    assert Repo.get!(Alert, second.id).status == "acknowledged"

    assert {:ok, 2} = Alerts.bulk_resolve([first.id, second.id], "bulk-user")
    assert Repo.get!(Alert, first.id).status == "resolved"
    assert Repo.get!(Alert, second.id).status == "resolved"
  end

  property "alert rule threshold validation enforces ranges", [:verbose, numtests: 80] do
    forall code <- integer(0, 10_000) do
      {alert_type, threshold, valid?} = threshold_case(code)
      rule = Repo.get_by!(AlertRule, alert_type: alert_type)
      changeset = AlertRule.update_changeset(rule, %{threshold_value: threshold})
      changeset.valid? == valid?
    end
  end

  defp threshold_case(code) do
    case rem(code, 6) do
      0 -> {"packet_drops_high", rem(code, 101), true}
      1 -> {"packet_drops_high", -1.0, false}
      2 -> {"disk_critical", 101.0, false}
      3 -> {"clock_drift", rem(code, 500) + 1, true}
      4 -> {"sensor_offline", 0.0, false}
      5 -> {"rule_deploy_failed", 0.0, true}
    end
  end

  defp fire!(pod, alert_type, message, observed) do
    {:ok, alert} =
      Alerts.fire_alert(%{
        alert_type: alert_type,
        sensor_pod_id: pod.name,
        sensor_pod_db_id: pod.id,
        severity: "warning",
        message: message,
        threshold_value: 1.0,
        observed_value: observed
      })

    alert
  end

  defp insert_sensor!(name) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint",
      enrolled_at: now,
      enrolled_by: "tester"
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(%{
      status: "enrolled",
      cert_serial: "#{name}-serial",
      cert_expires_at: DateTime.add(now, 7 * 24 * 60 * 60, :second)
    })
    |> Repo.update!()
  end
end
