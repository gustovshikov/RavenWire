defmodule ConfigManager.Alerts.AlertEngineTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Alerts
  alias ConfigManager.Alerts.{Alert, AlertEngine, AlertRule}
  alias ConfigManager.{Repo, SensorPod}

  setup do
    Repo.delete_all(Alert)
    Repo.delete_all(AlertRule)
    Alerts.seed_default_rules()
    :ok
  end

  test "health report evaluation fires and auto-resolves supported alerts" do
    pod = insert_sensor!("engine-health-sensor")
    {:ok, state} = AlertEngine.init(subscribe?: false, schedule?: false)

    report = %Health.HealthReport{
      timestamp_unix_ms: DateTime.utc_now() |> DateTime.to_unix(:millisecond),
      capture: %Health.CaptureStats{
        consumers: %{
          "zeek" => %Health.ConsumerStats{drop_percent: 8.0}
        }
      },
      storage: %Health.StorageStats{used_percent: 95.0},
      clock: %Health.ClockStats{offset_ms: 150}
    }

    :ets.insert(:health_registry, {pod.name, report})
    assert {:noreply, state} = AlertEngine.handle_info({:pod_updated, pod.name}, state)

    assert Repo.get_by!(Alert, alert_type: "packet_drops_high", sensor_pod_id: pod.name)
    assert Repo.get_by!(Alert, alert_type: "disk_critical", sensor_pod_id: pod.name)
    assert Repo.get_by!(Alert, alert_type: "clock_drift", sensor_pod_id: pod.name)

    clearing = %{
      report
      | capture: %Health.CaptureStats{
          consumers: %{"zeek" => %Health.ConsumerStats{drop_percent: 0.1}}
        },
        storage: %Health.StorageStats{used_percent: 20.0},
        clock: %Health.ClockStats{offset_ms: 1}
    }

    :ets.insert(:health_registry, {pod.name, clearing})
    assert {:noreply, _state} = AlertEngine.handle_info({:pod_updated, pod.name}, state)

    assert Repo.get_by!(Alert, alert_type: "packet_drops_high", sensor_pod_id: pod.name).status ==
             "resolved"
  end

  test "offline and cert checks fire alerts from persisted sensor state" do
    old_seen = DateTime.utc_now() |> DateTime.add(-120, :second) |> DateTime.truncate(:second)
    expiring = DateTime.utc_now() |> DateTime.add(2, :hour) |> DateTime.truncate(:second)

    pod =
      insert_sensor!("engine-periodic-sensor", last_seen_at: old_seen, cert_expires_at: expiring)

    {:ok, state} = AlertEngine.init(subscribe?: false, schedule?: false)
    assert {:noreply, _state} = AlertEngine.handle_info(:check_periodic, state)

    assert Repo.get_by!(Alert, alert_type: "sensor_offline", sensor_pod_id: pod.name)
    assert Repo.get_by!(Alert, alert_type: "cert_expiring", sensor_pod_id: pod.name)
  end

  test "rule deployment system event fires and success event resolves" do
    pod = insert_sensor!("engine-event-sensor")
    {:ok, state} = AlertEngine.init(subscribe?: false, schedule?: false)

    assert {:noreply, state} =
             AlertEngine.handle_info(
               {:system_event, :rule_deploy_failed, pod.name,
                %{sensor_pod_db_id: pod.id, reason: "push failed"}},
               state
             )

    alert = Repo.get_by!(Alert, alert_type: "rule_deploy_failed", sensor_pod_id: pod.name)
    assert alert.status == "firing"

    assert {:noreply, _state} =
             AlertEngine.handle_info(
               {:system_event, :rule_deploy_success, pod.name, %{sensor_pod_db_id: pod.id}},
               state
             )

    assert Repo.get!(Alert, alert.id).status == "resolved"
  end

  test "disabled deferred rules do not fire" do
    pod = insert_sensor!("engine-deferred-sensor")
    {:ok, state} = AlertEngine.init(subscribe?: false, schedule?: false)

    assert {:noreply, _state} =
             AlertEngine.handle_info(
               {:system_event, :pcap_prune_failed, pod.name, %{sensor_pod_db_id: pod.id}},
               state
             )

    refute Repo.get_by(Alert, alert_type: "pcap_prune_failed", sensor_pod_id: pod.name)
  end

  test "pure evaluation helpers classify thresholds" do
    rule = Repo.get_by!(AlertRule, alert_type: "clock_drift")

    assert AlertEngine.evaluate_health_rule(
             rule,
             %Health.HealthReport{clock: %Health.ClockStats{offset_ms: 101}},
             "pod"
           ) == :fire

    assert AlertEngine.evaluate_health_rule(
             rule,
             %Health.HealthReport{clock: %Health.ClockStats{offset_ms: 1}},
             "pod"
           ) == :resolve
  end

  defp insert_sensor!(name, attrs \\ []) do
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
      cert_expires_at:
        Keyword.get(attrs, :cert_expires_at, DateTime.add(now, 7 * 24 * 60 * 60, :second)),
      last_seen_at: Keyword.get(attrs, :last_seen_at, now)
    })
    |> Repo.update!()
  end
end
