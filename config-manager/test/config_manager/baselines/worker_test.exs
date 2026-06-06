defmodule ConfigManager.Baselines.WorkerTest do
  use ConfigManager.DataCase, async: false

  import Ecto.Query

  alias ConfigManager.Alerts
  alias ConfigManager.Alerts.{Alert, AlertRule}
  alias ConfigManager.Baselines
  alias ConfigManager.Baselines.{HealthBaseline, Worker}
  alias ConfigManager.Metrics
  alias ConfigManager.Metrics.MetricSnapshot
  alias ConfigManager.{Repo, SensorPod}

  setup do
    Repo.delete_all(Alert)
    Repo.delete_all(AlertRule)
    Repo.delete_all(HealthBaseline)
    Repo.delete_all(MetricSnapshot)
    Alerts.seed_default_rules()
    :ok
  end

  test "metric updates fire and auto-resolve baseline anomaly alerts" do
    pod = insert_sensor!("baseline-worker-anomaly")

    {:ok, _baseline} =
      Baselines.upsert_baseline(
        baseline_attrs(%{sensor_pod_id: pod.id, mean: 50.0, stddev: 2.0, p5: 45.0, p95: 55.0})
      )

    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "baselines:sensor:#{pod.id}")

    write_snapshot!(pod.id, "cpu_percent", 70.0, now)

    {:ok, worker} =
      start_supervised(
        {Worker, name: :baseline_worker_anomaly_test, schedule?: false, subscribe?: false}
      )

    send(worker, {:metrics_updated, pod.id})

    pod_id = pod.id
    assert_receive {:anomaly_status, ^pod_id, status}, 1_000
    assert status[{"cpu_percent", "default"}].status == :anomaly
    assert %Alert{status: "firing"} = Alerts.active_alert_for("baseline_anomaly", pod.name)

    write_snapshot!(pod.id, "cpu_percent", 51.0, DateTime.add(now, 60, :second))
    send(worker, {:metrics_updated, pod.id})

    assert_receive {:anomaly_status, ^pod_id, cleared}, 1_000
    assert cleared[{"cpu_percent", "default"}].status == :normal

    assert Repo.get_by!(Alert, alert_type: "baseline_anomaly", sensor_pod_id: pod.name).status ==
             "resolved"
  end

  test "mixed normal and anomalous series do not churn baseline anomaly alerts" do
    pod = insert_sensor!("baseline-worker-mixed-anomaly")

    for series_key <- ["vector", "zeek"] do
      {:ok, _baseline} =
        Baselines.upsert_baseline(
          baseline_attrs(%{
            sensor_pod_id: pod.id,
            metric_type: "cpu_percent",
            series_key: series_key,
            mean: 50.0,
            stddev: 2.0,
            p5: 45.0,
            p95: 55.0
          })
        )
    end

    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "baselines:sensor:#{pod.id}")

    write_snapshot!(pod.id, "cpu_percent", "vector", 80.0, now)
    write_snapshot!(pod.id, "cpu_percent", "zeek", 51.0, now)

    {:ok, worker} =
      start_supervised(
        {Worker, name: :baseline_worker_mixed_anomaly_test, schedule?: false, subscribe?: false}
      )

    send(worker, {:metrics_updated, pod.id})

    pod_id = pod.id
    assert_receive {:anomaly_status, ^pod_id, status}, 1_000
    assert status[{"cpu_percent", "vector"}].status == :anomaly
    assert status[{"cpu_percent", "zeek"}].status == :normal
    assert %Alert{status: "firing"} = Alerts.active_alert_for("baseline_anomaly", pod.name)

    send(worker, {:metrics_updated, pod.id})

    assert_receive {:anomaly_status, ^pod_id, _status}, 1_000

    assert Repo.aggregate(from(a in Alert, where: a.alert_type == "baseline_anomaly"), :count) ==
             1

    refute Repo.get_by(Alert,
             alert_type: "baseline_anomaly",
             sensor_pod_id: pod.name,
             status: "resolved"
           )
  end

  test "forecast recompute fires and resolves capacity warnings" do
    pod = insert_sensor!("baseline-worker-capacity")
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    write_recent_series!(pod.id, "pcap_disk_used_percent", [80.0, 86.0, 92.0], now)
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "baselines:sensor:#{pod.id}")

    {:ok, worker} =
      start_supervised(
        {Worker, name: :baseline_worker_capacity_test, schedule?: false, subscribe?: false}
      )

    assert :ok = Worker.forecast_once(worker)

    pod_id = pod.id
    assert_receive {:forecasts_updated, ^pod_id}, 1_000
    assert %Alert{status: "firing"} = Alerts.active_alert_for("capacity_warning", pod.name)

    from(s in MetricSnapshot, where: s.sensor_pod_id == ^pod.id)
    |> Repo.delete_all()

    assert :ok = Worker.forecast_once(worker)
    assert_receive {:forecasts_updated, ^pod_id}, 1_000

    assert Repo.get_by!(Alert, alert_type: "capacity_warning", sensor_pod_id: pod.name).status ==
             "resolved"
  end

  test "recompute_once persists sensor baselines and broadcasts updates" do
    pod = insert_sensor!("baseline-worker-recompute")
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    write_series!(pod.id, "drop_percent", [1.0, 2.0, 3.0], now)
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "baselines:sensor:#{pod.id}")

    {:ok, worker} =
      start_supervised(
        {Worker, name: :baseline_worker_recompute_test, schedule?: false, subscribe?: false}
      )

    assert :ok = Worker.recompute_once(worker)

    pod_id = pod.id
    assert_receive {:baselines_updated, ^pod_id}, 1_000
    assert %HealthBaseline{mean: 2.0} = Baselines.get_baseline(pod.id, "drop_percent")
  end

  defp baseline_attrs(overrides) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    %{
      metric_type: "cpu_percent",
      series_key: "default",
      mean: 50.0,
      stddev: 2.0,
      p5: 45.0,
      p95: 55.0,
      min_value: 40.0,
      max_value: 60.0,
      sample_count: 10,
      window_start: DateTime.add(now, -3_600, :second),
      window_end: DateTime.add(now, -600, :second),
      computed_at: now
    }
    |> Map.merge(overrides)
  end

  defp write_series!(sensor_pod_id, metric_type, values, now) do
    snapshots =
      values
      |> Enum.with_index()
      |> Enum.map(fn {value, index} ->
        %{
          sensor_pod_id: sensor_pod_id,
          metric_type: metric_type,
          value: value,
          recorded_at: DateTime.add(now, -3_600 + index * 60, :second)
        }
      end)

    assert {:ok, count} = Metrics.write_snapshots(snapshots)
    assert count == length(values)
  end

  defp write_recent_series!(sensor_pod_id, metric_type, values, now) do
    snapshots =
      values
      |> Enum.with_index()
      |> Enum.map(fn {value, index} ->
        %{
          sensor_pod_id: sensor_pod_id,
          metric_type: metric_type,
          value: value,
          recorded_at: DateTime.add(now, -180 + index * 60, :second)
        }
      end)

    assert {:ok, count} = Metrics.write_snapshots(snapshots)
    assert count == length(values)
  end

  defp write_snapshot!(sensor_pod_id, metric_type, value, recorded_at) do
    write_snapshot!(sensor_pod_id, metric_type, "default", value, recorded_at)
  end

  defp write_snapshot!(sensor_pod_id, metric_type, series_key, value, recorded_at) do
    assert {:ok, 1} =
             Metrics.write_snapshots([
               %{
                 sensor_pod_id: sensor_pod_id,
                 metric_type: metric_type,
                 series_key: series_key,
                 value: value,
                 recorded_at: recorded_at
               }
             ])
  end

  defp insert_sensor!(name) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    suffix = System.unique_integer([:positive])

    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: "#{name}-#{suffix}",
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint-#{suffix}",
      enrolled_at: now,
      enrolled_by: "tester"
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(%{
      status: "enrolled",
      cert_serial: "#{name}-serial-#{suffix}",
      cert_expires_at: DateTime.add(now, 7 * 24 * 60 * 60, :second)
    })
    |> Repo.update!()
  end
end
