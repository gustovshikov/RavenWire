defmodule ConfigManager.Baselines.ContextTest do
  use ConfigManager.DataCase, async: false
  use PropCheck

  alias ConfigManager.Baselines
  alias ConfigManager.Baselines.HealthBaseline
  alias ConfigManager.Metrics
  alias ConfigManager.Metrics.MetricSnapshot
  alias ConfigManager.{Pools, Repo, SensorPod}

  setup do
    Repo.delete_all(HealthBaseline)
    Repo.delete_all(MetricSnapshot)
    :ok
  end

  test "health baseline changeset validates metric scope, type, series key, and sample count" do
    pod = insert_sensor!("baseline-context-validation")
    {:ok, pool} = Pools.create_pool(%{"name" => "baseline-context-validation-pool"}, "tester")
    attrs = baseline_attrs(%{sensor_pod_id: pod.id})

    assert HealthBaseline.changeset(%HealthBaseline{}, attrs).valid?

    missing_scope =
      attrs
      |> Map.delete(:sensor_pod_id)
      |> then(&HealthBaseline.changeset(%HealthBaseline{}, &1))

    refute missing_scope.valid?
    assert %{sensor_pod_id: [_]} = errors_on(missing_scope)

    both_scopes =
      attrs
      |> Map.put(:pool_id, pool.id)
      |> then(&HealthBaseline.changeset(%HealthBaseline{}, &1))

    refute both_scopes.valid?
    assert %{pool_id: [_]} = errors_on(both_scopes)

    invalid =
      attrs
      |> Map.merge(%{metric_type: "unknown", series_key: "bad key", sample_count: 0})
      |> then(&HealthBaseline.changeset(%HealthBaseline{}, &1))

    refute invalid.valid?
    assert %{metric_type: [_], series_key: [_], sample_count: [_]} = errors_on(invalid)
  end

  test "upsert, sensor listing, and cascade cleanup work" do
    pod = insert_sensor!("baseline-context-upsert")

    assert {:ok, baseline} =
             Baselines.upsert_baseline(baseline_attrs(%{sensor_pod_id: pod.id, mean: 10.0}))

    assert Baselines.get_baseline(pod.id, "cpu_percent").mean == 10.0

    assert {:ok, updated} =
             Baselines.upsert_baseline(baseline_attrs(%{sensor_pod_id: pod.id, mean: 15.0}))

    assert updated.id == baseline.id
    assert Baselines.list_baselines_for_sensor(pod.id) |> Enum.map(& &1.mean) == [15.0]

    assert {1, nil} = Baselines.delete_baselines_for_sensor(pod.id)
    assert Baselines.list_baselines_for_sensor(pod.id) == []
  end

  test "compute sensor and pool baselines from historical snapshots" do
    {:ok, pool} = Pools.create_pool(%{"name" => "baseline-context-pool"}, "tester")
    first = insert_sensor!("baseline-context-pool-first", pool.id)
    second = insert_sensor!("baseline-context-pool-second", pool.id)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    write_series!(first.id, "drop_percent", [1.0, 2.0, 3.0], now)
    write_series!(second.id, "drop_percent", [2.0, 3.0, 4.0], now)

    assert {:ok, sensor_profile} =
             Baselines.compute_sensor_baseline(first.id, "drop_percent", "default",
               now: now,
               min_samples: 3
             )

    assert sensor_profile.sample_count == 3
    assert sensor_profile.mean == 2.0

    assert {:ok, pool_profile} =
             Baselines.compute_pool_baseline(pool.id, "drop_percent", "default",
               now: now,
               min_samples: 3
             )

    assert pool_profile.sample_count == 6
    assert_in_delta pool_profile.mean, 2.5, 0.001
  end

  test "anomaly and capacity forecast helpers classify current values" do
    pod = insert_sensor!("baseline-context-anomaly")
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    {:ok, baseline} =
      Baselines.upsert_baseline(
        baseline_attrs(%{sensor_pod_id: pod.id, mean: 50.0, stddev: 2.0, p5: 45.0, p95: 55.0})
      )

    assert :normal = Baselines.evaluate_anomaly(52.0, baseline)
    assert {:anomaly, score, details} = Baselines.evaluate_anomaly(70.0, baseline)
    assert score == 10.0
    assert details.metric_type == "cpu_percent"

    write_recent_series!(pod.id, "pcap_disk_used_percent", [80.0, 82.0, 84.0], now)

    assert {:ok, forecast} =
             Baselines.compute_forecast(pod.id, "pcap_disk_used_percent", "default",
               now: now,
               min_samples: 3
             )

    assert forecast.projected_value > forecast.threshold
    assert forecast.breach_at
  end

  property "pool outlier identification matches sensors outside two sigma", [
    :verbose,
    numtests: 80
  ] do
    forall offset <- integer(-5, 5) do
      baseline = %{
        metric_type: "cpu_percent",
        mean: 50.0,
        stddev: 1.0,
        p5: 48.0,
        p95: 52.0
      }

      value = 50.0 + offset
      outliers = Baselines.outliers_from_pool_baseline(baseline, [{"sensor", value}], 2.0)
      expected? = abs(offset) > 2
      outliers != [] == expected?
    end
  end

  defp baseline_attrs(overrides) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    %{
      metric_type: "cpu_percent",
      series_key: "default",
      mean: 50.0,
      stddev: 5.0,
      p5: 40.0,
      p95: 60.0,
      min_value: 35.0,
      max_value: 65.0,
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

  defp insert_sensor!(name, pool_id \\ nil) do
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
      cert_expires_at: DateTime.add(now, 7 * 24 * 60 * 60, :second),
      pool_id: pool_id
    })
    |> Repo.update!()
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
