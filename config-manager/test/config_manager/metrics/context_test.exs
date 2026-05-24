defmodule ConfigManager.Metrics.ContextTest do
  use ConfigManager.DataCase, async: false
  use PropCheck

  alias ConfigManager.Metrics
  alias ConfigManager.Metrics.MetricSnapshot
  alias ConfigManager.{Pools, Repo, SensorPod}

  setup do
    Repo.delete_all(MetricSnapshot)
    :ok
  end

  test "metric snapshot changeset validates metric type, series key, finite value, and metadata" do
    pod = insert_sensor!("metrics-context-validation")
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    valid =
      MetricSnapshot.changeset(%MetricSnapshot{}, %{
        sensor_pod_id: pod.id,
        metric_type: "drop_percent",
        series_key: "default",
        value: 1.5,
        recorded_at: now,
        metadata: %{"source" => "test"}
      })

    assert valid.valid?

    invalid =
      MetricSnapshot.changeset(%MetricSnapshot{}, %{
        sensor_pod_id: pod.id,
        metric_type: "unknown",
        series_key: "bad key",
        value: "nan",
        recorded_at: now,
        metadata: "[]"
      })

    refute invalid.valid?
    assert %{metric_type: [_], series_key: [_], value: [_], metadata: [_]} = errors_on(invalid)
  end

  test "write_snapshots de-duplicates and query helpers return bounded ordered data" do
    pod = insert_sensor!("metrics-context-query")
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    snapshot = %{
      sensor_pod_id: pod.id,
      metric_type: "drop_percent",
      value: 4.5,
      recorded_at: DateTime.add(now, -60, :second),
      metadata: %{"source" => "test"}
    }

    assert {:ok, 1} = Metrics.write_snapshots([snapshot, snapshot])
    assert {:ok, [stored]} = Metrics.list_snapshots(pod.id, "drop_percent", "1h", now: now)
    assert stored.value == 4.5
    assert stored.series_key == "default"
    assert Metrics.available_metric_types(pod.id) == ["drop_percent"]
    assert Metrics.latest_snapshot(pod.id, "drop_percent").id == stored.id
  end

  test "pool queries only include member sensors and sensor delete cascades snapshots" do
    {:ok, pool} = Pools.create_pool(%{"name" => "metrics-context-pool"}, "tester")
    member = insert_sensor!("metrics-context-member", pool.id)
    non_member = insert_sensor!("metrics-context-non-member")
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    assert {:ok, 2} =
             Metrics.write_snapshots([
               %{sensor_pod_id: member.id, metric_type: "clock_offset_ms", value: 10, recorded_at: now},
               %{sensor_pod_id: non_member.id, metric_type: "clock_offset_ms", value: 20, recorded_at: now}
             ])

    assert {:ok, %{snapshots: snapshots}} =
             Metrics.list_snapshots_for_pool(pool.id, "clock_offset_ms", "1h", now: now)

    assert Map.keys(snapshots) == [{member.id, "default"}]

    Repo.delete!(member)
    assert Repo.aggregate(MetricSnapshot, :count, :id) == 1
  end

  test "prune_before deletes expired rows in batches" do
    pod = insert_sensor!("metrics-context-prune")
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    old = DateTime.add(now, -4 * 60 * 60, :second)
    fresh = DateTime.add(now, -60, :second)

    assert {:ok, 2} =
             Metrics.write_snapshots([
               %{sensor_pod_id: pod.id, metric_type: "cpu_percent", series_key: "container:zeek", value: 50, recorded_at: old},
               %{sensor_pod_id: pod.id, metric_type: "cpu_percent", series_key: "container:zeek", value: 55, recorded_at: fresh}
             ])

    assert {:ok, 1} = Metrics.prune_before(DateTime.add(now, -2 * 60 * 60, :second), 1)
    assert Repo.aggregate(MetricSnapshot, :count, :id) == 1
  end

  property "time range parsing only accepts bounded supported ranges", [:verbose, numtests: 60] do
    forall code <- integer(0, 10_000) do
      candidates = ["1h", "6h", "24h", "72h", "", "all", "100d", "../"]
      value = Enum.at(candidates, rem(code, length(candidates)))

      case Metrics.parse_time_range(value) do
        {:ok, {start_at, end_at}} ->
          value in Metrics.valid_time_ranges() and DateTime.compare(start_at, end_at) == :lt

        {:error, :invalid_range} ->
          value not in Metrics.valid_time_ranges()
      end
    end
  end

  defp insert_sensor!(name, pool_id \\ nil) do
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
