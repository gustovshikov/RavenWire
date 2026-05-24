defmodule ConfigManagerWeb.BaselinesLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.Baselines
  alias ConfigManager.Baselines.HealthBaseline
  alias ConfigManager.Metrics
  alias ConfigManager.Metrics.MetricSnapshot
  alias ConfigManager.{Auth, Pools, Repo, SensorPod}

  setup do
    Repo.delete_all(HealthBaseline)
    Repo.delete_all(MetricSnapshot)
    :ok
  end

  test "sensor baselines route renders baseline status, forecast placeholder, and nav link", %{
    conn: conn
  } do
    {viewer_conn, _viewer} = login(conn, "viewer")
    pod = insert_sensor!("baselines-live-sensor")
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    write_snapshot!(pod.id, "cpu_percent", 52.0, now)
    {:ok, _baseline} = Baselines.upsert_baseline(baseline_attrs(%{sensor_pod_id: pod.id}))

    detail =
      viewer_conn
      |> recycle()
      |> get("/sensors/#{pod.id}")
      |> html_response(200)

    assert detail =~ ~s(/sensors/#{pod.id}/baselines)
    assert detail =~ "Baselines"

    html =
      viewer_conn
      |> recycle()
      |> get("/sensors/#{pod.id}/baselines")
      |> html_response(200)

    assert html =~ "#{pod.name} Baselines"
    assert html =~ "CPU percent"
    assert html =~ "Current value is within the learned baseline."
    assert html =~ "Insufficient data for forecast."
    assert html =~ "Baseline not available. Insufficient data for baseline."
  end

  test "pool baselines route renders comparison table and empty pool state", %{conn: conn} do
    {viewer_conn, _viewer} = login(conn, "viewer")
    {:ok, pool} = Pools.create_pool(%{"name" => "baselines-live-pool"}, "tester")
    first = insert_sensor!("baselines-live-pool-first", pool.id)
    second = insert_sensor!("baselines-live-pool-second", pool.id)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    write_snapshot!(first.id, "drop_percent", 1.0, now)
    write_snapshot!(second.id, "drop_percent", 7.0, now)

    {:ok, _baseline} =
      Baselines.upsert_baseline(
        baseline_attrs(%{
          pool_id: pool.id,
          metric_type: "drop_percent",
          mean: 2.0,
          stddev: 1.0,
          p5: 0.0,
          p95: 4.0
        })
      )

    pool_detail =
      viewer_conn
      |> recycle()
      |> get("/pools/#{pool.id}")
      |> html_response(200)

    assert pool_detail =~ ~s(/pools/#{pool.id}/baselines)

    html =
      viewer_conn
      |> recycle()
      |> get("/pools/#{pool.id}/baselines")
      |> html_response(200)

    assert html =~ "baselines-live-pool Baselines"
    assert html =~ "Pool-level baselines and sensor outlier comparison."
    assert html =~ "Drop percent"
    assert html =~ first.name
    assert html =~ second.name
    assert html =~ "Outlier"

    {:ok, empty_pool} = Pools.create_pool(%{"name" => "baselines-empty-pool"}, "tester")

    empty_html =
      viewer_conn
      |> recycle()
      |> get("/pools/#{empty_pool.id}/baselines")
      |> html_response(200)

    assert empty_html =~ "No sensors assigned to this pool."
  end

  test "baselines routes require authentication and handle missing records", %{conn: conn} do
    assert redirected_to(get(conn, "/sensors/#{Ecto.UUID.generate()}/baselines")) == "/login"
    assert redirected_to(get(conn, "/pools/#{Ecto.UUID.generate()}/baselines")) == "/login"

    {viewer_conn, _viewer} = login(conn, "viewer")

    assert viewer_conn
           |> recycle()
           |> get("/sensors/#{Ecto.UUID.generate()}/baselines")
           |> html_response(200) =~ "Sensor Not Found"

    assert viewer_conn
           |> recycle()
           |> get("/pools/#{Ecto.UUID.generate()}/baselines")
           |> html_response(200) =~ "Pool Not Found"
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
      sample_count: 12,
      window_start: DateTime.add(now, -3_600, :second),
      window_end: DateTime.add(now, -600, :second),
      computed_at: now
    }
    |> Map.merge(overrides)
  end

  defp write_snapshot!(sensor_pod_id, metric_type, value, recorded_at) do
    assert {:ok, 1} =
             Metrics.write_snapshots([
               %{
                 sensor_pod_id: sensor_pod_id,
                 metric_type: metric_type,
                 value: value,
                 recorded_at: recorded_at
               }
             ])
  end

  defp login(conn, role) do
    username = "baselines-live-#{role}-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "Baselines Live User",
        role: role,
        password: password
      })

    {post(conn, "/login", %{"username" => username, "password" => password}), user}
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
end
