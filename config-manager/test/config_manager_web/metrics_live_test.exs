defmodule ConfigManagerWeb.MetricsLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.{Auth, Metrics, Pools, Repo, SensorPod}
  alias ConfigManager.Metrics.MetricSnapshot

  setup do
    Repo.delete_all(MetricSnapshot)
    :ok
  end

  test "sensor metrics route renders charts, placeholders, table fallback, and nav link", %{conn: conn} do
    {viewer_conn, _viewer} = login(conn, "viewer")
    pod = insert_sensor!("metrics-live-sensor")
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    write_snapshot!(pod.id, "drop_percent", 2.5, now)

    detail =
      viewer_conn
      |> recycle()
      |> get("/sensors/#{pod.id}")
      |> html_response(200)

    assert detail =~ ~s(/sensors/#{pod.id}/metrics)
    assert detail =~ "Metrics"

    html =
      viewer_conn
      |> recycle()
      |> get("/sensors/#{pod.id}/metrics?range=1h")
      |> html_response(200)

    assert html =~ "#{pod.name} Metrics"
    assert html =~ "Drop percent"
    assert html =~ "View as table"
    assert html =~ "Data source not yet available - requires HealthReport protobuf extension for Vector records per second"
    assert html =~ "No data recorded for CPU percent in the selected time range"
    assert html =~ ~s(phx-hook="MetricsChart")
  end

  test "pool metrics route renders member data and empty pool message", %{conn: conn} do
    {viewer_conn, _viewer} = login(conn, "viewer")
    {:ok, pool} = Pools.create_pool(%{"name" => "metrics-live-pool"}, "tester")
    pod = insert_sensor!("metrics-live-pool-sensor", pool.id)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    write_snapshot!(pod.id, "clock_offset_ms", 25, now)

    pool_detail =
      viewer_conn
      |> recycle()
      |> get("/pools/#{pool.id}")
      |> html_response(200)

    assert pool_detail =~ ~s(/pools/#{pool.id}/metrics)

    html =
      viewer_conn
      |> recycle()
      |> get("/pools/#{pool.id}/metrics")
      |> html_response(200)

    assert html =~ "metrics-live-pool Metrics"
    assert html =~ "Clock offset"
    assert html =~ pod.name

    {:ok, empty_pool} = Pools.create_pool(%{"name" => "metrics-empty-pool"}, "tester")

    empty_html =
      viewer_conn
      |> recycle()
      |> get("/pools/#{empty_pool.id}/metrics")
      |> html_response(200)

    assert empty_html =~ "No sensors assigned to this pool"
  end

  test "metrics routes require authentication and handle missing records", %{conn: conn} do
    assert redirected_to(get(conn, "/sensors/#{Ecto.UUID.generate()}/metrics")) == "/login"

    {viewer_conn, _viewer} = login(conn, "viewer")

    assert viewer_conn
           |> recycle()
           |> get("/sensors/#{Ecto.UUID.generate()}/metrics")
           |> html_response(200) =~ "Sensor Not Found"

    assert viewer_conn
           |> recycle()
           |> get("/pools/#{Ecto.UUID.generate()}/metrics")
           |> html_response(200) =~ "Pool Not Found"
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
    username = "metrics-live-#{role}-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "Metrics Live User",
        role: role,
        password: password
      })

    {post(conn, "/login", %{"username" => username, "password" => password}), user}
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
end
