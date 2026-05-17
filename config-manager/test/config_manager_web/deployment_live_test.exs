defmodule ConfigManagerWeb.DeploymentLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.{Auth, Deployments, Pools, Repo, SensorPod}
  alias ConfigManager.Deployments.Deployment

  defp create_user(role) do
    username = "deployment-live-#{role}-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "Deployment Live User",
        role: role,
        password: password
      })

    {user, password}
  end

  defp login(conn, role) do
    {user, password} = create_user(role)
    post(conn, "/login", %{"username" => user.username, "password" => password})
  end

  test "fleet deployment list and detail render deployment state", %{conn: conn} do
    {:ok, pool} = Pools.create_pool(%{"name" => "deployment-live-pool"}, "tester")
    sensor = insert_sensor!("deployment-live-sensor", pool.id, control_api_host: "127.0.0.1")

    {:ok, deployment} =
      Deployments.create_deployment(pool, "tester", start_orchestrator?: false)

    logged_conn = login(conn, "viewer")

    list_response =
      logged_conn
      |> recycle()
      |> get("/deployments")
      |> html_response(200)

    assert list_response =~ "Deployments"
    assert list_response =~ pool.name
    assert list_response =~ "Pending"
    refute list_response =~ "New Deployment"

    detail_response =
      logged_conn
      |> recycle()
      |> get("/deployments/#{deployment.id}")
      |> html_response(200)

    assert detail_response =~ "Sensor Results"
    assert detail_response =~ sensor.name
    assert detail_response =~ "Configuration Snapshot"
  end

  test "operators with deployment permission see deployment creation entry points", %{conn: conn} do
    response =
      conn
      |> login("sensor-operator")
      |> recycle()
      |> get("/deployments")
      |> html_response(200)

    assert response =~ "New Deployment"
  end

  test "pool deployment and drift pages render pool-scoped state", %{conn: conn} do
    {:ok, pool} = Pools.create_pool(%{"name" => "pool-deployments-live"}, "tester")

    sensor =
      insert_sensor!("pool-deployment-drift-sensor", pool.id, control_api_host: "127.0.0.1")

    {:ok, deployment} = Deployments.create_deployment(pool, "tester", start_orchestrator?: false)
    logged_conn = login(conn, "viewer")

    deployments_response =
      logged_conn
      |> recycle()
      |> get("/pools/#{pool.id}/deployments")
      |> html_response(200)

    assert deployments_response =~ "#{pool.name} Deployments"
    assert deployments_response =~ String.slice(deployment.id, 0, 8)
    refute deployments_response =~ "Deploy Now"

    drift_response =
      logged_conn
      |> recycle()
      |> get("/pools/#{pool.id}/drift")
      |> html_response(200)

    assert drift_response =~ "#{pool.name} Drift"
    assert drift_response =~ sensor.name
    assert drift_response =~ "Never Deployed"
  end

  test "sensor detail shows deployment drift state", %{conn: conn} do
    {:ok, pool} = Pools.create_pool(%{"name" => "sensor-deployment-state-pool"}, "tester")
    sensor = insert_sensor!("sensor-deployment-state", pool.id, control_api_host: "127.0.0.1")

    response =
      conn
      |> login("viewer")
      |> recycle()
      |> get("/sensors/#{sensor.id}")
      |> html_response(200)

    assert response =~ "Deployment State"
    assert response =~ "Never Deployed"
  end

  test "read-only user is denied server-side deployment cancellation" do
    {:ok, pool} = Pools.create_pool(%{"name" => "readonly-cancel-pool"}, "tester")
    insert_sensor!("readonly-cancel-sensor", pool.id, control_api_host: "127.0.0.1")
    {:ok, deployment} = Deployments.create_deployment(pool, "tester", start_orchestrator?: false)
    {viewer, _password} = create_user("viewer")

    socket = build_detail_socket(deployment, viewer)

    assert {:noreply, denied} =
             ConfigManagerWeb.DeploymentLive.DetailLive.handle_event("cancel", %{}, socket)

    assert denied.assigns.flash["error"] == "Insufficient permissions."
    assert Repo.get!(Deployment, deployment.id).status == "pending"
  end

  defp build_detail_socket(deployment, user) do
    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        current_user: user,
        deployment: deployment
      },
      private: %{live_temp: %{}}
    }
  end

  defp insert_sensor!(name, pool_id, opts) do
    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint",
      enrolled_at: DateTime.utc_now() |> DateTime.truncate(:second),
      enrolled_by: "tester",
      control_api_host: Keyword.get(opts, :control_api_host)
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(status: "enrolled", pool_id: pool_id)
    |> Repo.update!()
  end
end
