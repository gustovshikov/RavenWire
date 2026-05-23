defmodule ConfigManagerWeb.PoolRouteTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.{Auth, Bpf, Forwarding, Pools}

  defp login(conn, role) do
    username = "pool-route-#{role}-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, _user} =
      Auth.create_user(%{
        username: username,
        display_name: "Pool Route User",
        role: role,
        password: password
      })

    post(conn, "/login", %{"username" => username, "password" => password})
  end

  test "pool list is available to read-only users", %{conn: conn} do
    conn =
      conn
      |> login("viewer")
      |> recycle()
      |> get("/pools")

    assert html_response(conn, 200) =~ "Sensor Pools"
  end

  test "pool creation route requires pools:manage", %{conn: conn} do
    conn =
      conn
      |> login("viewer")
      |> recycle()
      |> get("/pools/new")

    assert response(conn, 403) =~ "Forbidden"
  end

  test "platform admin can access pool creation form", %{conn: conn} do
    conn =
      conn
      |> login("platform-admin")
      |> recycle()
      |> get("/pools/new")

    response = html_response(conn, 200)
    assert response =~ "Create Pool"
    assert response =~ ~s(src="/assets/phoenix.min.js")
    assert response =~ ~s(src="/assets/phoenix_live_view.min.js")
    assert response =~ ~s(src="/assets/app.js")
  end

  test "pool detail pages render created pool", %{conn: conn} do
    {:ok, pool} = Pools.create_pool(%{"name" => "route-pool"}, "tester")

    conn =
      conn
      |> login("viewer")
      |> recycle()
      |> get("/pools/#{pool.id}")

    response = html_response(conn, 200)
    assert response =~ "route-pool"
    assert response =~ "Pool Overview"
    assert response =~ "Forwarding"
    assert response =~ "BPF Filters"
    assert response =~ "BPF Profile"
    refute response =~ "Delete Pool"
  end

  test "forwarding overview is visible to read-only pool users", %{conn: conn} do
    {:ok, pool} = Pools.create_pool(%{"name" => "route-forwarding-pool"}, "tester")

    conn =
      conn
      |> login("viewer")
      |> recycle()
      |> get("/pools/#{pool.id}/forwarding")

    response = html_response(conn, 200)
    assert response =~ "route-forwarding-pool Forwarding"
    assert response =~ "No forwarding sinks configured"
    refute response =~ "Add Sink"
  end

  test "forwarding sink form routes require forwarding management permission", %{conn: conn} do
    {:ok, pool} = Pools.create_pool(%{"name" => "route-forwarding-manage"}, "tester")

    viewer_conn =
      conn
      |> login("viewer")
      |> recycle()
      |> get("/pools/#{pool.id}/forwarding/sinks/new")

    assert response(viewer_conn, 403) =~ "Forbidden"

    operator_conn =
      Phoenix.ConnTest.build_conn()
      |> login("sensor-operator")
      |> recycle()
      |> get("/pools/#{pool.id}/forwarding/sinks/new")

    response = html_response(operator_conn, 200)
    assert response =~ "Add Forwarding Sink"
    assert response =~ "Path Template"
  end

  test "forwarding edit route enforces pool ownership and renders sink", %{conn: conn} do
    {:ok, pool} = Pools.create_pool(%{"name" => "route-forwarding-edit"}, "tester")
    {:ok, other_pool} = Pools.create_pool(%{"name" => "route-forwarding-other"}, "tester")

    {:ok, sink} =
      Forwarding.create_sink(
        pool.id,
        %{
          "name" => "route-file",
          "sink_type" => "file",
          "path_template" => "/var/log/ravenwire/events.ndjson",
          "encoding" => "ndjson"
        },
        "tester"
      )

    conn =
      conn
      |> login("sensor-operator")
      |> recycle()
      |> get("/pools/#{pool.id}/forwarding/sinks/#{sink.id}/edit")

    response = html_response(conn, 200)
    assert response =~ "Edit Forwarding Sink"
    assert response =~ "route-file"

    conn =
      Phoenix.ConnTest.build_conn()
      |> login("sensor-operator")
      |> recycle()
      |> get("/pools/#{other_pool.id}/forwarding/sinks/#{sink.id}/edit")

    assert html_response(conn, 200) =~ "Sink Not Found"
  end

  test "pool detail displays BPF summary and pending deployment badge", %{conn: conn} do
    {:ok, pool} = Pools.create_pool(%{"name" => "route-bpf-pool"}, "tester")
    {:ok, profile} = Bpf.create_profile(pool.id, "tester")

    {:ok, _updated} =
      Bpf.save_profile(
        profile,
        %{
          rules: [%{rule_type: "port_exclusion", params: %{"port" => 443}, position: 0}],
          raw_expression: nil,
          composition_mode: "append"
        },
        "tester",
        compiler: fn _expression -> {:ok, %{instruction_count: 1}} end
      )

    conn =
      conn
      |> login("viewer")
      |> recycle()
      |> get("/pools/#{pool.id}")

    response = html_response(conn, 200)
    assert response =~ "BPF Filters"
    assert response =~ "pending"
    assert response =~ "Pending deployment"
    assert response =~ "BPF Enabled Rules"
  end
end
