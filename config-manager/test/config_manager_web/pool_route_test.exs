defmodule ConfigManagerWeb.PoolRouteTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.{Auth, Pools}

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

    assert html_response(conn, 200) =~ "Create Pool"
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
    refute response =~ "Delete Pool"
  end
end
