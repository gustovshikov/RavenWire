defmodule ConfigManagerWeb.AuthRouteTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.Auth

  test "protected pages redirect unauthenticated users to login" do
    for path <- ["/", "/enrollment", "/pcap-config", "/rules", "/support-bundle", "/audit"] do
      conn = build_conn() |> get(path)
      assert redirected_to(conn) == "/login"
      assert html_response(conn, 302) =~ "redirected"
    end
  end

  test "valid credentials create a session and reach dashboard", %{conn: conn} do
    username = "route-user-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, _user} =
      Auth.create_user(%{
        username: username,
        display_name: "Route User",
        role: "platform-admin",
        password: password
      })

    conn =
      post(conn, "/login", %{
        "username" => username,
        "password" => password
      })

    assert redirected_to(conn) == "/"
    assert get_session(conn, :session_token)

    conn = get(recycle(conn), "/")
    assert html_response(conn, 200) =~ "RavenWire Sensor Health"
  end

  test "insufficient role receives forbidden response", %{conn: conn} do
    username = "viewer-user-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, _user} =
      Auth.create_user(%{
        username: username,
        display_name: "Viewer User",
        role: "viewer",
        password: password
      })

    conn =
      conn
      |> post("/login", %{"username" => username, "password" => password})
      |> recycle()
      |> get("/enrollment")

    assert response(conn, 403) =~ "Forbidden"
  end
end
