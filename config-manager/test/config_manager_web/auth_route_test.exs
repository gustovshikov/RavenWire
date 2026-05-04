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
    assert html_response(conn, 200) =~ "Sensors"
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

  test "audit page renders user display names for user actors and targets", %{conn: conn} do
    username = "AuditUser#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "Audit User",
        role: "platform-admin",
        password: password
      })

    conn = post(conn, "/login", %{"username" => username, "password" => password})
    session_token = get_session(conn, :session_token)

    conn =
      conn
      |> recycle()
      |> Plug.Test.init_test_session(session_token: session_token)
      |> get("/audit")

    response = html_response(conn, 200)

    assert response =~ "Audit User (#{user.username})"
    refute response =~ "user:#{user.id}"
  end
end
