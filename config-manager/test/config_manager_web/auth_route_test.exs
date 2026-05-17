defmodule ConfigManagerWeb.AuthRouteTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.{AuditEntry, Auth, Repo}
  alias ConfigManager.Auth.{RateLimiter, User}

  setup do
    previous_ip_limit = System.get_env("RAVENWIRE_LOGIN_IP_FAILURE_LIMIT")
    RateLimiter.reset()

    on_exit(fn ->
      RateLimiter.reset()
      restore_env("RAVENWIRE_LOGIN_IP_FAILURE_LIMIT", previous_ip_limit)
    end)

    :ok
  end

  test "protected pages redirect unauthenticated users to login" do
    for path <- [
          "/",
          "/enrollment",
          "/pcap-config",
          "/rules",
          "/support-bundle",
          "/audit",
          "/pools",
          "/pools/new"
        ] do
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

  test "login failures are indistinguishable for missing, bad, disabled, and rate-limited users",
       %{
         conn: conn
       } do
    password = "long-enough-password"

    {:ok, active_user} =
      Auth.create_user(%{
        username: "active-login-#{System.unique_integer([:positive])}",
        display_name: "Active Login",
        role: "viewer",
        password: password
      })

    {:ok, disabled_user} =
      Auth.create_user(%{
        username: "disabled-login-#{System.unique_integer([:positive])}",
        display_name: "Disabled Login",
        role: "viewer",
        active: false,
        password: password
      })

    System.put_env("RAVENWIRE_LOGIN_IP_FAILURE_LIMIT", "2")

    Enum.each(["missing-login-user", active_user.username, disabled_user.username], fn username ->
      response =
        conn
        |> recycle()
        |> post("/login", %{"username" => username, "password" => "wrong-password"})
        |> html_response(200)

      assert response =~ "Invalid username or password"
      refute response =~ "disabled"
      refute response =~ "rate"
    end)

    for username <- ["ip-rate-1", "ip-rate-2"] do
      conn
      |> recycle()
      |> Map.put(:remote_ip, {10, 0, 0, 7})
      |> post("/login", %{"username" => username, "password" => "wrong-password"})
    end

    response =
      conn
      |> recycle()
      |> Map.put(:remote_ip, {10, 0, 0, 7})
      |> post("/login", %{"username" => "ip-rate-3", "password" => "wrong-password"})
      |> html_response(200)

    assert response =~ "Invalid username or password"
    refute response =~ "rate"
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

    audit = Repo.get_by!(AuditEntry, action: "permission_denied", target_id: "/enrollment")
    assert audit.actor == username
    assert audit.actor_type == "user"
    assert Jason.decode!(audit.detail)["required_permission"] == "enrollment:manage"
  end

  test "forced password change redirects after login and blocks other routes", %{conn: conn} do
    username = "forced-password-#{System.unique_integer([:positive])}"
    old_password = "old-password-long"
    new_password = "new-password-long"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "Forced Password",
        role: "platform-admin",
        must_change_password: true,
        password: old_password
      })

    conn = post(conn, "/login", %{"username" => username, "password" => old_password})
    assert redirected_to(conn) == "/password/change"

    conn = get(recycle(conn), "/")
    assert redirected_to(conn) == "/password/change"

    conn = get(recycle(conn), "/password/change")
    assert html_response(conn, 200) =~ "Change Password"

    conn =
      post(recycle(conn), "/password/change", %{
        "current_password" => old_password,
        "password" => new_password
      })

    assert redirected_to(conn) == "/"
    refute Repo.get!(User, user.id).must_change_password

    conn = get(recycle(conn), "/")
    assert html_response(conn, 200) =~ "Sensors"
  end

  test "forced password change allows logout and rejects bad current password", %{conn: conn} do
    username = "forced-password-logout-#{System.unique_integer([:positive])}"
    password = "old-password-long"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "Forced Password Logout",
        role: "platform-admin",
        must_change_password: true,
        password: password
      })

    conn = post(conn, "/login", %{"username" => username, "password" => password})

    bad_change =
      post(recycle(conn), "/password/change", %{
        "current_password" => "wrong-password",
        "password" => "new-password-long"
      })

    assert html_response(bad_change, 200) =~ "Current password is incorrect"
    assert Repo.get!(User, user.id).must_change_password

    logout = post(recycle(conn), "/logout")
    assert redirected_to(logout) == "/login"
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

  defp restore_env(key, nil), do: System.delete_env(key)
  defp restore_env(key, value), do: System.put_env(key, value)
end
