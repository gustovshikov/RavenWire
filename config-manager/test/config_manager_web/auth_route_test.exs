defmodule ConfigManagerWeb.AuthRouteTest do
  use ConfigManagerWeb.ConnCase, async: false
  use PropCheck

  alias ConfigManager.{AuditEntry, Auth, Forwarding, Pools, Repo, Rules, SensorPod}
  alias ConfigManager.Auth.{Policy, RateLimiter, User}

  @browser_route_permissions [
    {"/", "dashboard:view"},
    {"/pools", "sensors:view"},
    {"/enrollment", "enrollment:manage"},
    {"/pcap-config", "sensors:view"},
    {"/deployments", "sensors:view"},
    {"/rules", "sensors:view"},
    {"/support-bundle", "sensors:view"},
    {"/audit", "audit:view"},
    {"/audit/export", "audit:export"},
    {"/admin/users", "users:manage"},
    {"/admin/roles", "roles:view"},
    {"/admin/api-tokens", "tokens:manage"},
    {"/pools/new", "pools:manage"}
  ]

  @api_route_permissions [
    {:post, "/api/v1/enrollments/missing/approve", "enrollment:manage"},
    {:post, "/api/v1/enrollments/missing/deny", "enrollment:manage"},
    {:post, "/api/v1/pcap-config", "pcap:configure"},
    {:get, "/api/v1/pcap/requests", "pcap:search"},
    {:get, "/api/v1/pcap/requests/missing", "pcap:search"},
    {:get, "/api/v1/pcap/requests/missing/manifest", "pcap:search"},
    {:post, "/api/v1/pcap/carve", "pcap:search"},
    {:get, "/api/v1/pcap/requests/missing/download", "pcap:download"},
    {:post, "/api/v1/rules/deploy", "rules:deploy"},
    {:get, "/api/v1/rules", "sensors:view"},
    {:get, "/api/v1/rulesets", "sensors:view"},
    {:get, "/api/v1/repositories", "sensors:view"},
    {:post, "/api/v1/rules", "rules:manage"},
    {:post, "/api/v1/rulesets", "rules:manage"},
    {:post, "/api/v1/repositories", "rules:manage"},
    {:get, "/api/v1/deployments", "sensors:view"},
    {:get, "/api/v1/deployments/missing", "sensors:view"},
    {:post, "/api/v1/deployments", "deployments:manage"},
    {:post, "/api/v1/deployments/missing/cancel", "deployments:manage"},
    {:post, "/api/v1/deployments/missing/rollback", "deployments:manage"},
    {:post, "/api/v1/support-bundles", "bundle:download"},
    {:get, "/api/v1/audit", "audit:view"},
    {:get, "/api/v1/audit/export", "audit:export"},
    {:post, "/api/v1/admin/users", "users:manage"},
    {:post, "/api/v1/admin/api-tokens", "tokens:manage"}
  ]

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
          "/audit/export",
          "/admin/users",
          "/admin/roles",
          "/admin/api-tokens",
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

  test "viewer cannot access admin or audit export pages", %{conn: conn} do
    username = "viewer-admin-denied-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, _user} =
      Auth.create_user(%{
        username: username,
        display_name: "Viewer Admin Denied",
        role: "viewer",
        password: password
      })

    logged_in = post(conn, "/login", %{"username" => username, "password" => password})

    for {path, permission} <- [
          {"/admin/users", "users:manage"},
          {"/admin/api-tokens", "tokens:manage"},
          {"/audit/export", "audit:export"}
        ] do
      denied = logged_in |> recycle() |> get(path)
      assert response(denied, 403) =~ "Forbidden"

      audit = Repo.get_by!(AuditEntry, action: "permission_denied", target_id: path)
      assert Jason.decode!(audit.detail)["required_permission"] == permission
    end
  end

  test "dynamic browser routes redirect unauthenticated users" do
    fixtures = dynamic_route_fixtures()

    for path <-
          dynamic_read_paths(fixtures) ++ Enum.map(dynamic_manage_paths(fixtures), &elem(&1, 0)) do
      conn = build_conn() |> get(path)
      assert redirected_to(conn) == "/login", "#{path} should redirect to login"
    end
  end

  test "dynamic read routes render for authenticated users with sensors:view" do
    fixtures = dynamic_route_fixtures()
    logged_in = login_as(build_conn(), "viewer") |> elem(0)

    for path <- dynamic_read_paths(fixtures) do
      conn = logged_in |> recycle() |> get(path)
      assert html_response(conn, 200), "#{path} should render for a viewer"
    end
  end

  test "dynamic management routes enforce their required permissions" do
    fixtures = dynamic_route_fixtures()
    {viewer_conn, viewer} = login_as(build_conn(), "viewer")
    {operator_conn, _operator} = login_as(build_conn(), "sensor-operator")

    for {path, permission} <- dynamic_manage_paths(fixtures) do
      denied = viewer_conn |> recycle() |> get(path)
      assert response(denied, 403) =~ "Forbidden"

      audit = latest_permission_denial(viewer.username, path)
      assert audit.actor_type == "user"
      assert Jason.decode!(audit.detail)["required_permission"] == permission

      allowed = operator_conn |> recycle() |> get(path)
      assert html_response(allowed, 200), "#{path} should render for a sensor operator"
    end
  end

  test "public API routes require bearer tokens" do
    for {method, path, _permission} <- @api_route_permissions do
      conn = request_api(build_conn(), method, path)

      assert conn.status == 401, "#{method} #{path} should require a bearer token"
      assert json_response(conn, 401)["error"]["code"] == "UNAUTHORIZED"
    end
  end

  test "public API routes reject tokens without the required scope" do
    {raw_token, token_name} = create_api_token!(["dashboard:view"])

    for {method, path, permission} <- @api_route_permissions do
      conn =
        build_conn()
        |> bearer(raw_token)
        |> request_api(method, path)

      assert conn.status == 403, "#{method} #{path} should require #{permission}"
      assert json_response(conn, 403)["error"]["code"] == "FORBIDDEN"

      audit = latest_permission_denial(token_name, path)
      assert audit.actor_type == "api_token"
      assert Jason.decode!(audit.detail)["required_permission"] == permission
    end
  end

  test "public API routes with matching token scopes pass authentication and RBAC" do
    for {method, path, permission} <- @api_route_permissions do
      {raw_token, _token_name} = create_api_token!([permission])

      conn =
        build_conn()
        |> bearer(raw_token)
        |> request_api(method, path)

      refute conn.status in [401, 403],
             "#{method} #{path} should pass token auth and #{permission} RBAC, got #{conn.status}"
    end
  end

  property "Property 6: Browser route RBAC matches the policy table",
           [:verbose, numtests: 60] do
    forall code <- integer(0, 20_000) do
      roles = Policy.roles()

      {path, permission} =
        Enum.at(@browser_route_permissions, rem(code, length(@browser_route_permissions)))

      role = Enum.at(roles, rem(div(code, length(@browser_route_permissions)), length(roles)))
      {conn, user} = login_as(build_conn(), role)

      response_conn =
        conn
        |> recycle()
        |> get(path)

      if Policy.has_permission?(role, permission) do
        response_conn.status == 200
      else
        denied_audit =
          Repo.get_by(AuditEntry,
            actor: user.username,
            action: "permission_denied",
            target_id: path
          )

        response_conn.status == 403 and
          not is_nil(denied_audit) and
          Jason.decode!(denied_audit.detail)["required_permission"] == permission
      end
    end
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

  defp login_as(conn, role) do
    username = "rbac-route-#{role}-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "RBAC Route User",
        role: role,
        password: password
      })

    {post(conn, "/login", %{"username" => username, "password" => password}), user}
  end

  defp dynamic_route_fixtures do
    suffix = System.unique_integer([:positive])
    {:ok, pool} = Pools.create_pool(%{"name" => "dynamic-route-pool-#{suffix}"}, "tester")
    sensor = insert_sensor!(pool.id, suffix)
    {:ok, ruleset} = Rules.create_ruleset(%{name: "dynamic-route-ruleset-#{suffix}"}, "tester")

    {:ok, sink} =
      Forwarding.create_sink(
        pool.id,
        %{
          "name" => "dynamic-route-sink-#{suffix}",
          "sink_type" => "file",
          "path_template" => "/var/log/ravenwire/events.ndjson",
          "encoding" => "ndjson"
        },
        "tester"
      )

    %{
      pool: pool,
      sensor: sensor,
      ruleset: ruleset,
      sink: sink,
      missing_deployment_id: Ecto.UUID.generate()
    }
  end

  defp dynamic_read_paths(%{
         pool: pool,
         sensor: sensor,
         ruleset: ruleset,
         missing_deployment_id: deployment_id
       }) do
    [
      "/pools/#{pool.id}",
      "/pools/#{pool.id}/sensors",
      "/pools/#{pool.id}/config",
      "/pools/#{pool.id}/forwarding",
      "/pools/#{pool.id}/bpf",
      "/pools/#{pool.id}/deployments",
      "/pools/#{pool.id}/drift",
      "/deployments/#{deployment_id}",
      "/rules/store",
      "/rules/categories",
      "/rules/repositories",
      "/rules/rulesets",
      "/rules/rulesets/new",
      "/rules/rulesets/#{ruleset.id}",
      "/rules/rulesets/#{ruleset.id}/edit",
      "/rules/deployments",
      "/sensors/#{sensor.id}"
    ]
  end

  defp dynamic_manage_paths(%{pool: pool, sink: sink}) do
    [
      {"/pools/#{pool.id}/edit", "pools:manage"},
      {"/pools/#{pool.id}/forwarding/sinks/new", "forwarding:manage"},
      {"/pools/#{pool.id}/forwarding/sinks/#{sink.id}/edit", "forwarding:manage"}
    ]
  end

  defp insert_sensor!(pool_id, suffix) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: "dynamic-route-sensor-#{suffix}",
      public_key_pem: "public-key",
      key_fingerprint: "fingerprint",
      enrolled_at: now,
      enrolled_by: "tester",
      control_api_host: "127.0.0.1"
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(%{
      status: "enrolled",
      cert_serial: "DYNAMIC#{suffix}",
      cert_expires_at: DateTime.add(now, 24, :hour),
      pool_id: pool_id
    })
    |> Repo.update!()
  end

  defp create_api_token!(permissions) do
    username = "api-route-user-#{System.unique_integer([:positive])}"
    token_name = "api-route-token-#{System.unique_integer([:positive])}"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "API Route User",
        role: "platform-admin",
        password: "long-enough-password"
      })

    {:ok, _token, raw_token} =
      Auth.create_api_token(user, %{name: token_name, permissions: permissions}, user)

    {raw_token, token_name}
  end

  defp bearer(conn, raw_token) do
    put_req_header(conn, "authorization", "Bearer #{raw_token}")
  end

  defp request_api(conn, :get, path) do
    conn
    |> put_req_header("accept", "application/json")
    |> get(path)
  end

  defp request_api(conn, :post, path) do
    conn
    |> put_req_header("accept", "application/json")
    |> post(path, %{})
  end

  defp latest_permission_denial(actor, path) do
    import Ecto.Query

    Repo.one!(
      from(a in AuditEntry,
        where: a.actor == ^actor and a.action == "permission_denied" and a.target_id == ^path,
        order_by: [desc: a.timestamp],
        limit: 1
      )
    )
  end
end
