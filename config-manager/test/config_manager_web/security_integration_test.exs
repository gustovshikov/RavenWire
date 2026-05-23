defmodule ConfigManagerWeb.SecurityIntegrationTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.{AuditEntry, Auth, Repo}
  alias ConfigManager.Auth.ApiToken

  test "login sets secure cookie attributes and renews the session token", %{conn: conn} do
    username = unique_username("cookie-user")
    password = "long-enough-password"
    fixed_token = "attacker-fixed-session-token"

    {:ok, _user} = create_user(username, password: password)

    conn =
      conn
      |> Plug.Test.init_test_session(session_token: fixed_token)
      |> post("/login", %{"username" => username, "password" => password})

    assert redirected_to(conn) == "/"

    session_token = get_session(conn, :session_token)
    assert is_binary(session_token)
    assert session_token != fixed_token

    cookie = conn |> get_resp_header("set-cookie") |> Enum.join("; ")
    assert cookie =~ "_config_manager_key="
    assert String.contains?(String.downcase(cookie), "secure")
    assert String.contains?(String.downcase(cookie), "httponly")
    assert cookie =~ "SameSite=Strict"
  end

  test "disabled users cannot log in through the browser", %{conn: conn} do
    username = unique_username("disabled-login")
    password = "long-enough-password"

    {:ok, _user} = create_user(username, password: password, active: false)

    conn = post(conn, "/login", %{"username" => username, "password" => password})

    assert html_response(conn, 200) =~ "Invalid username or password"
    refute get_session(conn, :session_token)

    audit = Repo.get_by!(AuditEntry, action: "login_failed", target_id: username)
    assert audit.actor_type == "anonymous"
    assert audit.result == "failure"
  end

  test "API tokens created by disabled users are rejected by API auth" do
    {:ok, user} = create_user(unique_username("disabled-token-owner"))

    {:ok, _token, raw_token} =
      Auth.create_api_token(user, token_attrs("disabled-owner-token"), user)

    {:ok, _disabled} = Auth.disable_user(user, user)

    conn =
      build_conn()
      |> bearer(raw_token)
      |> get("/api/v1/rules")

    assert json_response(conn, 401)["error"]["code"] == "UNAUTHORIZED"
  end

  test "API token creation endpoint returns raw token once without returning stored hash" do
    {:ok, admin} = create_user(unique_username("token-api-admin"))

    {:ok, _admin_token, admin_raw_token} =
      Auth.create_api_token(admin, token_attrs("token-api-admin", ["tokens:manage"]), admin)

    token_name = "api-created-token-#{System.unique_integer([:positive])}"

    conn =
      build_conn()
      |> bearer(admin_raw_token)
      |> post("/api/v1/admin/api-tokens", %{
        "name" => token_name,
        "permissions" => ["sensors:view"]
      })

    body = json_response(conn, 201)
    raw_token = body["token"]
    stored = Repo.get_by!(ApiToken, name: token_name)
    response_body = response(conn, 201)

    assert is_binary(raw_token)
    assert byte_size(raw_token) >= 32
    refute Map.has_key?(body["data"], "token_hash")
    refute response_body =~ stored.token_hash
    assert stored.token_hash == Auth.token_hash(raw_token)
  end

  test "browser forms include CSRF tokens and invalid CSRF tokens are rejected", %{conn: conn} do
    login_page =
      conn
      |> get("/login")
      |> html_response(200)

    assert login_page =~ ~s(name="_csrf_token")

    assert_raise Plug.CSRFProtection.InvalidCSRFTokenError, fn ->
      build_conn()
      |> put_private(:plug_skip_csrf_protection, false)
      |> post("/login", %{
        "_csrf_token" => "invalid-token",
        "username" => "missing-user",
        "password" => "wrong-password"
      })
    end
  end

  defp create_user(username, opts \\ []) do
    password = Keyword.get(opts, :password, "long-enough-password")
    role = Keyword.get(opts, :role, "platform-admin")
    active = Keyword.get(opts, :active, true)

    Auth.create_user(%{
      username: username,
      display_name: username,
      role: role,
      active: active,
      password: password
    })
  end

  defp token_attrs(name, permissions \\ ["sensors:view"]) do
    %{name: name, permissions: permissions}
  end

  defp unique_username(prefix), do: "#{prefix}-#{System.unique_integer([:positive])}"

  defp bearer(conn, raw_token) do
    put_req_header(conn, "authorization", "Bearer #{raw_token}")
  end
end
