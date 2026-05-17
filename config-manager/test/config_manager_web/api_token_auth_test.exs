defmodule ConfigManagerWeb.ApiTokenAuthTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.{AuditEntry, Auth, Repo}
  alias ConfigManagerWeb.Plugs.{ApiTokenAuth, RequirePermission}

  test "api token auth assigns the token and owner for a valid bearer token", %{conn: conn} do
    {:ok, user} = create_user!("api-token-user")
    {:ok, token, raw_token} = Auth.create_api_token(user, token_attrs(), user)

    conn =
      conn
      |> put_req_header("authorization", "Bearer #{raw_token}")
      |> ApiTokenAuth.call([])

    refute conn.halted
    assert conn.assigns.current_token.id == token.id
    assert conn.assigns.current_token.token_hash == nil
    assert conn.assigns.current_user.id == user.id
  end

  test "api token auth rejects missing or invalid bearer tokens", %{conn: conn} do
    conn = ApiTokenAuth.call(conn, [])
    assert conn.halted
    assert json_response(conn, 401)["error"]["code"] == "UNAUTHORIZED"

    conn =
      build_conn()
      |> put_req_header("authorization", "Bearer bad-token")
      |> ApiTokenAuth.call([])

    assert conn.halted
    assert json_response(conn, 401)["error"]["code"] == "UNAUTHORIZED"
  end

  test "require permission enforces token scopes and records denial audits", %{conn: conn} do
    {:ok, user} = create_user!("scoped-token-user")
    {:ok, _token, raw_token} = Auth.create_api_token(user, token_attrs(), user)

    allowed_conn =
      conn
      |> Map.put(:request_path, "/api/v1/example")
      |> put_req_header("authorization", "Bearer #{raw_token}")
      |> ApiTokenAuth.call([])
      |> RequirePermission.call("sensors:view")

    refute allowed_conn.halted

    denied_conn =
      build_conn(:get, "/api/v1/example")
      |> put_req_header("authorization", "Bearer #{raw_token}")
      |> ApiTokenAuth.call([])
      |> RequirePermission.call("rules:deploy")

    assert denied_conn.halted
    assert json_response(denied_conn, 403)["error"]["code"] == "FORBIDDEN"

    audit = Repo.get_by!(AuditEntry, action: "permission_denied", target_id: "/api/v1/example")
    assert audit.actor == "workflow"
    assert audit.actor_type == "api_token"
    assert Jason.decode!(audit.detail)["required_permission"] == "rules:deploy"
  end

  defp token_attrs do
    %{name: "workflow", permissions: ["sensors:view"]}
  end

  defp create_user!(username) do
    Auth.create_user(%{
      username: username,
      display_name: username,
      role: "platform-admin",
      password: "long-enough-password"
    })
  end
end
