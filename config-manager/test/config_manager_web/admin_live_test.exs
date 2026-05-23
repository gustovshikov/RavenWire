defmodule ConfigManagerWeb.AdminLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.{AuditEntry, Auth, Repo}
  alias ConfigManager.Auth.ApiToken

  defp login(conn, role \\ "platform-admin") do
    username = "admin-live-#{role}-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "Admin Live",
        role: role,
        password: password
      })

    {post(conn, "/login", %{"username" => username, "password" => password}), user}
  end

  test "platform admin can render local security admin pages", %{conn: conn} do
    {conn, admin} = login(conn)

    users_response =
      conn
      |> recycle()
      |> get("/admin/users")
      |> html_response(200)

    assert users_response =~ "User Administration"
    assert users_response =~ admin.username

    roles_response =
      conn
      |> recycle()
      |> get("/admin/roles")
      |> html_response(200)

    assert roles_response =~ "Role Reference"
    assert roles_response =~ "users:manage"

    tokens_response =
      conn
      |> recycle()
      |> get("/admin/api-tokens")
      |> html_response(200)

    assert tokens_response =~ "API Tokens"
    assert tokens_response =~ "sensors:view"
  end

  test "API token admin page lists redacted token metadata", %{conn: conn} do
    {conn, admin} = login(conn)

    {:ok, token, raw_token} =
      Auth.create_api_token(
        admin,
        %{name: "automation-token", permissions: ["sensors:view"]},
        admin
      )

    assert token.name == "automation-token"
    assert token.token_hash == nil
    assert ApiToken.permissions_list(token) == ["sensors:view"]

    response =
      conn
      |> recycle()
      |> get("/admin/api-tokens")
      |> html_response(200)

    assert response =~ "automation-token"
    assert response =~ "sensors:view"
    refute response =~ raw_token
  end

  test "audit export download applies filters and records an export audit entry", %{conn: conn} do
    {conn, admin} = login(conn)

    {:ok, _entry} =
      ConfigManager.Audit.log(%{
        actor: admin.username,
        actor_type: "user",
        action: "export_test_action",
        target_type: "test",
        target_id: "target-1",
        result: "success",
        detail: %{note: "export"}
      })

    conn = get(conn, "/audit/export/download?format=json&action=export_test_action")

    assert response(conn, 200) =~ "export_test_action"
    assert get_resp_header(conn, "content-disposition") |> List.first() =~ "ravenwire-audit"

    audit = Repo.get_by!(AuditEntry, action: "audit_export", actor: admin.username)
    assert Jason.decode!(audit.detail)["filters"] == %{"action" => "export_test_action"}
  end
end
