defmodule ConfigManagerWeb.AuditIntegrationTest do
  use ConfigManagerWeb.ConnCase, async: false

  import Ecto.Query

  alias ConfigManager.{AuditEntry, Auth, Repo}

  test "browser authentication success and failure paths write structural audits", %{conn: conn} do
    username = unique_name("audit-browser-user")
    password = "long-enough-password"
    {:ok, user} = create_user(username, password: password)

    failed_conn = post(conn, "/login", %{"username" => username, "password" => "wrong-password"})
    assert html_response(failed_conn, 200) =~ "Invalid username or password"

    failed_audit = latest_audit!("login_failed", username)
    assert_structural_audit(failed_audit, username, "login_failed", "failure")
    assert failed_audit.actor_type == "anonymous"
    assert Jason.decode!(failed_audit.detail)["reason"] == "invalid_credentials"

    logged_in = post(recycle(conn), "/login", %{"username" => username, "password" => password})
    assert redirected_to(logged_in) == "/"

    login_audit = latest_audit!("login", user.id)
    assert_structural_audit(login_audit, username, "login", "success")

    logged_out = post(recycle(logged_in), "/logout")
    assert redirected_to(logged_out) == "/login"

    logout_audit = latest_audit!("logout", user.id)
    assert_structural_audit(logout_audit, username, "logout", "success")
  end

  test "public API success, failure, and denial paths write structural audits" do
    {:ok, admin} = create_user(unique_name("audit-api-admin"))

    token_name = unique_name("audit-api-token")

    {:ok, _token, raw_token} =
      Auth.create_api_token(
        admin,
        %{
          name: token_name,
          permissions: [
            "users:manage",
            "tokens:manage",
            "bundle:download",
            "pcap:configure",
            "audit:export"
          ]
        },
        admin
      )

    created_username = unique_name("audit-api-created-user")

    user_conn =
      build_conn()
      |> bearer(raw_token)
      |> post("/api/v1/admin/users", %{
        "username" => created_username,
        "display_name" => "Audit API Created User",
        "role" => "viewer",
        "password" => "long-enough-password"
      })

    assert json_response(user_conn, 201)["data"]["username"] == created_username
    created_user = Auth.get_user_by_username(created_username)
    user_audit = latest_audit!("user_created", created_user.id)
    assert_structural_audit(user_audit, token_name, "user_created", "success")
    assert user_audit.actor_type == "api_token"

    created_token_name = unique_name("audit-api-created-token")

    token_conn =
      build_conn()
      |> bearer(raw_token)
      |> post("/api/v1/admin/api-tokens", %{
        "name" => created_token_name,
        "permissions" => ["sensors:view"]
      })

    assert json_response(token_conn, 201)["data"]["name"] == created_token_name

    created_token_audit =
      Repo.get_by!(AuditEntry, action: "api_token_created", actor: token_name)

    assert_structural_audit(created_token_audit, token_name, "api_token_created", "success")
    assert created_token_audit.actor_type == "api_token"

    missing_bundle_pod_id = Ecto.UUID.generate()

    bundle_conn =
      build_conn()
      |> bearer(raw_token)
      |> post("/api/v1/support-bundles", %{"pod_id" => missing_bundle_pod_id})

    assert json_response(bundle_conn, 404)["error"]["code"] == "NOT_FOUND"

    bundle_audit = latest_audit!("support_bundle_requested", missing_bundle_pod_id)
    assert_structural_audit(bundle_audit, token_name, "support_bundle_requested", "failure")
    assert Jason.decode!(bundle_audit.detail)["reason"] == "not_found"

    missing_pcap_pod_id = Ecto.UUID.generate()

    pcap_conn =
      build_conn()
      |> bearer(raw_token)
      |> post("/api/v1/pcap-config", %{
        "pod_id" => missing_pcap_pod_id,
        "pcap_ring_size_mb" => 4096,
        "pre_alert_window_sec" => 60,
        "post_alert_window_sec" => 30,
        "alert_severity_threshold" => 2
      })

    assert json_response(pcap_conn, 404)["error"]["code"] == "NOT_FOUND"

    pcap_audit = latest_audit!("pcap_config_changed", missing_pcap_pod_id)
    assert_structural_audit(pcap_audit, token_name, "pcap_config_changed", "failure")
    assert Jason.decode!(pcap_audit.detail)["reason"] == "not_found"

    export_conn =
      build_conn()
      |> bearer(raw_token)
      |> get("/api/v1/audit/export?format=json&action=login")

    assert response(export_conn, 200)

    export_audit = latest_audit!("audit_export", "export")
    assert_structural_audit(export_audit, token_name, "audit_export", "success")
    assert Jason.decode!(export_audit.detail)["format"] == "json"

    {:ok, _deny_token, deny_raw_token} =
      Auth.create_api_token(
        admin,
        %{name: unique_name("audit-deny-token"), permissions: ["dashboard:view"]},
        admin
      )

    denied_conn =
      build_conn()
      |> bearer(deny_raw_token)
      |> get("/api/v1/audit")

    assert json_response(denied_conn, 403)["error"]["code"] == "FORBIDDEN"

    denied_audit = latest_audit!("permission_denied", "/api/v1/audit")
    assert_structural_audit(denied_audit, denied_audit.actor, "permission_denied", "failure")
    assert Jason.decode!(denied_audit.detail)["required_permission"] == "audit:view"
  end

  defp create_user(username, opts \\ []) do
    Auth.create_user(%{
      username: username,
      display_name: username,
      role: Keyword.get(opts, :role, "platform-admin"),
      password: Keyword.get(opts, :password, "long-enough-password")
    })
  end

  defp bearer(conn, raw_token) do
    put_req_header(conn, "authorization", "Bearer #{raw_token}")
  end

  defp latest_audit!(action, target_id) do
    Repo.one!(
      from(a in AuditEntry,
        where: a.action == ^action and a.target_id == ^target_id,
        order_by: [desc: a.timestamp],
        limit: 1
      )
    )
  end

  defp assert_structural_audit(entry, actor, action, result) do
    assert entry.id
    assert entry.timestamp
    assert entry.actor == actor
    assert entry.actor_type in ~w(user api_token system anonymous)
    assert entry.action == action
    assert entry.result == result
    assert entry.detail
    assert {:ok, decoded} = Jason.decode(entry.detail)
    assert is_map(decoded)
  end

  defp unique_name(prefix), do: "#{prefix}-#{System.unique_integer([:positive])}"
end
