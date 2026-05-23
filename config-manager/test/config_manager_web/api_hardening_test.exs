defmodule ConfigManagerWeb.ApiHardeningTest do
  use ConfigManagerWeb.ConnCase, async: false

  import Ecto.Query

  alias ConfigManager.{AuditEntry, Auth, Repo}
  alias ConfigManagerWeb.Api.RateLimiter

  test "API success, pagination, and error envelopes keep their documented structure" do
    {raw_token, _token} = create_api_token!(["sensors:view"])

    success_conn =
      build_conn()
      |> bearer(raw_token)
      |> get("/api/v1/rules?page=1&page_size=25")

    success_body = json_response(success_conn, 200)
    assert is_list(success_body["data"])
    assert success_body["meta"]["page"] == 1
    assert success_body["meta"]["page_size"] == 25
    assert is_integer(success_body["meta"]["total_count"])
    assert is_integer(success_body["meta"]["total_pages"])

    error_conn =
      build_conn()
      |> put_req_header("accept", "application/json")
      |> get("/api/v1/rules")

    error_body = json_response(error_conn, 401)
    assert error_body["error"]["code"] == "UNAUTHORIZED"
    assert is_binary(error_body["error"]["message"])
    assert is_binary(error_body["error"]["request_id"])
  end

  test "authenticated API requests write request-level audit entries" do
    {raw_token, token} = create_api_token!(["sensors:view"])

    conn =
      build_conn()
      |> bearer(raw_token)
      |> get("/api/v1/rules")

    assert json_response(conn, 200)["data"] == []

    audit = latest_request_audit!(token.name)
    detail = Jason.decode!(audit.detail)

    assert audit.actor == token.name
    assert audit.actor_type == "api_token"
    assert audit.target_type == "api_route"
    assert audit.target_id == "/api/v1/rules"
    assert audit.result == "success"
    assert detail["method"] == "GET"
    assert detail["path_template"] == "/api/v1/rules"
    assert detail["required_permission"] == "sensors:view"
    assert detail["status"] == 200
    assert detail["token_id"] == token.id
    assert is_binary(detail["request_id"])
    refute audit.detail =~ raw_token
    refute audit.detail =~ "authorization"
  end

  test "request-level audit records failure status and route template for denied API requests" do
    {raw_token, token} = create_api_token!(["dashboard:view"])

    conn =
      build_conn()
      |> bearer(raw_token)
      |> get("/api/v1/pcap/requests/missing")

    assert json_response(conn, 403)["error"]["code"] == "FORBIDDEN"

    audit = latest_request_audit!(token.name)
    detail = Jason.decode!(audit.detail)

    assert audit.target_id == "/api/v1/pcap/requests/:id"
    assert audit.result == "failure"
    assert detail["required_permission"] == "pcap:search"
    assert detail["status"] == 403
  end

  test "API token rate limit returns 429 and is audited" do
    previous_limit = Application.get_env(:config_manager, :api_token_rate_limit_per_minute)
    Application.put_env(:config_manager, :api_token_rate_limit_per_minute, 2)
    RateLimiter.reset()

    on_exit(fn ->
      Application.put_env(:config_manager, :api_token_rate_limit_per_minute, previous_limit)
      RateLimiter.reset()
    end)

    {raw_token, token} = create_api_token!(["sensors:view"])

    for _ <- 1..2 do
      conn =
        build_conn()
        |> bearer(raw_token)
        |> get("/api/v1/rules")

      assert json_response(conn, 200)["data"] == []
    end

    limited_conn =
      build_conn()
      |> bearer(raw_token)
      |> get("/api/v1/rules")

    body = json_response(limited_conn, 429)
    assert body["error"]["code"] == "RATE_LIMITED"
    assert body["error"]["details"]["limit"] == 2
    assert [retry_after] = get_resp_header(limited_conn, "retry-after")
    assert String.to_integer(retry_after) > 0

    audit = latest_request_audit!(token.name)
    detail = Jason.decode!(audit.detail)
    assert audit.result == "failure"
    assert audit.target_id == "/api/v1/rules"
    assert detail["status"] == 429
  end

  defp create_api_token!(permissions) do
    username = "api-hardening-user-#{System.unique_integer([:positive])}"
    token_name = "api-hardening-token-#{System.unique_integer([:positive])}"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: username,
        role: "platform-admin",
        password: "long-enough-password"
      })

    {:ok, token, raw_token} =
      Auth.create_api_token(user, %{name: token_name, permissions: permissions}, user)

    {raw_token, token}
  end

  defp bearer(conn, raw_token) do
    put_req_header(conn, "authorization", "Bearer #{raw_token}")
  end

  defp latest_request_audit!(actor) do
    Repo.one!(
      from(a in AuditEntry,
        where: a.actor == ^actor and a.action == "api_request",
        order_by: [desc: a.timestamp],
        limit: 1
      )
    )
  end
end
