defmodule ConfigManagerWeb.ApiDocsTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.Auth.Policy
  alias ConfigManagerWeb.Api.Spec
  alias ConfigManagerWeb.Router

  test "GET /api/v1/openapi.json serves the implemented public API spec", %{conn: conn} do
    conn = get(conn, "/api/v1/openapi.json")
    body = json_response(conn, 200)

    assert get_resp_header(conn, "x-api-version") == ["v1"]
    assert body["openapi"] == "3.0.3"
    assert body["info"]["title"] == "RavenWire Config Manager Public API"
    assert body["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"
    assert body["paths"]["/api/v1/pcap/carve"]["post"]["x-ravenwire-permission"] == "pcap:search"
    refute Map.has_key?(body["paths"], "/api/v1/sensors")
    refute Map.has_key?(body["paths"], "/api/v1/pools")
  end

  test "local /api/docs page uses the local OpenAPI document without CDN assets", %{conn: conn} do
    conn = get(conn, "/api/docs")
    response = html_response(conn, 200)

    assert response =~ "RavenWire Config Manager API"
    assert response =~ "/api/v1/openapi.json"
    refute response =~ "cdn"
    refute response =~ "https://"
  end

  test "documentation endpoints can require browser authentication through hardened config", %{
    conn: conn
  } do
    previous = Application.get_env(:config_manager, :api_docs_require_auth)
    Application.put_env(:config_manager, :api_docs_require_auth, true)

    on_exit(fn ->
      Application.put_env(:config_manager, :api_docs_require_auth, previous)
    end)

    docs_conn = get(conn, "/api/docs")
    assert redirected_to(docs_conn) == "/login"

    spec_conn =
      build_conn()
      |> put_req_header("accept", "application/json")
      |> get("/api/v1/openapi.json")

    assert json_response(spec_conn, 401)["error"]["code"] == "UNAUTHORIZED"
  end

  test "protected API errors include version and request id headers and body fields", %{
    conn: conn
  } do
    conn =
      conn
      |> put_req_header("accept", "application/json")
      |> get("/api/v1/rules")

    body = json_response(conn, 401)
    request_id = get_resp_header(conn, "x-request-id") |> List.first()

    assert get_resp_header(conn, "x-api-version") == ["v1"]
    assert is_binary(request_id)
    assert body["error"]["code"] == "UNAUTHORIZED"
    assert body["error"]["request_id"] == request_id
  end

  test "unsupported API versions return JSON 404", %{conn: conn} do
    conn =
      conn
      |> put_req_header("accept", "application/json")
      |> get("/api/v2/rules")

    assert get_resp_header(conn, "x-api-version") == ["v1"]
    assert json_response(conn, 404)["error"]["code"] == "NOT_FOUND"
  end

  test "documented OpenAPI routes exist in the Phoenix router" do
    router_routes =
      Router.__routes__()
      |> Enum.map(fn route -> {route.verb |> to_string() |> String.downcase(), route.path} end)
      |> MapSet.new()

    for operation <- Spec.operations() do
      route_key = {operation.method |> Atom.to_string(), operation.router_path}

      assert MapSet.member?(router_routes, route_key),
             "#{operation.method} #{operation.router_path}"
    end
  end

  test "documented permissions are canonical RBAC permissions" do
    canonical_permissions = Policy.canonical_permissions()

    for operation <- Spec.operations() do
      assert operation.permission in canonical_permissions,
             "#{operation.method} #{operation.path} documents #{operation.permission}"
    end
  end

  test "no public automation route is mounted under an unversioned /api prefix" do
    unversioned_routes =
      Router.__routes__()
      |> Enum.filter(fn route ->
        String.starts_with?(route.path, "/api/") and
          not String.starts_with?(route.path, "/api/v1") and
          route.path not in ["/api/docs", "/api/*path"]
      end)

    assert unversioned_routes == []
  end
end
