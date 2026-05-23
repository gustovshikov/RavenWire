defmodule ConfigManagerWeb.OperationalLiveRouteTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.Auth

  defp login(conn) do
    username = "ops-route-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, _user} =
      Auth.create_user(%{
        username: username,
        display_name: "Ops Route User",
        role: "platform-admin",
        password: password
      })

    post(conn, "/login", %{"username" => username, "password" => password})
  end

  test "platform admin can render operational LiveViews", %{conn: conn} do
    logged_in = login(conn)

    for {path, expected} <- [
          {"/enrollment", "RavenWire Enrollment"},
          {"/pcap-config", "Alert-Driven PCAP Configuration"},
          {"/deployments", "Fleet-wide desired-state deployment history"},
          {"/rules", "Quick Deploy"},
          {"/support-bundle", "Support Bundles"},
          {"/audit", "Audit Log"},
          {"/audit/export", "Audit Export"},
          {"/admin/users", "User Administration"},
          {"/admin/roles", "Role Reference"},
          {"/admin/api-tokens", "API Tokens"}
        ] do
      conn = logged_in |> recycle() |> get(path)
      assert html_response(conn, 200) =~ expected
    end
  end
end
