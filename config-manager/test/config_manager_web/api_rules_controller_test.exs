defmodule ConfigManagerWeb.ApiRulesControllerTest do
  use ConfigManagerWeb.ConnCase, async: false

  alias ConfigManager.Rules.SuricataRule
  alias ConfigManager.{AuditEntry, Auth, Repo}

  test "POST /api/v1/rules creates a manual rule with a rules:manage token" do
    {raw_token, token_name} = create_api_token!(["rules:manage"])
    sid = unique_sid()

    raw_text =
      ~s|alert tcp any any -> any any (msg:"API Manual Rule"; classtype:policy-violation; sid:#{sid}; rev:3;)|

    conn =
      build_conn()
      |> bearer(raw_token)
      |> post("/api/v1/rules", %{
        "raw_text" => raw_text,
        "category" => "manual-api",
        "severity" => 1
      })

    body = json_response(conn, 201)
    assert body["data"]["sid"] == sid
    assert body["data"]["message"] == "API Manual Rule"
    assert body["data"]["category"] == "manual-api"

    rule = Repo.get_by!(SuricataRule, sid: sid)
    assert rule.raw_text == raw_text
    assert rule.classtype == "policy-violation"
    assert rule.revision == 3

    audit = Repo.get_by!(AuditEntry, action: "rule_created", target_id: rule.id)
    assert audit.actor == token_name
    assert audit.actor_type == "api_token"
    assert Jason.decode!(audit.detail)["sid"] == sid
  end

  test "POST /api/v1/rules reports validation errors for invalid manual rules" do
    {raw_token, _token_name} = create_api_token!(["rules:manage"])

    conn =
      build_conn()
      |> bearer(raw_token)
      |> post("/api/v1/rules", %{
        "raw_text" => ~s|alert tcp any any -> any any (msg:"Missing SID"; rev:1;)|,
        "category" => "manual-api"
      })

    body = json_response(conn, 422)
    assert body["error"]["code"] == "ACTION_FAILED"
    assert body["error"]["message"] == "missing sid"
  end

  defp create_api_token!(permissions) do
    username = "api-rules-user-#{System.unique_integer([:positive])}"
    token_name = "api-rules-token-#{System.unique_integer([:positive])}"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: username,
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

  defp unique_sid do
    4_000_000 + System.unique_integer([:positive])
  end
end
