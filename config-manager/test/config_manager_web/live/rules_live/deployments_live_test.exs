defmodule ConfigManagerWeb.RulesLive.DeploymentsLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  import ConfigManagerWeb.RulesLiveTestHelpers

  alias ConfigManager.Audit

  test "rule deployment history renders managed and quick deploy audit entries", %{conn: conn} do
    pool = insert_pool!(%{name: "history-pool"})

    Audit.log(%{
      actor: "tester",
      actor_type: "user",
      action: "rules_deployed",
      target_type: "pool",
      target_id: pool.id,
      result: "success",
      detail: %{
        pool_name: pool.name,
        ruleset_name: "prod-rules",
        version: 2,
        sensor_results: [%{pod_id: "sensor-1", pod_name: "sensor-1", result: "{:ok, %{}}"}]
      }
    })

    Audit.log(%{
      actor: "tester",
      actor_type: "user",
      action: "adhoc_rules_deployed",
      target_type: "pool",
      target_id: pool.id,
      result: "success",
      detail: %{
        pool_name: pool.name,
        filename: "local.rules",
        sensor_results: [%{result: "ok", message: "history-pool: rules deployed successfully."}]
      }
    })

    {logged_conn, _viewer} = login(conn, "viewer")

    response =
      logged_conn
      |> recycle()
      |> get("/rules/deployments")
      |> html_response(200)

    assert response =~ "Rule Deployments"
    assert response =~ "Managed Ruleset"
    assert response =~ "Quick Deploy"
    assert response =~ "prod-rules"
    assert response =~ "history-pool"
  end
end
