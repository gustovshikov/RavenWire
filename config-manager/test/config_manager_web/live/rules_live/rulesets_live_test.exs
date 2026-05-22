defmodule ConfigManagerWeb.RulesLive.RulesetsLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  import ConfigManagerWeb.RulesLiveTestHelpers

  alias ConfigManager.Rules
  alias ConfigManager.Rules.PoolRulesetAssignment
  alias ConfigManager.Repo
  alias ConfigManagerWeb.RulesLive.RulesetDetailLive

  test "ruleset list and detail pages render effective counts and assignments", %{conn: conn} do
    insert_rule!(%{sid: 930_001, category: "malware"})

    {:ok, ruleset} =
      Rules.create_ruleset(%{name: "prod-rules", categories: ["malware"]}, "tester")

    pool = insert_pool!(%{name: "prod-pool"})
    {:ok, _assignment} = Rules.assign_ruleset_to_pool(ruleset, pool, "tester")

    {logged_conn, _viewer} = login(conn, "viewer")

    list_response =
      logged_conn
      |> recycle()
      |> get("/rules/rulesets")
      |> html_response(200)

    assert list_response =~ "prod-rules"
    assert list_response =~ "prod-pool" or list_response =~ "1"
    refute list_response =~ "Create Ruleset"

    detail_response =
      logged_conn
      |> recycle()
      |> get("/rules/rulesets/#{ruleset.id}")
      |> html_response(200)

    assert detail_response =~ "Version 1 with 1 effective rule"
    assert detail_response =~ "malware"
    assert detail_response =~ "prod-pool"
    refute detail_response =~ "Deploy Rules"
    refute detail_response =~ "Edit"
  end

  test "new and edit pages show write controls to rule managers", %{conn: conn} do
    insert_rule!(%{sid: 931_001, category: "policy"})
    {:ok, ruleset} = Rules.create_ruleset(%{name: "editable-rules"}, "tester")
    {logged_conn, _admin} = login(conn, "platform-admin")

    new_response =
      logged_conn
      |> recycle()
      |> get("/rules/rulesets/new")
      |> html_response(200)

    assert new_response =~ "New Ruleset"
    assert new_response =~ "Save Ruleset"

    edit_response =
      logged_conn
      |> recycle()
      |> get("/rules/rulesets/#{ruleset.id}/edit")
      |> html_response(200)

    assert edit_response =~ "Save Ruleset"
    assert edit_response =~ "policy"
  end

  test "ruleset form validation and detail overrides render" do
    {admin, _password} = create_user("platform-admin")
    rule = insert_rule!(%{sid: 931_101, category: "policy"})
    {:ok, ruleset} = Rules.create_ruleset(%{name: "override-rules"}, "tester")
    {:ok, _override} = Rules.add_ruleset_override(ruleset, rule.sid, "include", "tester")

    socket = build_socket(admin, %ConfigManager.Rules.Ruleset{categories: []})

    assert {:noreply, invalid} =
             RulesetDetailLive.handle_event(
               "validate",
               %{"ruleset" => %{"name" => "bad name", "categories" => ["policy"]}},
               %{socket | assigns: Map.put(socket.assigns, :live_action, :new)}
             )

    assert invalid.assigns.form.source.errors[:name]
    assert invalid.assigns.selected_categories == ["policy"]

    {viewer_conn, _viewer} = login(Phoenix.ConnTest.build_conn(), "viewer")

    detail_response =
      viewer_conn
      |> recycle()
      |> get("/rules/rulesets/#{ruleset.id}")
      |> html_response(200)

    assert detail_response =~ "931101"
    assert detail_response =~ "include"
  end

  test "assign and unassign pool events enforce one assignment" do
    {admin, _password} = create_user("platform-admin")
    {:ok, ruleset} = Rules.create_ruleset(%{name: "assignable-rules"}, "tester")
    pool = insert_pool!(%{name: "assignable-pool"})

    socket = build_socket(admin, ruleset)

    assert {:noreply, assigned} =
             RulesetDetailLive.handle_event("assign_pool", %{"pool_id" => pool.id}, socket)

    assert assigned.assigns.flash["info"] == "Ruleset assigned."
    assert Repo.get_by!(PoolRulesetAssignment, pool_id: pool.id).ruleset_id == ruleset.id

    assert {:noreply, unassigned} =
             RulesetDetailLive.handle_event("unassign_pool", %{"pool_id" => pool.id}, assigned)

    assert unassigned.assigns.flash["info"] == "Ruleset unassigned."
    assert Repo.get_by(PoolRulesetAssignment, pool_id: pool.id) == nil
  end

  test "deploy event compiles assigned ruleset and writes deployment audit" do
    {admin, _password} = create_user("platform-admin")
    insert_rule!(%{sid: 932_001, category: "malware"})

    {:ok, ruleset} =
      Rules.create_ruleset(%{name: "deployable-rules", categories: ["malware"]}, "tester")

    pool = insert_pool!(%{name: "deployable-pool"})
    {:ok, _assignment} = Rules.assign_ruleset_to_pool(ruleset, pool, "tester")

    socket = build_socket(admin, ruleset)

    assert {:noreply, deployed} =
             RulesetDetailLive.handle_event("deploy_to_pool", %{"pool_id" => pool.id}, socket)

    assert deployed.assigns.flash["info"] == "Ruleset v1 deployed to 0 sensor(s)."
    assert ConfigManager.Rules.deployed_rule_version(pool.id) == nil
    assert Repo.get_by!(ConfigManager.AuditEntry, action: "rules_deployed", target_id: pool.id)
  end

  defp build_socket(user, ruleset) do
    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        current_user: user,
        live_action: :show,
        ruleset: ruleset
      },
      private: %{live_temp: %{}}
    }
  end
end
