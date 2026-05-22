defmodule ConfigManagerWeb.RulesLive.StoreLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  import ConfigManagerWeb.RulesLiveTestHelpers

  alias ConfigManager.{AuditEntry, Repo}
  alias ConfigManager.Rules.SuricataRule
  alias ConfigManagerWeb.RulesLive.StoreLive

  test "store page renders rules sorted by SID and filters by search, category, and repository",
       %{
         conn: conn
       } do
    repository = insert_repository!(%{name: "ET Open"})

    later =
      insert_rule!(%{
        sid: 910_002,
        message: "Beta exploit",
        category: "exploit",
        repository_id: repository.id,
        repository_name: repository.name
      })

    earlier =
      insert_rule!(%{
        sid: 910_001,
        message: "Alpha malware",
        category: "malware",
        repository_id: repository.id,
        repository_name: repository.name
      })

    {logged_conn, _user} = login(conn, "viewer")

    response =
      logged_conn
      |> recycle()
      |> get("/rules/store")
      |> html_response(200)

    assert response =~ "Rule Store"
    assert response =~ "Alpha malware"
    assert response =~ "Beta exploit"
    assert String.contains?(response, Integer.to_string(earlier.sid))
    assert String.contains?(response, Integer.to_string(later.sid))

    assert :binary.match(response, Integer.to_string(earlier.sid)) <
             :binary.match(response, Integer.to_string(later.sid))

    search_response =
      logged_conn
      |> recycle()
      |> get("/rules/store?search=Alpha")
      |> html_response(200)

    assert search_response =~ "Alpha malware"
    refute search_response =~ "Beta exploit"

    category_response =
      logged_conn
      |> recycle()
      |> get("/rules/store?category=exploit")
      |> html_response(200)

    assert category_response =~ "Beta exploit"
    refute category_response =~ "Alpha malware"

    repo_response =
      logged_conn
      |> recycle()
      |> get("/rules/store?repository_id=#{repository.id}")
      |> html_response(200)

    assert repo_response =~ "ET Open"
  end

  test "store page hides mutation controls from read-only users", %{conn: conn} do
    insert_rule!(%{sid: 911_001, message: "read only"})

    {logged_conn, _user} = login(conn, "viewer")

    response =
      logged_conn
      |> recycle()
      |> get("/rules/store")
      |> html_response(200)

    refute response =~ "Select Page"
    refute response =~ ~s(phx-click="toggle_rule")
  end

  test "store page paginates and distinguishes empty states", %{conn: conn} do
    {logged_conn, _user} = login(conn, "viewer")

    empty_response =
      logged_conn
      |> recycle()
      |> get("/rules/store")
      |> html_response(200)

    assert empty_response =~ "No rules in store"

    for sid <- 913_001..913_026 do
      insert_rule!(%{sid: sid, message: "paged #{sid}"})
    end

    page_one =
      logged_conn
      |> recycle()
      |> get("/rules/store")
      |> html_response(200)

    assert page_one =~ "913001"
    refute page_one =~ "913026"

    page_two =
      logged_conn
      |> recycle()
      |> get("/rules/store?page=2")
      |> html_response(200)

    assert page_two =~ "913026"

    no_match =
      logged_conn
      |> recycle()
      |> get("/rules/store?search=missing")
      |> html_response(200)

    assert no_match =~ "No rules found"
  end

  test "toggle and bulk toggle events enforce rules:manage and write audits" do
    {admin, _password} = create_user("platform-admin")
    rule = insert_rule!(%{sid: 912_001, enabled: true})
    other = insert_rule!(%{sid: 912_002, enabled: true})

    socket = build_socket(admin, MapSet.new([rule.id, other.id]))

    assert {:noreply, toggled} = StoreLive.handle_event("toggle_rule", %{"id" => rule.id}, socket)
    refute Repo.get!(SuricataRule, rule.id).enabled
    assert toggled.assigns.rules.total_count == 2

    assert {:noreply, bulked} =
             StoreLive.handle_event("bulk_toggle", %{"enabled" => "false"}, socket)

    refute Repo.get!(SuricataRule, other.id).enabled
    assert bulked.assigns.flash["info"] == "Updated 2 rule(s)."
    assert Repo.get_by!(AuditEntry, action: "rule_toggled", target_id: rule.id)
    assert Repo.get_by!(AuditEntry, action: "bulk_rules_toggled", target_id: "bulk")
  end

  defp build_socket(user, selected_ids) do
    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        current_user: user,
        filters: %{
          "search" => "",
          "category" => "",
          "repository_id" => "",
          "sort_by" => "sid",
          "sort_dir" => "asc",
          "page" => "1"
        },
        selected_ids: selected_ids
      },
      private: %{live_temp: %{}}
    }
  end
end
