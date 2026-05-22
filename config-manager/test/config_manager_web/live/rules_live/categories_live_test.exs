defmodule ConfigManagerWeb.RulesLive.CategoriesLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  import ConfigManagerWeb.RulesLiveTestHelpers

  alias ConfigManager.{AuditEntry, Repo}
  alias ConfigManager.Rules.SuricataRule
  alias ConfigManagerWeb.RulesLive.CategoriesLive

  test "categories page renders counts and hides toggles for viewers", %{conn: conn} do
    insert_rule!(%{sid: 920_001, category: "malware", enabled: true})
    insert_rule!(%{sid: 920_002, category: "malware", enabled: false})

    {logged_conn, _user} = login(conn, "viewer")

    response =
      logged_conn
      |> recycle()
      |> get("/rules/categories")
      |> html_response(200)

    assert response =~ "Rule Categories"
    assert response =~ "malware"
    assert response =~ "2"
    refute response =~ ~s(phx-click="toggle_category")
  end

  test "category toggle updates matching rules and writes audit" do
    {admin, _password} = create_user("platform-admin")
    malware = insert_rule!(%{sid: 921_001, category: "malware", enabled: true})
    exploit = insert_rule!(%{sid: 921_002, category: "exploit", enabled: true})

    socket = build_socket(admin)

    assert {:noreply, updated} =
             CategoriesLive.handle_event(
               "toggle_category",
               %{"category" => "malware", "enabled" => "false"},
               socket
             )

    refute Repo.get!(SuricataRule, malware.id).enabled
    assert Repo.get!(SuricataRule, exploit.id).enabled
    assert updated.assigns.flash["info"] == "Updated 1 rule(s)."
    assert Repo.get_by!(AuditEntry, action: "category_toggled", target_id: "malware")
  end

  defp build_socket(user) do
    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        current_user: user,
        categories: []
      },
      private: %{live_temp: %{}}
    }
  end
end
