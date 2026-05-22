defmodule ConfigManagerWeb.RulesLive.RepositoriesLiveTest do
  use ConfigManagerWeb.ConnCase, async: false

  import ConfigManagerWeb.RulesLiveTestHelpers

  alias ConfigManager.{Repo, Rules}
  alias ConfigManager.Rules.RuleRepository
  alias ConfigManager.Rules.SuricataRule
  alias ConfigManagerWeb.RulesLive.RepositoriesLive

  test "repositories page renders repository state and hides management actions from viewers", %{
    conn: conn
  } do
    insert_repository!(%{
      name: "Threat Feed",
      url: "https://example.test/threat-feed.tar.gz"
    })

    {viewer_conn, _viewer} = login(conn, "viewer")

    viewer_response =
      viewer_conn
      |> recycle()
      |> get("/rules/repositories")
      |> html_response(200)

    assert viewer_response =~ "Threat Feed"
    refute viewer_response =~ "Add Repository"
    refute viewer_response =~ "Update Now"

    {admin_conn, _admin} = login(conn, "platform-admin")

    admin_response =
      admin_conn
      |> recycle()
      |> get("/rules/repositories")
      |> html_response(200)

    assert admin_response =~ "Add Repository"
    assert admin_response =~ "Update Now"
  end

  test "create event validates repository attributes and rejects duplicate names" do
    {admin, _password} = create_user("platform-admin")
    socket = build_socket(admin)

    assert {:noreply, created} =
             RepositoriesLive.handle_event(
               "create",
               %{
                 "repository" => %{
                   "name" => "New Feed",
                   "url" => "https://example.test/new.tar.gz",
                   "repo_type" => "custom"
                 }
               },
               socket
             )

    assert created.assigns.flash["info"] == "Repository added."
    assert %RuleRepository{} = Rules.get_repository(hd(created.assigns.repositories).id)

    assert {:noreply, duplicate} =
             RepositoriesLive.handle_event(
               "create",
               %{
                 "repository" => %{
                   "name" => "new feed",
                   "url" => "https://example.test/dupe.tar.gz",
                   "repo_type" => "custom"
                 }
               },
               socket
             )

    assert duplicate.assigns.form.source.errors[:name]
  end

  test "validation and delete events report errors and preserve imported rules" do
    {admin, _password} = create_user("platform-admin")
    repository = insert_repository!(%{name: "Delete Feed"})

    rule =
      insert_rule!(%{
        sid: 922_001,
        repository_id: repository.id,
        repository_name: repository.name
      })

    socket = build_socket(admin)

    assert {:noreply, invalid} =
             RepositoriesLive.handle_event(
               "validate",
               %{
                 "repository" => %{
                   "name" => "Bad Feed",
                   "url" => "not-a-url",
                   "repo_type" => "custom"
                 }
               },
               socket
             )

    assert invalid.assigns.form.source.errors[:url]

    assert {:noreply, deleted} =
             RepositoriesLive.handle_event("delete", %{"id" => repository.id}, socket)

    assert deleted.assigns.flash["info"] ==
             "Repository deleted. Imported rules were preserved."

    assert Rules.get_repository(repository.id) == nil
    assert Repo.get!(SuricataRule, rule.id).repository_name == repository.name
  end

  defp build_socket(user) do
    %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        flash: %{},
        current_user: user,
        repositories: [],
        repo_types: [{"Custom", "custom"}],
        form: nil
      },
      private: %{live_temp: %{}}
    }
  end
end
