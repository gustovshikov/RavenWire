defmodule ConfigManagerWeb.RulesLiveTestHelpers do
  @moduledoc false

  alias ConfigManager.Rules.{RuleRepository, SuricataRule}
  alias ConfigManager.{Auth, Repo, SensorPod, SensorPool}

  def create_user(role \\ "platform-admin") do
    username = "rules-live-#{role}-#{System.unique_integer([:positive])}"
    password = "long-enough-password"

    {:ok, user} =
      Auth.create_user(%{
        username: username,
        display_name: "Rules Live User",
        role: role,
        password: password
      })

    {user, password}
  end

  def login(conn, role \\ "platform-admin") do
    {user, password} = create_user(role)

    conn =
      Phoenix.ConnTest.dispatch(conn, ConfigManagerWeb.Endpoint, :post, "/login", %{
        "username" => user.username,
        "password" => password
      })

    {conn, user}
  end

  def insert_rule!(attrs) do
    sid = Map.fetch!(attrs, :sid)
    message = Map.get(attrs, :message, "Rule #{sid}")
    revision = Map.get(attrs, :revision, 1)

    attrs =
      Map.merge(
        %{
          message: message,
          raw_text:
            ~s|alert ip any any -> any any (msg:"#{message}"; classtype:trojan-activity; sid:#{sid}; rev:#{revision};)|,
          category: "local",
          classtype: "trojan-activity",
          severity: 2,
          revision: revision,
          enabled: true
        },
        attrs
      )

    %SuricataRule{}
    |> SuricataRule.changeset(attrs)
    |> Repo.insert!()
  end

  def insert_repository!(attrs \\ %{}) do
    attrs =
      Map.merge(
        %{
          name: "repo-#{System.unique_integer([:positive])}",
          url: "https://example.test/rules.tar.gz",
          repo_type: "custom"
        },
        attrs
      )

    %RuleRepository{}
    |> RuleRepository.changeset(attrs)
    |> Repo.insert!()
  end

  def insert_pool!(attrs \\ %{}) do
    attrs = Map.put_new(attrs, :name, "pool-#{System.unique_integer([:positive])}")

    %SensorPool{}
    |> SensorPool.create_changeset(attrs, "tester")
    |> Repo.insert!()
  end

  def insert_sensor!(name, pool_id \\ nil) do
    %SensorPod{}
    |> SensorPod.enrollment_changeset(%{
      name: name,
      public_key_pem: "public-key",
      key_fingerprint: "#{name}-fingerprint",
      enrolled_at: DateTime.utc_now() |> DateTime.truncate(:second),
      enrolled_by: "tester"
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(status: "enrolled", pool_id: pool_id)
    |> Repo.update!()
  end
end
