defmodule ConfigManager.Rules.RepositoryTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Rules
  alias ConfigManager.Rules.{RuleRepository, SuricataRule}
  alias ConfigManager.{AuditEntry, Repo}

  test "creates, lists, and gets repositories with audit entries" do
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rule_repositories")

    assert {:ok, repository} =
             Rules.create_repository(
               %{
                 name: " ET Open ",
                 url: "https://rules.example.test/emerging.rules.tar.gz",
                 repo_type: "et_open"
               },
               "tester"
             )

    assert repository.name == "ET Open"
    assert Rules.get_repository(repository.id).id == repository.id
    assert Enum.map(Rules.list_repositories(), & &1.id) == [repository.id]

    audit = Repo.get_by!(AuditEntry, action: "repository_added", target_id: repository.id)
    assert audit.actor == "tester"
    assert audit.detail =~ "ET Open"
    assert_received {:repository_created, created}
    assert created.id == repository.id
  end

  test "rejects invalid repositories and duplicate names case-insensitively" do
    assert {:error, invalid} =
             Rules.create_repository(
               %{name: "bad", url: "ftp://rules.example.test/a.tar.gz"},
               "tester"
             )

    assert %{url: [_]} = errors_on(invalid)

    assert {:ok, _repository} =
             Rules.create_repository(
               %{name: "Case Repo", url: "https://rules.example.test/a.tar.gz"},
               "tester"
             )

    assert {:error, duplicate} =
             Rules.create_repository(
               %{name: "case repo", url: "https://rules.example.test/b.tar.gz"},
               "tester"
             )

    assert %{name: [_]} = errors_on(duplicate)
  end

  test "update_repository marks status updating and broadcasts" do
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rule_repositories")
    repository = insert_repository!("Update Repo")

    assert {:ok, :updating} = Rules.update_repository(repository, "tester", start_task?: false)

    updated = Repo.get!(RuleRepository, repository.id)
    assert updated.last_update_status == "updating"
    assert updated.last_update_error == nil
    assert_received {:repository_updating, repository_id}
    assert repository_id == repository.id
  end

  test "delete_repository preserves imported rules and writes audit entry" do
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rule_repositories")
    repository = insert_repository!("Delete Repo")
    rule = insert_rule!(repository, %{sid: 400_001, repository_name: repository.name})

    assert {:ok, deleted} = Rules.delete_repository(repository, "tester")
    assert deleted.id == repository.id
    assert Repo.get(RuleRepository, repository.id) == nil

    preserved = Repo.get!(SuricataRule, rule.id)
    assert preserved.repository_id == repository.id
    assert preserved.repository_name == repository.name

    audit = Repo.get_by!(AuditEntry, action: "repository_deleted", target_id: repository.id)
    assert audit.detail =~ "\"preserved_rule_count\":1"
    assert_received {:repository_deleted, repository_id}
    assert repository_id == repository.id
  end

  test "bulk_upsert_rules inserts new rules and audits counts" do
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rules")
    repository = insert_repository!("Insert Repo")

    assert {:ok, %{added: 2, updated: 0, unchanged: 0}} =
             Rules.bulk_upsert_rules(
               [rule_data(410_001, revision: 1), rule_data(410_002, revision: 1)],
               repository,
               "tester"
             )

    assert Repo.get_by!(SuricataRule, sid: 410_001).repository_name == repository.name
    assert Repo.get_by!(SuricataRule, sid: 410_002).repository_id == repository.id

    audit = Repo.get_by!(AuditEntry, action: "repository_updated", target_id: repository.id)
    assert audit.detail =~ "\"added\":2"
    assert_received {:rules_updated, repository_id}
    assert repository_id == repository.id
  end

  test "bulk_upsert_rules updates rev-greater-or-equal data while preserving enabled state" do
    repository = insert_repository!("Update Rules Repo")
    existing = insert_rule!(repository, %{sid: 420_001, revision: 1, enabled: false})

    assert {:ok, %{added: 0, updated: 1, unchanged: 0}} =
             Rules.bulk_upsert_rules(
               [
                 rule_data(420_001,
                   message: "Updated message",
                   revision: 2,
                   raw_text: generated_rule(420_001, "Updated message", 2)
                 )
               ],
               repository,
               "tester"
             )

    updated = Repo.get!(SuricataRule, existing.id)
    assert updated.message == "Updated message"
    assert updated.revision == 2
    assert updated.enabled == false
  end

  test "bulk_upsert_rules leaves older revisions unchanged" do
    repository = insert_repository!("Older Rules Repo")
    existing = insert_rule!(repository, %{sid: 430_001, message: "Current", revision: 3})

    assert {:ok, %{added: 0, updated: 0, unchanged: 1}} =
             Rules.bulk_upsert_rules(
               [
                 rule_data(430_001,
                   message: "Older",
                   revision: 2,
                   raw_text: generated_rule(430_001, "Older", 2)
                 )
               ],
               repository,
               "tester"
             )

    unchanged = Repo.get!(SuricataRule, existing.id)
    assert unchanged.message == "Current"
    assert unchanged.revision == 3
  end

  test "bulk_upsert_rules is idempotent for identical incoming data" do
    repository = insert_repository!("Idempotent Repo")
    rules = [rule_data(440_001, revision: 1)]

    assert {:ok, %{added: 1, updated: 0, unchanged: 0}} =
             Rules.bulk_upsert_rules(rules, repository, "tester")

    assert {:ok, %{added: 0, updated: 0, unchanged: 1}} =
             Rules.bulk_upsert_rules(rules, repository, "tester")
  end

  defp insert_repository!(name) do
    {:ok, repository} =
      Rules.create_repository(
        %{
          name: name,
          url: "https://rules.example.test/#{String.replace(name, " ", "-")}.tar.gz"
        },
        "tester"
      )

    repository
  end

  defp insert_rule!(repository, attrs) do
    sid = Map.fetch!(attrs, :sid)
    message = Map.get(attrs, :message, "Rule #{sid}")
    revision = Map.get(attrs, :revision, 1)

    attrs =
      Map.merge(
        %{
          message: message,
          raw_text: generated_rule(sid, message, revision),
          category: "emerging-test",
          classtype: "trojan-activity",
          severity: 2,
          revision: revision,
          enabled: true,
          repository_id: repository.id,
          repository_name: repository.name
        },
        attrs
      )

    %SuricataRule{}
    |> SuricataRule.changeset(attrs)
    |> Repo.insert!()
  end

  defp rule_data(sid, opts) do
    message = Keyword.get(opts, :message, "Imported #{sid}")
    revision = Keyword.get(opts, :revision, 1)

    %{
      sid: sid,
      message: message,
      raw_text: Keyword.get(opts, :raw_text, generated_rule(sid, message, revision)),
      category: Keyword.get(opts, :category, "emerging-test"),
      classtype: Keyword.get(opts, :classtype, "trojan-activity"),
      revision: revision
    }
  end

  defp generated_rule(sid, message, revision) do
    ~s|alert ip any any -> any any (msg:"#{message}"; classtype:trojan-activity; sid:#{sid}; rev:#{revision};)|
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
