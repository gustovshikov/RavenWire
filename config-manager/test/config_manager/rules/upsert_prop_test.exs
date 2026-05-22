defmodule ConfigManager.Rules.UpsertPropTest do
  @moduledoc "Property coverage for repository SID upsert and deletion behavior."

  use ExUnit.Case, async: false
  use PropCheck

  alias ConfigManager.Rules
  alias ConfigManager.Rules.{RuleRepository, SuricataRule}
  alias ConfigManager.{AuditEntry, Repo}

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    :ok
  end

  property "Property 2: SID-based upsert preserves enabled state and is idempotent",
           [:verbose, numtests: 40] do
    forall code <- integer(1, 200_000) do
      reset_rule_store!()
      repository = insert_repository!("upsert-prop-#{code}")
      sid = 500_000 + code
      initial = rule_data(sid, "Initial #{code}", 1)

      {:ok, %{added: 1}} = Rules.bulk_upsert_rules([initial], repository, "property-operator")

      desired_enabled = rem(code, 2) == 0

      Repo.get_by!(SuricataRule, sid: sid)
      |> Ecto.Changeset.change(enabled: desired_enabled)
      |> Repo.update!()

      incoming = rule_data(sid, "Updated #{code}", rem(code, 5) + 2)

      {:ok, _counts} = Rules.bulk_upsert_rules([incoming], repository, "property-operator")
      first_state = rule_state(sid)
      {:ok, _counts} = Rules.bulk_upsert_rules([incoming], repository, "property-operator")
      second_state = rule_state(sid)

      first_state.enabled == desired_enabled and
        second_state.enabled == desired_enabled and
        first_state == second_state and
        Repo.aggregate(SuricataRule, :count, :id) == 1
    end
  end

  property "Property 11: Repository deletion preserves imported rules",
           [:verbose, numtests: 30] do
    forall code <- integer(1, 100_000) do
      reset_rule_store!()
      repository = insert_repository!("delete-prop-#{code}")
      rule_count = rem(code, 5) + 1

      rules =
        1..rule_count
        |> Enum.map(fn index -> rule_data(700_000 + code * 10 + index, "Rule #{index}", 1) end)

      {:ok, %{added: ^rule_count}} =
        Rules.bulk_upsert_rules(rules, repository, "property-operator")

      before_count = Repo.aggregate(SuricataRule, :count, :id)
      {:ok, _deleted} = Rules.delete_repository(repository, "property-operator")
      preserved_rules = Repo.all(SuricataRule)

      Repo.get(RuleRepository, repository.id) == nil and
        length(preserved_rules) == before_count and
        Enum.all?(preserved_rules, &(&1.repository_name == repository.name))
    end
  end

  defp reset_rule_store! do
    Repo.delete_all(AuditEntry)
    Repo.delete_all(SuricataRule)
    Repo.delete_all(RuleRepository)
  end

  defp insert_repository!(name) do
    {:ok, repository} =
      Rules.create_repository(
        %{name: name, url: "https://rules.example.test/#{name}.tar.gz"},
        "property-operator"
      )

    repository
  end

  defp rule_data(sid, message, revision) do
    %{
      sid: sid,
      message: message,
      raw_text:
        ~s|alert ip any any -> any any (msg:"#{message}"; classtype:trojan-activity; sid:#{sid}; rev:#{revision};)|,
      category: "emerging-property",
      classtype: "trojan-activity",
      revision: revision
    }
  end

  defp rule_state(sid) do
    rule = Repo.get_by!(SuricataRule, sid: sid)

    Map.take(rule, [
      :sid,
      :message,
      :raw_text,
      :category,
      :classtype,
      :severity,
      :revision,
      :enabled,
      :repository_id,
      :repository_name
    ])
  end
end
