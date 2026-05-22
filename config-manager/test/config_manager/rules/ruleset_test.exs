defmodule ConfigManager.Rules.RulesetTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Rules

  alias ConfigManager.Rules.{
    Compiler,
    PoolRulesetAssignment,
    Ruleset,
    RulesetRule,
    SuricataRule
  }

  alias ConfigManager.{AuditEntry, Repo, SensorPool}

  test "create_ruleset accepts valid attrs, audits, and broadcasts" do
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rulesets")

    assert {:ok, ruleset} =
             Rules.create_ruleset(
               %{name: " Default ", description: "Default rules", categories: ["malware"]},
               "tester"
             )

    assert ruleset.name == "Default"
    assert ruleset.version == 1
    assert ruleset.categories == ["malware"]
    assert ruleset.updated_by == "tester"

    audit = Repo.get_by!(AuditEntry, action: "ruleset_created", target_id: ruleset.id)
    assert audit.detail =~ "Default"
    assert_received {:ruleset_created, created}
    assert created.id == ruleset.id
  end

  test "create_ruleset rejects invalid and duplicate names case-insensitively" do
    assert {:error, invalid} = Rules.create_ruleset(%{name: "bad name"}, "tester")
    assert %{name: [_]} = errors_on(invalid)

    assert {:ok, _ruleset} = Rules.create_ruleset(%{name: "ProdRules"}, "tester")
    assert {:error, duplicate} = Rules.create_ruleset(%{name: "prodrules"}, "tester")
    assert %{name: [_]} = errors_on(duplicate)
  end

  test "update_ruleset increments version on category changes but not name-only changes" do
    {:ok, ruleset} = Rules.create_ruleset(%{name: "versioned", categories: ["malware"]}, "tester")

    assert {:ok, renamed} = Rules.update_ruleset(ruleset, %{name: "versioned-renamed"}, "tester")
    assert renamed.version == ruleset.version

    assert {:ok, changed} =
             Rules.update_ruleset(renamed, %{categories: ["malware", "exploit"]}, "tester")

    assert changed.version == renamed.version + 1
    assert changed.updated_by == "tester"
  end

  test "delete_ruleset cascade-deletes overrides and assignments and writes audit entry" do
    {:ok, ruleset} = Rules.create_ruleset(%{name: "delete-me", categories: ["malware"]}, "tester")
    rule = insert_rule!(%{sid: 610_001, category: "malware"})
    {:ok, _override} = Rules.add_ruleset_override(ruleset, rule.sid, "include", "tester")
    assignment = insert_assignment!(ruleset)

    assert {:ok, deleted} = Rules.delete_ruleset(ruleset, "tester")
    assert deleted.id == ruleset.id
    assert Repo.get(Ruleset, ruleset.id) == nil
    assert Repo.get_by(RulesetRule, ruleset_id: ruleset.id) == nil
    assert Repo.get(PoolRulesetAssignment, assignment.id) == nil

    audit = Repo.get_by!(AuditEntry, action: "ruleset_deleted", target_id: ruleset.id)
    assert audit.detail =~ "\"affected_pool_count\":1"
  end

  test "add and remove ruleset overrides increment version and audit" do
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rulesets")
    {:ok, ruleset} = Rules.create_ruleset(%{name: "overrides", categories: []}, "tester")
    rule = insert_rule!(%{sid: 620_001, category: "local"})

    assert {:ok, override} = Rules.add_ruleset_override(ruleset, rule.sid, "include", "tester")
    assert override.sid == rule.sid
    assert override.action == "include"
    assert Repo.get!(Ruleset, ruleset.id).version == ruleset.version + 1

    updated_ruleset = Repo.get!(Ruleset, ruleset.id)
    assert {:ok, deleted} = Rules.remove_ruleset_override(updated_ruleset, rule.sid, "tester")
    assert deleted.id == override.id
    assert Repo.get!(Ruleset, ruleset.id).version == ruleset.version + 2

    audits = Repo.all(from_audit("ruleset_updated", ruleset.id))
    assert Enum.any?(audits, &(&1.detail =~ "override_added"))
    assert Enum.any?(audits, &(&1.detail =~ "override_removed"))
    assert_received {:ruleset_updated, _}
  end

  test "include overrides validate that the SID exists" do
    {:ok, ruleset} = Rules.create_ruleset(%{name: "missing-include"}, "tester")

    assert {:error, :rule_not_found} =
             Rules.add_ruleset_override(ruleset, 629_999, "include", "tester")
  end

  test "effective_rules handles categories, includes, excludes, disabled rules, and counts" do
    malware = insert_rule!(%{sid: 630_001, category: "malware", enabled: true})
    excluded = insert_rule!(%{sid: 630_002, category: "malware", enabled: true})
    disabled = insert_rule!(%{sid: 630_003, category: "malware", enabled: false})
    included = insert_rule!(%{sid: 630_004, category: "local", enabled: true})
    _other = insert_rule!(%{sid: 630_005, category: "other", enabled: true})

    {:ok, ruleset} = Rules.create_ruleset(%{name: "effective", categories: ["malware"]}, "tester")
    {:ok, _include} = Rules.add_ruleset_override(ruleset, included.sid, "include", "tester")

    {:ok, _exclude} =
      Rules.add_ruleset_override(
        Repo.get!(Ruleset, ruleset.id),
        excluded.sid,
        "exclude",
        "tester"
      )

    effective_sids =
      ruleset.id
      |> Rules.effective_rules()
      |> Enum.map(& &1.sid)

    assert effective_sids == [malware.sid, included.sid]
    assert Rules.effective_rule_count(ruleset.id) == 2
    refute disabled.sid in effective_sids
  end

  test "compiler produces category files and local override files" do
    malware = insert_rule!(%{sid: 640_001, category: "malware", enabled: true})
    local = insert_rule!(%{sid: 640_002, category: "local", enabled: true})

    {:ok, ruleset} = Rules.create_ruleset(%{name: "compile", categories: ["malware"]}, "tester")
    {:ok, _include} = Rules.add_ruleset_override(ruleset, local.sid, "include", "tester")

    assert {:ok, files} = Compiler.compile(ruleset.id)
    assert Map.keys(files) |> Enum.sort() == ["local-overrides.rules", "malware.rules"]
    assert files["malware.rules"] =~ "sid:#{malware.sid};"
    assert files["local-overrides.rules"] =~ "sid:#{local.sid};"
  end

  test "compiler returns empty_ruleset for rulesets with no effective rules" do
    {:ok, ruleset} = Rules.create_ruleset(%{name: "empty", categories: ["missing"]}, "tester")

    assert {:error, :empty_ruleset} = Compiler.compile(ruleset.id)
  end

  test "list_rulesets includes effective counts and assigned pool counts" do
    insert_rule!(%{sid: 650_001, category: "malware"})
    {:ok, ruleset} = Rules.create_ruleset(%{name: "listed", categories: ["malware"]}, "tester")
    insert_assignment!(ruleset)

    assert [%{ruleset: listed, effective_count: 1, pool_count: 1}] = Rules.list_rulesets()
    assert listed.id == ruleset.id
  end

  defp insert_rule!(attrs) do
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

  defp insert_assignment!(ruleset) do
    pool =
      %SensorPool{}
      |> SensorPool.create_changeset(
        %{name: "pool-#{System.unique_integer([:positive])}"},
        "tester"
      )
      |> Repo.insert!()

    %PoolRulesetAssignment{}
    |> PoolRulesetAssignment.changeset(%{
      pool_id: pool.id,
      ruleset_id: ruleset.id,
      assigned_by: "tester"
    })
    |> Repo.insert!()
  end

  defp from_audit(action, target_id) do
    import Ecto.Query

    from(a in AuditEntry,
      where: a.action == ^action and a.target_id == ^target_id,
      order_by: [asc: a.timestamp]
    )
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
