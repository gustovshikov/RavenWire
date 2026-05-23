defmodule ConfigManager.Rules.RulesContextTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Rules
  alias ConfigManager.Rules.SuricataRule
  alias ConfigManager.{AuditEntry, Repo}

  test "list_rules supports search, filters, sorting, and repository filters" do
    repo_id = Ecto.UUID.generate()
    other_repo_id = Ecto.UUID.generate()

    malware_a =
      insert_rule!(%{
        sid: 100_001,
        message: "ET MALWARE Alpha",
        category: "malware",
        repository_id: repo_id,
        repository_name: "ET Open"
      })

    malware_b =
      insert_rule!(%{
        sid: 200_001,
        message: "Alpha policy event",
        category: "malware",
        repository_id: other_repo_id,
        repository_name: "Local"
      })

    exploit =
      insert_rule!(%{
        sid: 100_002,
        message: "ET EXPLOIT Beta",
        category: "exploit",
        repository_id: repo_id,
        repository_name: "ET Open"
      })

    assert %{entries: entries, total_count: 2} =
             Rules.list_rules(search: "100", sort_by: :sid, sort_dir: :desc)

    assert Enum.map(entries, & &1.sid) == [exploit.sid, malware_a.sid]

    assert %{entries: entries, total_count: 2} = Rules.list_rules(category: "malware")
    assert Enum.map(entries, & &1.id) == [malware_a.id, malware_b.id]

    assert %{entries: entries, total_count: 2} = Rules.list_rules(repository: "ET Open")
    assert Enum.map(entries, & &1.sid) == [malware_a.sid, exploit.sid]

    assert %{entries: [^malware_b], total_count: 1} = Rules.list_rules(search: "policy")
  end

  test "list_rules paginates and reports total pages" do
    insert_rule!(%{sid: 300_001, message: "one"})
    insert_rule!(%{sid: 300_002, message: "two"})
    insert_rule!(%{sid: 300_003, message: "three"})

    assert %{entries: page_one, total_count: 3, total_pages: 2, page: 1, page_size: 2} =
             Rules.list_rules(page: 1, page_size: 2)

    assert Enum.map(page_one, & &1.sid) == [300_001, 300_002]

    assert %{entries: page_two, total_count: 3, total_pages: 2, page: 2} =
             Rules.list_rules(page: 2, page_size: 2)

    assert Enum.map(page_two, & &1.sid) == [300_003]

    assert %{entries: [], total_count: 3, total_pages: 2, page: 3} =
             Rules.list_rules(page: 3, page_size: 2)
  end

  test "get_rule and get_rule_by_sid return rule records" do
    rule = insert_rule!(%{sid: 310_001, message: "lookup"})

    assert Rules.get_rule(rule.id).sid == rule.sid
    assert Rules.get_rule_by_sid(rule.sid).id == rule.id
  end

  test "create_rule parses raw manual rules, audits, and broadcasts" do
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rules")

    raw_text =
      ~s|alert tcp any any -> any any (msg:"Manual API Rule"; classtype:policy-violation; sid:315001; rev:2;)|

    assert {:ok, rule} =
             Rules.create_rule(
               %{"raw_text" => raw_text, "category" => "manual-api", "severity" => 1},
               "tester"
             )

    assert rule.sid == 315_001
    assert rule.message == "Manual API Rule"
    assert rule.category == "manual-api"
    assert rule.classtype == "policy-violation"
    assert rule.revision == 2
    assert rule.severity == 1
    assert rule.enabled

    audit = Repo.get_by!(AuditEntry, action: "rule_created", target_id: rule.id)
    assert audit.actor == "tester"
    assert audit.actor_type == "user"
    assert audit.target_type == "suricata_rule"
    assert Jason.decode!(audit.detail)["source"] == "manual"
    assert_received {:rule_created, rule_id}
    assert rule_id == rule.id
  end

  test "create_rule formats field-based rules and rejects invalid input" do
    assert {:ok, rule} =
             Rules.create_rule(
               %{"sid" => "315002", "message" => "Field Rule", "enabled" => "false"},
               "tester"
             )

    assert rule.sid == 315_002
    assert rule.message == "Field Rule"
    assert rule.category == "manual"
    assert rule.raw_text =~ ~s(msg:"Field Rule";)
    assert rule.raw_text =~ "sid:315002;"
    refute rule.enabled

    assert {:error, :invalid_rule} =
             Rules.create_rule(%{"message" => "Missing SID"}, "tester")
  end

  test "toggle_rule flips enabled state, audits, and broadcasts" do
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rules")
    rule = insert_rule!(%{sid: 320_001, enabled: true})

    assert {:ok, updated} = Rules.toggle_rule(rule, "tester")
    assert updated.enabled == false

    audit = Repo.get_by!(AuditEntry, action: "rule_toggled", target_id: rule.id)
    assert audit.actor == "tester"
    assert audit.target_type == "suricata_rule"
    assert audit.detail =~ "320001"
    assert_received {:rule_toggled, rule_id}
    assert rule_id == rule.id
  end

  test "bulk_toggle_rules handles empty, single, and multiple selections" do
    assert {:ok, 0} = Rules.bulk_toggle_rules([], false, "tester")

    rule_a = insert_rule!(%{sid: 330_001, enabled: true})
    rule_b = insert_rule!(%{sid: 330_002, enabled: true})
    rule_c = insert_rule!(%{sid: 330_003, enabled: true})

    assert {:ok, 1} = Rules.bulk_toggle_rules([rule_a.id], false, "tester")
    refute Repo.get!(SuricataRule, rule_a.id).enabled

    assert {:ok, 2} = Rules.bulk_toggle_rules([rule_b.id, rule_c.id], false, "tester")
    refute Repo.get!(SuricataRule, rule_b.id).enabled
    refute Repo.get!(SuricataRule, rule_c.id).enabled

    audits = Repo.all(from_audit("bulk_rules_toggled"))
    assert length(audits) == 3
    assert Enum.any?(audits, &(&1.detail =~ "330002"))
  end

  test "list_categories returns total, enabled, and disabled counts" do
    insert_rule!(%{sid: 340_001, category: "malware", enabled: true})
    insert_rule!(%{sid: 340_002, category: "malware", enabled: false})
    insert_rule!(%{sid: 340_003, category: "exploit", enabled: false})

    categories = Map.new(Rules.list_categories(), &{&1.name, &1})

    assert categories["malware"].total == 2
    assert categories["malware"].enabled == 1
    assert categories["malware"].disabled == 1
    assert categories["exploit"].total == 1
    assert categories["exploit"].enabled == 0
    assert categories["exploit"].disabled == 1
  end

  test "toggle_category affects only matching rules and audits the count" do
    Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rules")
    malware_a = insert_rule!(%{sid: 350_001, category: "malware", enabled: true})
    malware_b = insert_rule!(%{sid: 350_002, category: "malware", enabled: true})
    exploit = insert_rule!(%{sid: 350_003, category: "exploit", enabled: true})

    assert {:ok, 2} = Rules.toggle_category("malware", false, "tester")

    refute Repo.get!(SuricataRule, malware_a.id).enabled
    refute Repo.get!(SuricataRule, malware_b.id).enabled
    assert Repo.get!(SuricataRule, exploit.id).enabled

    audit = Repo.get_by!(AuditEntry, action: "category_toggled", target_id: "malware")
    assert audit.detail =~ "\"affected_count\":2"
    assert_received {:category_toggled, "malware"}
  end

  defp insert_rule!(attrs) do
    sid = Map.fetch!(attrs, :sid)

    attrs =
      Map.merge(
        %{
          message: "Rule #{sid}",
          raw_text: ~s|alert ip any any -> any any (msg:"Rule #{sid}"; sid:#{sid}; rev:1;)|,
          category: "local",
          revision: 1,
          severity: 2,
          enabled: true
        },
        attrs
      )

    %SuricataRule{}
    |> SuricataRule.changeset(attrs)
    |> Repo.insert!()
  end

  defp from_audit(action) do
    import Ecto.Query

    from(a in AuditEntry,
      where: a.action == ^action,
      order_by: [asc: a.timestamp]
    )
  end
end
