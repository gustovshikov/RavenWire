defmodule ConfigManager.Rules.SchemasTest do
  use ConfigManager.DataCase, async: false

  alias ConfigManager.Rules.{
    PoolRulesetAssignment,
    RuleRepository,
    Ruleset,
    RulesetRule,
    SuricataRule
  }

  alias ConfigManager.{Repo, SensorPool}

  describe "SuricataRule changeset" do
    test "accepts valid attrs and defaults enabled, severity, and revision" do
      changeset =
        SuricataRule.changeset(%SuricataRule{}, %{
          sid: 2_400_001,
          message: "ET MALWARE Example",
          raw_text:
            ~s|alert tcp any any -> any any (msg:"ET MALWARE Example"; sid:2400001; rev:1;)|,
          category: " emerging-malware "
        })

      assert changeset.valid?
      assert Ecto.Changeset.get_field(changeset, :severity) == 2
      assert Ecto.Changeset.get_field(changeset, :revision) == 1
      assert Ecto.Changeset.get_field(changeset, :enabled) == true
      assert Ecto.Changeset.get_field(changeset, :category) == "emerging-malware"
    end

    test "rejects missing sid and invalid severity" do
      changeset =
        SuricataRule.changeset(%SuricataRule{}, %{
          raw_text: "alert ip any any -> any any (msg:\"missing sid\";)",
          category: "local",
          severity: 9
        })

      refute changeset.valid?
      assert %{sid: [_], severity: [_]} = errors_on(changeset)
    end

    test "rejects duplicate sid" do
      attrs = valid_rule_attrs(2_400_002)

      assert {:ok, _rule} = %SuricataRule{} |> SuricataRule.changeset(attrs) |> Repo.insert()

      assert {:error, changeset} =
               %SuricataRule{} |> SuricataRule.changeset(attrs) |> Repo.insert()

      assert %{sid: [_]} = errors_on(changeset)
    end
  end

  describe "RuleRepository changeset" do
    test "accepts valid repository attrs and status updates" do
      changeset =
        RuleRepository.changeset(%RuleRepository{}, %{
          name: " ET Open ",
          url: "https://rules.example.test/emerging.rules.tar.gz",
          repo_type: "et_open"
        })

      assert changeset.valid?
      assert Ecto.Changeset.get_field(changeset, :name) == "ET Open"

      status =
        RuleRepository.update_status_changeset(%RuleRepository{}, %{
          last_update_status: "success",
          last_updated_at: DateTime.utc_now() |> DateTime.truncate(:second),
          rule_count: 42
        })

      assert status.valid?
    end

    test "rejects invalid URLs and duplicate names case-insensitively" do
      invalid =
        RuleRepository.changeset(%RuleRepository{}, %{
          name: "bad-url",
          url: "ftp://rules.example.test/archive.tar.gz",
          repo_type: "custom"
        })

      refute invalid.valid?
      assert %{url: [_]} = errors_on(invalid)

      assert {:ok, _repo} =
               %RuleRepository{}
               |> RuleRepository.changeset(%{
                 name: "Case Repo",
                 url: "https://rules.example.test/a.tar.gz"
               })
               |> Repo.insert()

      assert {:error, duplicate} =
               %RuleRepository{}
               |> RuleRepository.changeset(%{
                 name: "case repo",
                 url: "https://rules.example.test/b.tar.gz"
               })
               |> Repo.insert()

      assert %{name: [_]} = errors_on(duplicate)
    end
  end

  describe "Ruleset changeset" do
    test "accepts valid attrs, trims name, normalizes categories, and sets actor" do
      changeset =
        Ruleset.create_changeset(
          %Ruleset{},
          %{name: " Default ", categories: [" malware ", "exploit", "malware"]},
          "tester"
        )

      assert changeset.valid?
      assert Ecto.Changeset.get_field(changeset, :name) == "Default"
      assert Ecto.Changeset.get_field(changeset, :categories) == ["malware", "exploit"]
      assert Ecto.Changeset.get_field(changeset, :version) == 1
      assert Ecto.Changeset.get_field(changeset, :updated_by) == "tester"
    end

    test "rejects invalid names and duplicate names case-insensitively" do
      invalid = Ruleset.create_changeset(%Ruleset{}, %{name: "bad name"}, "tester")
      refute invalid.valid?
      assert %{name: [_]} = errors_on(invalid)

      assert {:ok, _ruleset} =
               %Ruleset{}
               |> Ruleset.create_changeset(%{name: "ProdRules"}, "tester")
               |> Repo.insert()

      assert {:error, duplicate} =
               %Ruleset{}
               |> Ruleset.create_changeset(%{name: "prodrules"}, "tester")
               |> Repo.insert()

      assert %{name: [_]} = errors_on(duplicate)
    end

    test "increments version on category changes but not metadata-only changes" do
      ruleset = %Ruleset{name: "default", version: 3, categories: ["malware"], updated_by: "old"}

      metadata = Ruleset.update_changeset(ruleset, %{description: "renamed"}, "tester")
      assert metadata.valid?
      assert Ecto.Changeset.get_field(metadata, :version) == 3
      assert Ecto.Changeset.get_field(metadata, :updated_by) == "old"

      content =
        Ruleset.update_changeset(ruleset, %{categories: ["malware", "exploit"]}, "tester")

      assert content.valid?
      assert Ecto.Changeset.get_field(content, :version) == 4
      assert Ecto.Changeset.get_field(content, :updated_by) == "tester"
    end
  end

  describe "RulesetRule changeset" do
    test "accepts include and exclude actions and rejects invalid actions" do
      ruleset = insert_ruleset!("override-rules")

      valid =
        RulesetRule.changeset(%RulesetRule{}, %{
          ruleset_id: ruleset.id,
          sid: 2_400_010,
          action: "include"
        })

      assert valid.valid?

      invalid =
        RulesetRule.changeset(%RulesetRule{}, %{
          ruleset_id: ruleset.id,
          sid: 2_400_011,
          action: "drop"
        })

      refute invalid.valid?
      assert %{action: [_]} = errors_on(invalid)
    end

    test "rejects duplicate ruleset and sid pairs" do
      ruleset = insert_ruleset!("duplicate-overrides")
      attrs = %{ruleset_id: ruleset.id, sid: 2_400_012, action: "exclude"}

      assert {:ok, _override} = %RulesetRule{} |> RulesetRule.changeset(attrs) |> Repo.insert()
      assert {:error, changeset} = %RulesetRule{} |> RulesetRule.changeset(attrs) |> Repo.insert()
      assert %{ruleset_id: [_]} = errors_on(changeset)
    end
  end

  describe "PoolRulesetAssignment changeset" do
    test "accepts valid assignment and rejects duplicate pool assignment" do
      pool = insert_pool!("rules-pool")
      ruleset = insert_ruleset!("pool-ruleset")
      replacement = insert_ruleset!("pool-ruleset-replacement")

      attrs = %{pool_id: pool.id, ruleset_id: ruleset.id, assigned_by: "tester"}
      assert {:ok, _assignment} = assignment_insert(attrs)

      assert {:error, changeset} =
               assignment_insert(%{
                 pool_id: pool.id,
                 ruleset_id: replacement.id,
                 assigned_by: "tester"
               })

      assert %{pool_id: [_]} = errors_on(changeset)
    end

    test "validates deployed rule version when present" do
      invalid =
        PoolRulesetAssignment.changeset(%PoolRulesetAssignment{}, %{
          pool_id: Ecto.UUID.generate(),
          ruleset_id: Ecto.UUID.generate(),
          assigned_by: "tester",
          deployed_rule_version: 0
        })

      refute invalid.valid?
      assert %{deployed_rule_version: [_]} = errors_on(invalid)
    end
  end

  defp valid_rule_attrs(sid) do
    %{
      sid: sid,
      message: "ET TEST #{sid}",
      raw_text: ~s|alert ip any any -> any any (msg:"ET TEST #{sid}"; sid:#{sid}; rev:1;)|,
      category: "emerging-test",
      classtype: "trojan-activity"
    }
  end

  defp insert_pool!(name) do
    %SensorPool{}
    |> SensorPool.create_changeset(%{name: name}, "tester")
    |> Repo.insert!()
  end

  defp insert_ruleset!(name) do
    %Ruleset{}
    |> Ruleset.create_changeset(%{name: name}, "tester")
    |> Repo.insert!()
  end

  defp assignment_insert(attrs) do
    %PoolRulesetAssignment{}
    |> PoolRulesetAssignment.changeset(attrs)
    |> Repo.insert()
  end

  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
