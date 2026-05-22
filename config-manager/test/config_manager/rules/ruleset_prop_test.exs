defmodule ConfigManager.Rules.RulesetPropTest do
  @moduledoc "Property coverage for ruleset composition, uniqueness, versioning, and compilation."

  use ExUnit.Case, async: false
  use PropCheck

  alias ConfigManager.Rules
  alias ConfigManager.Rules.{Compiler, PoolRulesetAssignment, Ruleset, RulesetRule, SuricataRule}
  alias ConfigManager.{AuditEntry, Repo}

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    :ok
  end

  property "Property 5: Ruleset effective rule computation matches composition model",
           [:verbose, numtests: 40] do
    forall code <- integer(1, 100_000) do
      reset_ruleset_store!()

      malware = insert_rule!(sid(code, 1), "malware", true)
      exploit = insert_rule!(sid(code, 2), "exploit", true)
      local = insert_rule!(sid(code, 3), "local", true)
      disabled = insert_rule!(sid(code, 4), "malware", false)

      categories = if rem(code, 2) == 0, do: ["malware"], else: ["malware", "exploit"]

      {:ok, ruleset} =
        Rules.create_ruleset(%{name: "composition-#{code}", categories: categories}, "prop")

      {:ok, _include} = Rules.add_ruleset_override(ruleset, local.sid, "include", "prop")

      {:ok, _exclude} =
        Rules.add_ruleset_override(Repo.get!(Ruleset, ruleset.id), malware.sid, "exclude", "prop")

      expected =
        [malware, exploit, local, disabled]
        |> Enum.filter(& &1.enabled)
        |> Enum.filter(
          &((&1.category in categories or &1.sid == local.sid) and &1.sid != malware.sid)
        )
        |> Enum.map(& &1.sid)
        |> Enum.sort()

      actual =
        ruleset.id
        |> Rules.effective_rules()
        |> Enum.map(& &1.sid)

      actual == expected
    end
  end

  property "Property 6: Ruleset name uniqueness is case-insensitive",
           [:verbose, numtests: 25] do
    forall code <- integer(1, 100_000) do
      reset_ruleset_store!()
      name = "unique-ruleset-#{code}"

      {:ok, _ruleset} = Rules.create_ruleset(%{name: name}, "prop")
      before_count = Repo.aggregate(Ruleset, :count, :id)
      duplicate_result = Rules.create_ruleset(%{name: String.upcase(name)}, "prop")
      after_count = Repo.aggregate(Ruleset, :count, :id)

      match?({:error, _changeset}, duplicate_result) and before_count == after_count
    end
  end

  property "Property 7: Ruleset version increments only on content changes",
           [:verbose, numtests: 25] do
    forall code <- integer(1, 100_000) do
      reset_ruleset_store!()
      rule = insert_rule!(sid(code, 1), "local", true)

      {:ok, ruleset} =
        Rules.create_ruleset(%{name: "version-prop-#{code}", categories: ["malware"]}, "prop")

      {:ok, metadata} = Rules.update_ruleset(ruleset, %{description: "metadata only"}, "prop")

      {:ok, content} =
        Rules.update_ruleset(metadata, %{categories: ["malware", "exploit"]}, "prop")

      {:ok, _override} = Rules.add_ruleset_override(content, rule.sid, "include", "prop")
      override_version = Repo.get!(Ruleset, ruleset.id).version

      metadata.version == ruleset.version and
        content.version == ruleset.version + 1 and
        override_version == ruleset.version + 2
    end
  end

  property "Property 9: Ruleset compilation produces valid rule file map",
           [:verbose, numtests: 30] do
    forall code <- integer(1, 100_000) do
      reset_ruleset_store!()

      malware = insert_rule!(sid(code, 1), "malware", true)
      local = insert_rule!(sid(code, 2), "local", true)
      _disabled = insert_rule!(sid(code, 3), "malware", false)

      {:ok, ruleset} =
        Rules.create_ruleset(%{name: "compile-prop-#{code}", categories: ["malware"]}, "prop")

      {:ok, _include} = Rules.add_ruleset_override(ruleset, local.sid, "include", "prop")

      {:ok, files} = Compiler.compile(ruleset.id)

      compiled_sids =
        files
        |> Map.values()
        |> Enum.flat_map(&Regex.scan(~r/sid:(\d+);/, &1, capture: :all_but_first))
        |> Enum.map(fn [sid] -> String.to_integer(sid) end)

      expected_sids = [malware.sid, local.sid] |> Enum.sort()

      map_size(files) > 0 and
        Enum.all?(Map.keys(files), &String.ends_with?(&1, ".rules")) and
        Enum.all?(Map.values(files), &(&1 != "")) and
        Enum.sort(compiled_sids) == expected_sids and
        length(compiled_sids) == length(Enum.uniq(compiled_sids))
    end
  end

  defp reset_ruleset_store! do
    Repo.delete_all(AuditEntry)
    Repo.delete_all(PoolRulesetAssignment)
    Repo.delete_all(RulesetRule)
    Repo.delete_all(Ruleset)
    Repo.delete_all(SuricataRule)
  end

  defp insert_rule!(sid, category, enabled) do
    message = "Property rule #{sid}"

    %SuricataRule{}
    |> SuricataRule.changeset(%{
      sid: sid,
      message: message,
      raw_text:
        ~s|alert ip any any -> any any (msg:"#{message}"; classtype:trojan-activity; sid:#{sid}; rev:1;)|,
      category: category,
      classtype: "trojan-activity",
      severity: 2,
      revision: 1,
      enabled: enabled
    })
    |> Repo.insert!()
  end

  defp sid(code, index), do: 800_000 + code * 10 + index
end
