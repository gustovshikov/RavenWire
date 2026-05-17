defmodule ConfigManager.Rules.TogglePropTest do
  @moduledoc "Property coverage for rule and category toggle behavior."

  use ExUnit.Case, async: false
  use PropCheck

  alias ConfigManager.Rules
  alias ConfigManager.Rules.SuricataRule
  alias ConfigManager.{AuditEntry, Repo}

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    :ok
  end

  property "Property 3: Rule toggle is its own inverse",
           [:verbose, numtests: 50] do
    forall code <- integer(1, 500_000) do
      reset_rules!()

      enabled = rem(code, 2) == 0
      rule = insert_rule!(code, "toggle-prop", enabled)
      original = Map.take(rule, [:sid, :raw_text, :category, :revision])

      {:ok, toggled} = Rules.toggle_rule(rule, "property-operator")
      {:ok, restored} = Rules.toggle_rule(toggled, "property-operator")

      toggled.enabled == !enabled and
        restored.enabled == enabled and
        Map.take(toggled, [:sid, :raw_text, :category, :revision]) == original and
        Map.take(restored, [:sid, :raw_text, :category, :revision]) == original
    end
  end

  property "Property 4: Category toggle affects exactly the rules in that category",
           [:verbose, numtests: 50] do
    forall code <- integer(1, 100_000) do
      reset_rules!()

      category = "category-prop-#{code}"
      other_category = "other-category-prop-#{code}"
      category_count = rem(code, 4) + 1

      category_rules =
        1..category_count
        |> Enum.map(fn index ->
          insert_rule!(code * 10 + index, category, rem(index, 2) == 0)
        end)

      other_rules =
        1..3
        |> Enum.map(fn index ->
          insert_rule!(code * 10 + 100 + index, other_category, rem(index, 2) == 0)
        end)

      other_states = Map.new(other_rules, &{&1.id, &1.enabled})

      {:ok, affected_count} = Rules.toggle_category(category, false, "property-operator")

      reloaded_category_rules = Enum.map(category_rules, &Repo.get!(SuricataRule, &1.id))
      reloaded_other_rules = Enum.map(other_rules, &Repo.get!(SuricataRule, &1.id))

      affected_count == category_count and
        Enum.all?(reloaded_category_rules, &(&1.enabled == false)) and
        Enum.all?(reloaded_other_rules, &(&1.enabled == Map.fetch!(other_states, &1.id)))
    end
  end

  defp reset_rules! do
    Repo.delete_all(AuditEntry)
    Repo.delete_all(SuricataRule)
  end

  defp insert_rule!(sid, category, enabled) do
    attrs = %{
      sid: sid,
      message: "Property rule #{sid}",
      raw_text: ~s|alert ip any any -> any any (msg:"Property rule #{sid}"; sid:#{sid}; rev:1;)|,
      category: category,
      revision: 1,
      severity: 2,
      enabled: enabled
    }

    %SuricataRule{}
    |> SuricataRule.changeset(attrs)
    |> Repo.insert!()
  end
end
