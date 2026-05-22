defmodule ConfigManager.Rules.Compiler do
  @moduledoc "Compiles rulesets into Sensor Agent rule bundle files."

  alias ConfigManager.Rules

  def compile(ruleset_id) do
    case Rules.get_ruleset(ruleset_id) do
      nil ->
        {:error, :ruleset_not_found}

      ruleset ->
        compile_ruleset(ruleset)
    end
  end

  defp compile_ruleset(ruleset) do
    rules = Rules.effective_rules(ruleset)

    if rules == [] do
      {:error, :empty_ruleset}
    else
      categories = MapSet.new(ruleset.categories || [])
      explicit_includes = include_sids(ruleset)

      files =
        rules
        |> Enum.group_by(&filename_for_rule(&1, categories, explicit_includes))
        |> Enum.map(fn {filename, grouped_rules} ->
          content =
            grouped_rules
            |> Enum.sort_by(& &1.sid)
            |> Enum.map_join("\n", & &1.raw_text)

          {filename, content <> "\n"}
        end)
        |> Map.new()

      {:ok, files}
    end
  end

  defp filename_for_rule(rule, categories, explicit_includes) do
    cond do
      MapSet.member?(categories, rule.category) ->
        "#{rule.category}.rules"

      MapSet.member?(explicit_includes, rule.sid) ->
        "local-overrides.rules"

      true ->
        "#{rule.category}.rules"
    end
  end

  defp include_sids(ruleset) do
    ruleset.overrides
    |> Enum.filter(&(&1.action == "include"))
    |> Enum.map(& &1.sid)
    |> MapSet.new()
  end
end
