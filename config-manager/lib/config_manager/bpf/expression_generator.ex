defmodule ConfigManager.Bpf.ExpressionGenerator do
  @moduledoc "Pure BPF expression generation from structured filter rules and raw BPF text."

  alias ConfigManager.Bpf.RuleParams

  def generate(_rules, raw_expression, "replace"), do: normalize_raw(raw_expression)

  def generate(rules, raw_expression, _composition_mode) do
    clauses =
      rules
      |> List.wrap()
      |> Enum.filter(&enabled?/1)
      |> Enum.sort_by(&position/1)
      |> Enum.map(&rule_to_clause/1)
      |> Enum.reject(&(&1 == ""))

    raw = normalize_raw(raw_expression)

    (clauses ++ raw_clause(raw))
    |> Enum.reject(&(&1 == ""))
    |> Enum.join(" and ")
  end

  def rule_to_clause(%{rule_type: "cidr_pair", params: params}) do
    params = RuleParams.normalize_params(params || %{})
    "not (src net #{params["src_cidr"]} and dst net #{params["dst_cidr"]})"
  end

  def rule_to_clause(%{rule_type: "elephant_flow", params: params}) do
    params = RuleParams.normalize_params(params || %{})

    params
    |> common_predicates([:src, :dst, :port, :protocol])
    |> exclusion_clause()
  end

  def rule_to_clause(%{rule_type: "port_exclusion", params: params}) do
    params = RuleParams.normalize_params(params || %{})

    params
    |> common_predicates([:port, :protocol])
    |> exclusion_clause()
  end

  def rule_to_clause(_rule), do: ""

  defp common_predicates(params, fields) do
    Enum.flat_map(fields, fn
      :src -> if present?(params["src_cidr"]), do: ["src net #{params["src_cidr"]}"], else: []
      :dst -> if present?(params["dst_cidr"]), do: ["dst net #{params["dst_cidr"]}"], else: []
      :port -> port_predicate(params)
      :protocol -> protocol_predicate(params)
    end)
  end

  defp port_predicate(params) do
    cond do
      present?(params["port"]) and present?(params["port_end"]) ->
        ["portrange #{params["port"]}-#{params["port_end"]}"]

      present?(params["port"]) ->
        ["port #{params["port"]}"]

      true ->
        []
    end
  end

  defp protocol_predicate(params) do
    case params["protocol"] do
      protocol when protocol in ["tcp", "udp"] -> [protocol]
      _other -> []
    end
  end

  defp exclusion_clause([]), do: ""
  defp exclusion_clause(predicates), do: "not (#{Enum.join(predicates, " and ")})"

  defp enabled?(%{enabled: false}), do: false
  defp enabled?(_rule), do: true

  defp position(%{position: position}) when is_integer(position), do: position
  defp position(_rule), do: 0

  defp raw_clause(""), do: []
  defp raw_clause(raw), do: ["(#{raw})"]

  defp normalize_raw(nil), do: ""
  defp normalize_raw(raw_expression), do: raw_expression |> to_string() |> String.trim()

  defp present?(nil), do: false
  defp present?(""), do: false
  defp present?(_value), do: true
end
