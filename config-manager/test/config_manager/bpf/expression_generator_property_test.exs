defmodule ConfigManager.Bpf.ExpressionGeneratorPropertyTest do
  @moduledoc "Property coverage for BPF expression generation and compiler handoff."

  use ExUnit.Case, async: false
  use PropCheck

  alias ConfigManager.Bpf.{Compiler, ExpressionGenerator}

  property "Property 3: Expression generation respects enabled state and rule order",
           [:verbose, numtests: 80] do
    forall code <- integer(0, 10_000) do
      rules = rules_for(code)

      ExpressionGenerator.generate(rules, nil, "append") == expected_append_expression(rules, nil)
    end
  end

  property "Property 4: Composition mode determines expression structure",
           [:verbose, numtests: 80] do
    forall code <- integer(0, 10_000) do
      rules = rules_for(code)
      raw_expression = raw_expression(code)

      ExpressionGenerator.generate(rules, raw_expression, "append") ==
        expected_append_expression(rules, raw_expression) and
        ExpressionGenerator.generate(rules, raw_expression, "replace") ==
          normalize_raw(raw_expression)
    end
  end

  property "Property 6: Clause generation produces correct BPF syntax per rule type",
           [:verbose, numtests: 80] do
    forall code <- integer(0, 10_000) do
      {rule, expected_clause} = clause_case(code)

      ExpressionGenerator.rule_to_clause(rule) == expected_clause and
        balanced_parentheses?(expected_clause) and
        not String.contains?(expected_clause, "nil")
    end
  end

  property "Property 5: Generated expressions round-trip through the compiler path",
           [:verbose, numtests: 40] do
    forall code <- integer(0, 10_000) do
      expression =
        code
        |> rules_for()
        |> ExpressionGenerator.generate(raw_expression(code), composition_mode(code))

      if expression == "" do
        true
      else
        Compiler.compile(expression, compiler: &syntactic_compile/1) ==
          {:ok, %{instruction_count: synthetic_instruction_count(expression)}}
      end
    end
  end

  defp rules_for(code) do
    [
      %{
        rule_type: "port_exclusion",
        params: %{"port" => 1000 + rem(code, 200), "protocol" => "tcp"},
        enabled: enabled?(code, 0),
        position: 3
      },
      %{
        rule_type: "cidr_pair",
        params: %{"src_cidr" => "10.0.0.0/8", "dst_cidr" => "192.168.0.0/16"},
        enabled: enabled?(code, 1),
        position: 1
      },
      %{
        rule_type: "elephant_flow",
        params: %{"src_cidr" => "172.16.0.0/12", "port" => 2000 + rem(code, 100)},
        enabled: enabled?(code, 2),
        position: 2
      },
      %{
        rule_type: "port_exclusion",
        params: %{"port" => 53, "protocol" => "udp"},
        enabled: enabled?(code, 3),
        position: 0
      }
    ]
  end

  defp expected_append_expression(rules, raw_expression) do
    raw = normalize_raw(raw_expression)

    rules
    |> Enum.filter(& &1.enabled)
    |> Enum.sort_by(& &1.position)
    |> Enum.map(&ExpressionGenerator.rule_to_clause/1)
    |> append_raw(raw)
    |> Enum.reject(&(&1 == ""))
    |> Enum.join(" and ")
  end

  defp append_raw(clauses, ""), do: clauses
  defp append_raw(clauses, raw), do: clauses ++ ["(#{raw})"]

  defp clause_case(code) do
    case rem(code, 3) do
      0 ->
        rule = %{
          rule_type: "cidr_pair",
          params: %{"src_cidr" => "10.#{rem(code, 256)}.0.0/16", "dst_cidr" => "192.168.0.0/16"}
        }

        {rule, "not (src net #{rule.params["src_cidr"]} and dst net #{rule.params["dst_cidr"]})"}

      1 ->
        port = 1000 + rem(code, 1000)
        rule = %{rule_type: "port_exclusion", params: %{"port" => port, "protocol" => "tcp"}}
        {rule, "not (port #{port} and tcp)"}

      2 ->
        port = 2000 + rem(code, 1000)

        rule = %{
          rule_type: "elephant_flow",
          params: %{"src_cidr" => "172.16.0.0/12", "port" => port, "protocol" => "udp"}
        }

        {rule, "not (src net 172.16.0.0/12 and port #{port} and udp)"}
    end
  end

  defp syntactic_compile(expression) do
    if balanced_parentheses?(expression) and not String.contains?(expression, "nil") do
      {:ok, %{instruction_count: synthetic_instruction_count(expression)}}
    else
      {:error, %{message: "invalid generated expression"}}
    end
  end

  defp synthetic_instruction_count(expression) do
    expression
    |> String.split(" and ", trim: true)
    |> length()
  end

  defp balanced_parentheses?(expression) do
    expression
    |> String.graphemes()
    |> Enum.reduce_while(0, fn
      "(", depth -> {:cont, depth + 1}
      ")", 0 -> {:halt, :invalid}
      ")", depth -> {:cont, depth - 1}
      _char, depth -> {:cont, depth}
    end)
    |> Kernel.==(0)
  end

  defp raw_expression(code) do
    case rem(code, 4) do
      0 -> nil
      1 -> ""
      2 -> " tcp "
      3 -> "udp"
    end
  end

  defp composition_mode(code), do: Enum.at(["append", "replace"], rem(code, 2))
  defp normalize_raw(nil), do: ""
  defp normalize_raw(raw), do: raw |> to_string() |> String.trim()
  defp enabled?(code, bit), do: Bitwise.band(code, Bitwise.bsl(1, bit)) != 0
end
