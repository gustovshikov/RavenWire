defmodule ConfigManager.Bpf.ExpressionGeneratorTest do
  use ExUnit.Case, async: true

  alias ConfigManager.Bpf.ExpressionGenerator

  test "generates clauses for each structured rule type" do
    assert ExpressionGenerator.rule_to_clause(%{
             rule_type: "cidr_pair",
             params: %{"src_cidr" => "10.0.0.0/8", "dst_cidr" => "192.168.0.0/16"}
           }) == "not (src net 10.0.0.0/8 and dst net 192.168.0.0/16)"

    assert ExpressionGenerator.rule_to_clause(%{
             rule_type: "port_exclusion",
             params: %{"port" => 1000, "port_end" => 2000, "protocol" => "udp"}
           }) == "not (portrange 1000-2000 and udp)"

    assert ExpressionGenerator.rule_to_clause(%{
             rule_type: "elephant_flow",
             params: %{"src_cidr" => "10.0.0.0/8", "port" => 443, "protocol" => "tcp"}
           }) == "not (src net 10.0.0.0/8 and port 443 and tcp)"
  end

  test "append mode respects enabled state and position order" do
    rules = [
      %{rule_type: "port_exclusion", params: %{"port" => 443}, enabled: true, position: 2},
      %{
        rule_type: "port_exclusion",
        params: %{"port" => 53, "protocol" => "udp"},
        enabled: false,
        position: 1
      },
      %{
        rule_type: "cidr_pair",
        params: %{"src_cidr" => "10.0.0.0/8", "dst_cidr" => "192.168.0.0/16"},
        enabled: true,
        position: 0
      }
    ]

    assert ExpressionGenerator.generate(rules, "tcp", "append") ==
             "not (src net 10.0.0.0/8 and dst net 192.168.0.0/16) and not (port 443) and (tcp)"
  end

  test "replace mode ignores structured rules and empty config returns no filter" do
    rules = [%{rule_type: "port_exclusion", params: %{"port" => 443}, enabled: true, position: 0}]

    assert ExpressionGenerator.generate(rules, "udp", "replace") == "udp"
    assert ExpressionGenerator.generate(rules, "  ", "replace") == ""
    assert ExpressionGenerator.generate([], nil, "append") == ""
  end
end
