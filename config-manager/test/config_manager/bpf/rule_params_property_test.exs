defmodule ConfigManager.Bpf.RuleParamsPropertyTest do
  @moduledoc "Property coverage for BPF structured rule parameter validation."

  use ExUnit.Case, async: true
  use PropCheck

  alias ConfigManager.Bpf.RuleParams

  property "Property 1: Rule parameter validation enforces type-specific constraints",
           [:verbose, numtests: 80] do
    forall code <- integer(0, 10_000) do
      {rule_type, params, expected_valid?} = rule_validation_case(code)

      ok?(RuleParams.validate(rule_type, params)) == expected_valid?
    end
  end

  property "Property 2: CIDR and port validation accepts exactly valid generated values",
           [:verbose, numtests: 80] do
    forall code <- integer(0, 100_000) do
      {cidr, expected_cidr_valid?} = cidr_case(code)
      port = rem(code, 70_000) - 1_000
      start_port = rem(code * 3, 70_000) - 1_000
      end_port = range_end(start_port, code)

      ok?(RuleParams.validate_cidr(cidr)) == expected_cidr_valid? and
        ok?(RuleParams.validate_port(port)) == valid_port?(port) and
        ok?(RuleParams.validate_port_range(start_port, end_port)) ==
          (valid_port?(start_port) and valid_port?(end_port) and start_port <= end_port)
    end
  end

  defp rule_validation_case(code) do
    case rem(code, 10) do
      0 ->
        {"elephant_flow",
         %{"src_cidr" => ipv4_cidr(code), "port" => valid_port(code), "protocol" => "tcp"}, true}

      1 ->
        {"elephant_flow", %{}, false}

      2 ->
        {"elephant_flow", %{"src_cidr" => "not-a-cidr", "port" => valid_port(code)}, false}

      3 ->
        {"cidr_pair", %{"src_cidr" => ipv4_cidr(code), "dst_cidr" => ipv6_cidr(code)}, true}

      4 ->
        {"cidr_pair", %{"src_cidr" => ipv4_cidr(code)}, false}

      5 ->
        {"cidr_pair", %{"src_cidr" => ipv4_cidr(code), "dst_cidr" => "192.168.1.1"}, false}

      6 ->
        start_port = valid_port(code)
        {"port_exclusion", %{"port" => start_port, "port_end" => start_port + 1}, true}

      7 ->
        {"port_exclusion", %{"protocol" => "udp"}, false}

      8 ->
        start_port = valid_port(code) + 1
        {"port_exclusion", %{"port" => start_port, "port_end" => start_port - 1}, false}

      9 ->
        {"unknown", %{"port" => valid_port(code)}, false}
    end
  end

  defp cidr_case(code) do
    case rem(code, 6) do
      0 -> {ipv4_cidr(code), true}
      1 -> {ipv6_cidr(code), true}
      2 -> {"10.0.0.0/#{33 + rem(code, 20)}", false}
      3 -> {"2001:db8::/#{129 + rem(code, 20)}", false}
      4 -> {"10.0.0.1", false}
      5 -> {"not-a-cidr/#{rem(code, 32)}", false}
    end
  end

  defp range_end(start_port, code) do
    if rem(code, 2) == 0 do
      start_port + rem(code, 100)
    else
      start_port - rem(code, 100) - 1
    end
  end

  defp ipv4_cidr(code), do: "10.#{rem(code, 256)}.0.0/#{rem(code, 33)}"
  defp ipv6_cidr(code), do: "2001:db8::/#{rem(code, 129)}"
  defp valid_port(code), do: rem(code, 65_534) + 1
  defp valid_port?(port), do: is_integer(port) and port >= 1 and port <= 65_535
  defp ok?(:ok), do: true
  defp ok?({:error, _message}), do: false
end
