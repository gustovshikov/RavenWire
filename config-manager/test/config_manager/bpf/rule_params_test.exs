defmodule ConfigManager.Bpf.RuleParamsTest do
  use ExUnit.Case, async: true

  alias ConfigManager.Bpf.RuleParams

  test "validates IPv4 and IPv6 CIDR notation" do
    assert :ok = RuleParams.validate_cidr("10.0.0.0/8")
    assert :ok = RuleParams.validate_cidr("2001:db8::/32")

    assert {:error, _} = RuleParams.validate_cidr("10.0.0.1")
    assert {:error, _} = RuleParams.validate_cidr("10.0.0.0/33")
    assert {:error, _} = RuleParams.validate_cidr("2001:db8::/129")
  end

  test "validates ports and ranges" do
    assert :ok = RuleParams.validate_port(1)
    assert :ok = RuleParams.validate_port("65535")
    assert {:error, _} = RuleParams.validate_port(0)
    assert {:error, _} = RuleParams.validate_port(65_536)

    assert :ok = RuleParams.validate_port_range(1000, 2000)
    assert {:error, _} = RuleParams.validate_port_range(2000, 1000)
  end

  test "validates type-specific rule params" do
    assert :ok =
             RuleParams.validate("elephant_flow", %{
               "src_cidr" => "10.0.0.0/8",
               "port" => 443,
               "protocol" => "tcp"
             })

    assert {:error, _} = RuleParams.validate("elephant_flow", %{})

    assert :ok =
             RuleParams.validate("cidr_pair", %{
               "src_cidr" => "10.0.0.0/8",
               "dst_cidr" => "172.16.0.0/12"
             })

    assert {:error, _} = RuleParams.validate("cidr_pair", %{"src_cidr" => "10.0.0.0/8"})
    assert :ok = RuleParams.validate("port_exclusion", %{"port" => 53, "protocol" => "udp"})
    assert {:error, _} = RuleParams.validate("port_exclusion", %{"protocol" => "udp"})
    assert {:error, _} = RuleParams.validate("unknown", %{})
  end
end
