defmodule ConfigManagerWeb.PoolLive.HelpersTest do
  use ExUnit.Case, async: true

  alias ConfigManagerWeb.PoolLive.Helpers

  test "can_manage_pools? follows role permissions" do
    refute Helpers.can_manage_pools?(nil)
    refute Helpers.can_manage_pools?(%{role: "viewer"})
    assert Helpers.can_manage_pools?(%{role: "platform-admin"})
  end

  test "can_manage_deployments? follows role permissions" do
    refute Helpers.can_manage_deployments?(nil)
    refute Helpers.can_manage_deployments?(%{role: "viewer"})
    assert Helpers.can_manage_deployments?(%{role: "sensor-operator"})
    assert Helpers.can_manage_deployments?(%{role: "platform-admin"})
  end

  test "formats capture modes and severities with nil-safe fallback" do
    assert Helpers.format_capture_mode("alert_driven") == "Alert Driven"
    assert Helpers.format_capture_mode("full_pcap") == "Full PCAP"
    assert Helpers.format_capture_mode(nil) == "—"

    assert Helpers.format_severity(1) == "1 - low"
    assert Helpers.format_severity(2) == "2 - medium"
    assert Helpers.format_severity(3) == "3 - high"
    assert Helpers.format_severity(nil) == "—"
  end
end
