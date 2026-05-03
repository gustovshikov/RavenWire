defmodule ConfigManager.Auth.PolicyTest do
  use ExUnit.Case, async: true

  alias ConfigManager.Auth.Policy

  test "platform admin has every canonical permission" do
    for permission <- Policy.canonical_permissions() do
      assert Policy.has_permission?("platform-admin", permission)
    end
  end

  test "auditor is read-only for audit and sensors" do
    assert Policy.has_permission?("auditor", "dashboard:view")
    assert Policy.has_permission?("auditor", "sensors:view")
    assert Policy.has_permission?("auditor", "audit:view")
    assert Policy.has_permission?("auditor", "audit:export")
    refute Policy.has_permission?("auditor", "pcap:download")
    refute Policy.has_permission?("auditor", "users:manage")
  end

  test "alerts view is only a sensors view alias" do
    assert Policy.has_permission?("viewer", "alerts:view")
  end
end
