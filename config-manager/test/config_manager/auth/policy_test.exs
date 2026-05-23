defmodule ConfigManager.Auth.PolicyTest do
  use ExUnit.Case, async: true

  alias ConfigManager.Auth.Policy

  @expected_permissions %{
    "viewer" => ~w(dashboard:view sensors:view audit:view),
    "analyst" => ~w(dashboard:view sensors:view audit:view pcap:search pcap:download),
    "sensor-operator" => ~w(
        dashboard:view
        sensors:view
        audit:view
        pcap:search
        pcap:download
        sensor:operate
        enrollment:manage
        pcap:configure
        pools:manage
        deployments:manage
        forwarding:manage
        bpf:manage
        alerts:manage
        bundle:download
      ),
    "rule-manager" => ~w(
        dashboard:view
        sensors:view
        audit:view
        pcap:search
        pcap:download
        sensor:operate
        enrollment:manage
        pcap:configure
        pools:manage
        deployments:manage
        forwarding:manage
        bpf:manage
        alerts:manage
        bundle:download
        rules:deploy
        rules:manage
      ),
    "platform-admin" => ~w(
        dashboard:view
        sensors:view
        sensor:operate
        enrollment:manage
        pcap:configure
        pcap:search
        pcap:download
        pools:manage
        deployments:manage
        rules:deploy
        rules:manage
        forwarding:manage
        bpf:manage
        alerts:manage
        bundle:download
        audit:view
        audit:export
        users:manage
        roles:view
        tokens:manage
        system:manage
      ),
    "auditor" => ~w(dashboard:view sensors:view audit:view audit:export)
  }

  test "role permission mapping matches the canonical specification exactly" do
    for {role, expected} <- @expected_permissions do
      assert MapSet.new(Policy.permissions_for(role)) == MapSet.new(expected)
    end
  end

  test "operator hierarchy is strictly additive through rule manager" do
    viewer = MapSet.new(Policy.permissions_for("viewer"))
    analyst = MapSet.new(Policy.permissions_for("analyst"))
    operator = MapSet.new(Policy.permissions_for("sensor-operator"))
    rule_manager = MapSet.new(Policy.permissions_for("rule-manager"))

    assert MapSet.subset?(viewer, analyst)
    assert MapSet.subset?(analyst, operator)
    assert MapSet.subset?(operator, rule_manager)

    assert MapSet.size(viewer) < MapSet.size(analyst)
    assert MapSet.size(analyst) < MapSet.size(operator)
    assert MapSet.size(operator) < MapSet.size(rule_manager)
  end

  test "platform admin has every canonical permission" do
    for permission <- Policy.canonical_permissions() do
      assert Policy.has_permission?("platform-admin", permission)
      assert Policy.valid_permission?(permission)
    end
  end

  test "forwarding management is canonical and limited to operator roles" do
    assert "forwarding:manage" in Policy.canonical_permissions()

    assert MapSet.new(Policy.permissions_for("platform-admin")) ==
             MapSet.new(Policy.canonical_permissions())

    for role <- ["sensor-operator", "rule-manager", "platform-admin"] do
      assert Policy.has_permission?(role, "forwarding:manage")
    end

    for role <- ["viewer", "analyst", "auditor"] do
      refute Policy.has_permission?(role, "forwarding:manage")
    end
  end

  test "auditor is read-only for audit and sensors" do
    assert Policy.has_permission?("auditor", "dashboard:view")
    assert Policy.has_permission?("auditor", "sensors:view")
    assert Policy.has_permission?("auditor", "audit:view")
    assert Policy.has_permission?("auditor", "audit:export")

    forbidden =
      ~w(
        sensor:operate
        enrollment:manage
        pcap:configure
        pcap:search
        pcap:download
        pools:manage
        deployments:manage
        rules:deploy
        rules:manage
        forwarding:manage
        bpf:manage
        alerts:manage
        bundle:download
        users:manage
        roles:view
        tokens:manage
        system:manage
      )

    for permission <- forbidden do
      refute Policy.has_permission?("auditor", permission)
    end
  end

  test "alerts view is only a sensors view alias" do
    assert Policy.has_permission?("viewer", "alerts:view")
    refute "alerts:view" in Policy.canonical_permissions()
  end
end
