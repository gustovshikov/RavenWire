defmodule ConfigManager.Auth.Policy do
  @moduledoc "Code-defined RavenWire role and permission policy."

  @canonical_permissions ~w(
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
  )

  @viewer ~w(dashboard:view sensors:view audit:view)
  @analyst @viewer ++ ~w(pcap:search pcap:download)

  @sensor_operator @analyst ++
                     ~w(
                       sensor:operate
                       enrollment:manage
                       pcap:configure
                       pools:manage
                       deployments:manage
                       forwarding:manage
                       bpf:manage
                       alerts:manage
                       bundle:download
                     )

  @rule_manager @sensor_operator ++ ~w(rules:deploy rules:manage)

  @roles_permissions %{
    "viewer" => @viewer,
    "analyst" => @analyst,
    "sensor-operator" => @sensor_operator,
    "rule-manager" => @rule_manager,
    "platform-admin" => @canonical_permissions,
    "auditor" => ~w(dashboard:view sensors:view audit:view audit:export)
  }

  def roles, do: Map.keys(@roles_permissions)
  def canonical_permissions, do: @canonical_permissions
  def permissions_for("alerts:view"), do: permissions_for("sensors:view")
  def permissions_for(role), do: Map.get(@roles_permissions, role, [])

  def valid_role?(role), do: role in roles()
  def valid_permission?(permission), do: permission in @canonical_permissions

  def has_permission?(role, "alerts:view"), do: has_permission?(role, "sensors:view")
  def has_permission?(role, permission), do: permission in permissions_for(role)

  def role_display_name(role) do
    role
    |> String.replace("-", " ")
    |> String.split(" ")
    |> Enum.map_join(" ", &String.capitalize/1)
  end

  def permission_display_name(permission), do: String.replace(permission, ":", ": ")
end
