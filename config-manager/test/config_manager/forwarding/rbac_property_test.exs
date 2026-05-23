defmodule ConfigManager.Forwarding.RBACPropertyTest do
  @moduledoc "Property coverage for forwarding write permission mapping."

  use ExUnit.Case, async: true
  use PropCheck

  alias ConfigManager.Auth.Policy

  @forwarding_manager_roles MapSet.new(["sensor-operator", "rule-manager", "platform-admin"])
  @forwarding_write_actions [
    :create_sink,
    :update_sink,
    :delete_sink,
    :toggle_sink,
    :test_connection,
    :update_schema_mode,
    :reveal_secret
  ]

  property "Property 1: RBAC allows forwarding write actions only for forwarding:manage roles",
           [:verbose, numtests: 40] do
    forall code <- integer(0, 10_000) do
      roles = Policy.roles()
      role = Enum.at(roles, rem(code, length(roles)))

      action =
        Enum.at(
          @forwarding_write_actions,
          rem(div(code, length(roles)), length(@forwarding_write_actions))
        )

      expected_allowed? = MapSet.member?(@forwarding_manager_roles, role)

      required_permission(action) == "forwarding:manage" and
        Policy.valid_permission?(required_permission(action)) and
        Policy.has_permission?(role, required_permission(action)) == expected_allowed?
    end
  end

  defp required_permission(action) when action in @forwarding_write_actions,
    do: "forwarding:manage"
end
