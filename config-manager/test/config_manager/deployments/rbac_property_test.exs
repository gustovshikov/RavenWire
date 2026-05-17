defmodule ConfigManager.Deployments.RBACPropertyTest do
  @moduledoc "Property coverage for deployment write permission mapping."

  use ExUnit.Case, async: true
  use PropCheck

  alias ConfigManager.Auth.Policy
  alias ConfigManagerWeb.DeploymentLive.Helpers

  @deployment_manager_roles MapSet.new(["sensor-operator", "rule-manager", "platform-admin"])

  property "Property 16: RBAC allows deployment write actions only for deployments:manage roles",
           [:verbose, numtests: 40] do
    forall code <- integer(0, 1_000) do
      role = Enum.at(Policy.roles(), rem(code, length(Policy.roles())))
      expected_allowed? = MapSet.member?(@deployment_manager_roles, role)

      Policy.has_permission?(role, "deployments:manage") == expected_allowed? and
        Helpers.can_manage_deployments?(%{role: role}) == expected_allowed?
    end
  end
end
