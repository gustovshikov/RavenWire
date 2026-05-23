defmodule ConfigManager.Bpf.RBACPropertyTest do
  @moduledoc "Property coverage for BPF write permission mapping."

  use ExUnit.Case, async: true
  use PropCheck

  alias ConfigManager.Auth.Policy

  @bpf_manager_roles MapSet.new(["sensor-operator", "rule-manager", "platform-admin"])

  property "Property 12: RBAC allows BPF write actions only for bpf:manage roles",
           [:verbose, numtests: 40] do
    forall code <- integer(0, 1_000) do
      role = Enum.at(Policy.roles(), rem(code, length(Policy.roles())))
      expected_allowed? = MapSet.member?(@bpf_manager_roles, role)

      Policy.has_permission?(role, "bpf:manage") == expected_allowed? and
        Policy.has_permission?(role, "sensors:view")
    end
  end
end
