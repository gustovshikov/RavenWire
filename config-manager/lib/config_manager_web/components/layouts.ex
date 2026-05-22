defmodule ConfigManagerWeb.Layouts do
  use ConfigManagerWeb, :html

  alias ConfigManager.Auth.Policy

  embed_templates("layouts/*")

  def nav_allowed?(%{role: role}, permission), do: Policy.has_permission?(role, permission)
  def nav_allowed?(_user, _permission), do: false
end
