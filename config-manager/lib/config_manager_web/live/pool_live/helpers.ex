defmodule ConfigManagerWeb.PoolLive.Helpers do
  @moduledoc false

  import Phoenix.Component

  alias ConfigManager.Auth.Policy
  alias ConfigManagerWeb.Formatters

  def can_manage_pools?(nil), do: false
  def can_manage_pools?(user), do: Policy.has_permission?(user.role, "pools:manage")

  def pool_nav(assigns) do
    ~H"""
    <div class="mb-4 flex flex-wrap gap-3 text-sm">
      <a href={"/pools/#{@pool.id}"} class="text-blue-600 hover:underline">Overview</a>
      <a href={"/pools/#{@pool.id}/sensors"} class="text-blue-600 hover:underline">Sensors</a>
      <a href={"/pools/#{@pool.id}/config"} class="text-blue-600 hover:underline">Config</a>
      <a href={"/pools/#{@pool.id}/deployments"} class="text-blue-600 hover:underline">Deployments</a>
    </div>
    """
  end

  def field(assigns) do
    ~H"""
    <div>
      <dt class="text-xs font-medium uppercase text-gray-500"><%= @label %></dt>
      <dd class="mt-1 break-words text-gray-900"><%= Formatters.display(@value) %></dd>
    </div>
    """
  end

  def format_capture_mode("alert_driven"), do: "Alert Driven"
  def format_capture_mode("full_pcap"), do: "Full PCAP"
  def format_capture_mode(value), do: Formatters.display(value)

  def format_severity(1), do: "1 - low"
  def format_severity(2), do: "2 - medium"
  def format_severity(3), do: "3 - high"
  def format_severity(value), do: Formatters.display(value)
end
