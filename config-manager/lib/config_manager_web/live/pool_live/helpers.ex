defmodule ConfigManagerWeb.PoolLive.Helpers do
  @moduledoc false

  import Phoenix.Component

  alias ConfigManager.{Bpf, Forwarding}
  alias ConfigManager.Auth.Policy
  alias ConfigManagerWeb.Formatters

  def can_manage_pools?(nil), do: false
  def can_manage_pools?(user), do: Policy.has_permission?(user.role, "pools:manage")

  def can_manage_deployments?(nil), do: false
  def can_manage_deployments?(user), do: Policy.has_permission?(user.role, "deployments:manage")

  def pool_nav(assigns) do
    assigns = assign(assigns, :bpf_summary, Bpf.bpf_summary(assigns.pool.id))
    assigns = assign(assigns, :forwarding_summary, Forwarding.forwarding_summary(assigns.pool.id))

    ~H"""
    <div class="mb-4 flex flex-wrap gap-3 text-sm">
      <a href={"/pools/#{@pool.id}"} class="text-blue-600 hover:underline">Overview</a>
      <a href={"/pools/#{@pool.id}/sensors"} class="text-blue-600 hover:underline">Sensors</a>
      <a href={"/pools/#{@pool.id}/config"} class="text-blue-600 hover:underline">Config</a>
      <a href={"/pools/#{@pool.id}/forwarding"} class="text-blue-600 hover:underline">
        Forwarding
        <%= if @forwarding_summary.sink_count > 0 do %>
          <span class="ml-1 rounded bg-blue-100 px-1.5 py-0.5 text-xs font-medium text-blue-800"><%= @forwarding_summary.enabled_count %>/<%= @forwarding_summary.sink_count %></span>
        <% end %>
      </a>
      <a href={"/pools/#{@pool.id}/bpf"} class="text-blue-600 hover:underline">
        BPF Filters
        <%= if @bpf_summary.pending_deployment do %>
          <span class="ml-1 rounded bg-yellow-100 px-1.5 py-0.5 text-xs font-medium text-yellow-800">pending</span>
        <% end %>
      </a>
      <a href={"/pools/#{@pool.id}/deployments"} class="text-blue-600 hover:underline">Deployments</a>
      <a href={"/pools/#{@pool.id}/drift"} class="text-blue-600 hover:underline">Drift</a>
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
