defmodule ConfigManagerWeb.AuditLive do
  @moduledoc "Basic audit log browser."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.Audit

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, entries: Audit.list_entries(page_size: 50))}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold text-gray-900">Audit Log</h1>
      </div>

      <div class="bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-xs text-gray-500 uppercase tracking-wide bg-gray-50 border-b border-gray-200">
              <th class="px-4 py-3 font-medium">Timestamp</th>
              <th class="px-4 py-3 font-medium">Actor</th>
              <th class="px-4 py-3 font-medium">Action</th>
              <th class="px-4 py-3 font-medium">Target</th>
              <th class="px-4 py-3 font-medium">Result</th>
            </tr>
          </thead>
          <tbody>
            <%= for entry <- @entries do %>
              <tr class="border-b border-gray-100 last:border-0">
                <td class="px-4 py-3 text-gray-600 whitespace-nowrap"><%= format_dt(entry.timestamp) %></td>
                <td class="px-4 py-3 font-mono text-gray-800"><%= entry.actor %></td>
                <td class="px-4 py-3 text-gray-800"><%= entry.action %></td>
                <td class="px-4 py-3 text-gray-600"><%= entry.target_type || "—" %>:<%= entry.target_id || "—" %></td>
                <td class="px-4 py-3"><%= entry.result %></td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </div>
    </div>
    """
  end

  defp format_dt(nil), do: "—"
  defp format_dt(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
end
