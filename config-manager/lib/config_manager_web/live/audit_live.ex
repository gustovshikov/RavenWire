defmodule ConfigManagerWeb.AuditLive do
  @moduledoc "Basic audit log browser."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.{Audit, Auth}

  @impl true
  def mount(_params, _session, socket) do
    users = Auth.list_users()

    {:ok,
     assign(socket,
       entries: Audit.list_entries(page_size: 50),
       users_by_id: Map.new(users, &{&1.id, &1}),
       users_by_username: Map.new(users, &{&1.username, &1})
     )}
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
                <td class="px-4 py-3 text-gray-800"><%= format_actor(entry, @users_by_username) %></td>
                <td class="px-4 py-3 text-gray-800"><%= entry.action %></td>
                <td class="px-4 py-3 text-gray-600"><%= format_target(entry, @users_by_id) %></td>
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

  defp format_actor(%{actor_type: "user", actor: actor}, users_by_username) do
    case Map.get(users_by_username, actor) do
      nil -> actor || "—"
      user -> format_user(user)
    end
  end

  defp format_actor(%{actor: actor}, _users_by_username), do: actor || "—"

  defp format_target(%{target_type: "user", target_id: target_id}, users_by_id) do
    case Map.get(users_by_id, target_id) do
      nil -> "user:#{target_id || "—"}"
      user -> format_user(user)
    end
  end

  defp format_target(%{target_type: nil, target_id: nil}, _users_by_id), do: "—"

  defp format_target(%{target_type: target_type, target_id: target_id}, _users_by_id) do
    "#{target_type || "—"}:#{target_id || "—"}"
  end

  defp format_user(user) do
    name = user.display_name || user.username

    if name == user.username do
      user.username
    else
      "#{name} (#{user.username})"
    end
  end
end
