defmodule ConfigManagerWeb.AdminLive.RolesLive do
  @moduledoc "Read-only role and permission reference."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.Auth.Policy

  @impl true
  def mount(_params, _session, socket) do
    roles =
      Policy.roles()
      |> Enum.sort()
      |> Enum.map(fn role ->
        %{
          id: role,
          label: Policy.role_display_name(role),
          permissions: Policy.permissions_for(role)
        }
      end)

    {:ok, assign(socket, roles: roles, permissions: Policy.canonical_permissions())}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <div class="mb-6 flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Role Reference</h1>
          <p class="mt-1 text-sm text-gray-500">Canonical RBAC roles and permissions used by browser routes, LiveView events, and API tokens.</p>
        </div>
        <div class="flex items-center gap-3 text-sm">
          <a href="/admin/users" class="text-blue-600 hover:underline">Users</a>
          <a href="/admin/api-tokens" class="text-blue-600 hover:underline">API Tokens</a>
        </div>
      </div>

      <section class="overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-gray-200 bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <th class="px-4 py-3 font-medium">Role</th>
              <th class="px-4 py-3 font-medium">Permissions</th>
            </tr>
          </thead>
          <tbody>
            <%= for role <- @roles do %>
              <tr class="border-b border-gray-100 align-top last:border-0">
                <td class="w-56 px-4 py-4">
                  <div class="font-semibold text-gray-900"><%= role.label %></div>
                  <code class="text-xs text-gray-500"><%= role.id %></code>
                </td>
                <td class="px-4 py-4">
                  <div class="flex flex-wrap gap-2">
                    <%= for permission <- role.permissions do %>
                      <span class="rounded bg-gray-100 px-2 py-1 font-mono text-xs text-gray-700">
                        <%= permission %>
                      </span>
                    <% end %>
                  </div>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </section>

      <section class="mt-8 rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
        <h2 class="mb-3 text-lg font-semibold text-gray-900">Canonical Permission Catalog</h2>
        <div class="grid grid-cols-1 gap-2 md:grid-cols-2 lg:grid-cols-3">
          <%= for permission <- @permissions do %>
            <code class="rounded bg-gray-50 px-3 py-2 text-xs text-gray-700"><%= permission %></code>
          <% end %>
        </div>
      </section>
    </div>
    """
  end
end
