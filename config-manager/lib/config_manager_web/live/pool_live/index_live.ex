defmodule ConfigManagerWeb.PoolLive.IndexLive do
  @moduledoc "Sensor pool list page."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.PoolLive.Helpers
  alias ConfigManager.Pools
  alias ConfigManagerWeb.Formatters

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pools")

    {:ok, assign(socket, page_title: "Sensor Pools", pools: Pools.list_pools())}
  end

  @impl true
  def handle_info(_message, socket) do
    {:noreply, assign(socket, pools: Pools.list_pools())}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <div class="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Sensor Pools</h1>
          <p class="text-sm text-gray-500">Organize sensors into shared configuration groups.</p>
        </div>
        <%= if can_manage_pools?(@current_user) do %>
          <a href="/pools/new" class="w-fit rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">Create Pool</a>
        <% end %>
      </div>

      <%= if @pools == [] do %>
        <section class="rounded border border-gray-200 bg-white p-8 text-center">
          <h2 class="text-lg font-semibold text-gray-900">No pools have been created.</h2>
          <p class="mt-1 text-sm text-gray-600">Create a pool to group sensors and define shared desired configuration.</p>
        </section>
      <% else %>
        <section class="overflow-hidden rounded border border-gray-200 bg-white">
          <table class="w-full text-left text-sm">
            <thead>
              <tr class="border-b border-gray-200 bg-gray-50 text-xs uppercase text-gray-500">
                <th class="px-4 py-3 font-medium">Name</th>
                <th class="px-4 py-3 font-medium">Capture Mode</th>
                <th class="px-4 py-3 font-medium">Members</th>
                <th class="px-4 py-3 font-medium">Config Version</th>
                <th class="px-4 py-3 font-medium">Last Updated</th>
                <th class="px-4 py-3 font-medium">Updated By</th>
              </tr>
            </thead>
            <tbody>
              <%= for %{pool: pool, member_count: member_count} <- @pools do %>
                <tr class="border-b border-gray-100 last:border-0 hover:bg-gray-50">
                  <th class="px-4 py-3 font-medium">
                    <a href={"/pools/#{pool.id}"} class="text-blue-700 hover:underline"><%= pool.name %></a>
                  </th>
                  <td class="px-4 py-3"><%= format_capture_mode(pool.capture_mode) %></td>
                  <td class="px-4 py-3"><%= member_count %></td>
                  <td class="px-4 py-3"><%= pool.config_version %></td>
                  <td class="px-4 py-3"><%= Formatters.format_utc(pool.config_updated_at) %></td>
                  <td class="px-4 py-3"><%= Formatters.display(pool.config_updated_by) %></td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </section>
      <% end %>
    </main>
    """
  end
end
