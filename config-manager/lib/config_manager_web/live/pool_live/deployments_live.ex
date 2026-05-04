defmodule ConfigManagerWeb.PoolLive.DeploymentsLive do
  @moduledoc "Pool deployment history page."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.PoolLive.Helpers
  alias ConfigManager.Pools
  alias ConfigManagerWeb.Formatters

  @impl true
  def mount(%{"id" => id} = params, _session, socket) do
    case Pools.get_pool(id) do
      nil ->
        {:ok, assign(socket, not_found: true, page_title: "Pool Not Found")}

      pool ->
        page = params["page"] || 1
        deployments = Pools.list_pool_deployments(pool.id, page: page)

        {:ok,
         assign(socket,
           not_found: false,
           page_title: "#{pool.name} Deployments",
           pool: pool,
           deployments: deployments
         )}
    end
  end

  @impl true
  def render(%{not_found: true} = assigns) do
    ~H"""
    <main class="mx-auto max-w-3xl px-6 py-10">
      <a href="/pools" class="text-sm text-blue-600 hover:underline">Back to pools</a>
      <h1 class="mt-6 text-2xl font-bold text-gray-900">Pool Not Found</h1>
    </main>
    """
  end

  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-5xl px-6 py-6">
      <a href={"/pools/#{@pool.id}"} class="text-sm text-blue-600 hover:underline">Back to pool</a>
      <h1 class="mt-2 text-2xl font-bold text-gray-900"><%= @pool.name %> Deployments</h1>

      <.pool_nav pool={@pool} />

      <section class="rounded border border-gray-200 bg-white p-4">
        <%= if @deployments.entries == [] do %>
          <p class="text-sm text-gray-600">No deployments have been recorded for this pool.</p>
        <% else %>
          <table class="w-full text-left text-sm">
            <thead>
              <tr class="border-b border-gray-200 text-xs uppercase text-gray-500">
                <th class="py-2 pr-4 font-medium">Timestamp</th>
                <th class="py-2 pr-4 font-medium">Actor</th>
                <th class="py-2 pr-4 font-medium">Action</th>
                <th class="py-2 font-medium">Result</th>
              </tr>
            </thead>
            <tbody>
              <%= for entry <- @deployments.entries do %>
                <tr class="border-b border-gray-100 last:border-0">
                  <td class="py-2 pr-4"><%= Formatters.format_utc(entry.timestamp) %></td>
                  <td class="py-2 pr-4"><%= entry.actor %></td>
                  <td class="py-2 pr-4"><%= entry.action %></td>
                  <td class="py-2"><%= entry.result %></td>
                </tr>
              <% end %>
            </tbody>
          </table>
        <% end %>
      </section>
    </main>
    """
  end
end
