defmodule ConfigManagerWeb.PoolLive.DriftLive do
  @moduledoc "Pool deployment drift page."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.DeploymentLive.Helpers,
    only: [domains_label: 1, status_class: 1, status_label: 1]

  import ConfigManagerWeb.PoolLive.Helpers

  alias ConfigManager.{Deployments, Pools}
  alias ConfigManagerWeb.Formatters

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Pools.get_pool(id) do
      nil ->
        {:ok, assign(socket, not_found: true, page_title: "Pool Not Found")}

      pool ->
        if connected?(socket) do
          Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool.id}:drift")
          Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool.id}")
        end

        {:ok, assign_drift(socket, pool)}
    end
  end

  @impl true
  def handle_info(_message, socket) do
    pool = Pools.get_pool!(socket.assigns.pool.id)
    {:noreply, assign_drift(socket, pool)}
  end

  defp assign_drift(socket, pool) do
    drift = Deployments.compute_drift(pool)

    assign(socket,
      not_found: false,
      page_title: "#{pool.name} Drift",
      pool: pool,
      drift: drift,
      summary: Deployments.drift_summary(pool)
    )
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
    <main class="mx-auto max-w-6xl px-6 py-6">
      <a href={"/pools/#{@pool.id}"} class="text-sm text-blue-600 hover:underline">Back to pool</a>
      <h1 class="mt-2 text-2xl font-bold text-gray-900"><%= @pool.name %> Drift</h1>
      <p class="mt-1 text-sm text-gray-600">Compares enrolled sensors against the pool desired state.</p>

      <.pool_nav pool={@pool} />

      <section class="mb-4 grid gap-3 md:grid-cols-4">
        <.summary_tile label="Total Sensors" value={@summary.total} />
        <.summary_tile label="In Sync" value={@summary.in_sync} status={:in_sync} />
        <.summary_tile label="Drift Detected" value={@summary.drift_detected} status={:drift_detected} />
        <.summary_tile label="Never Deployed" value={@summary.never_deployed} status={:never_deployed} />
      </section>

      <section class="overflow-hidden rounded border border-gray-200 bg-white">
        <%= if @drift == [] do %>
          <p class="p-6 text-sm text-gray-600">No enrolled sensors are assigned to this pool.</p>
        <% else %>
          <table class="w-full text-left text-sm">
            <thead>
              <tr class="border-b border-gray-200 bg-gray-50 text-xs uppercase text-gray-500">
                <th class="px-4 py-3 font-medium">Sensor</th>
                <th class="px-4 py-3 font-medium">Drift Status</th>
                <th class="px-4 py-3 font-medium">Domains</th>
                <th class="px-4 py-3 font-medium">Last Deployment</th>
                <th class="px-4 py-3 font-medium">Last Deployed At</th>
              </tr>
            </thead>
            <tbody>
              <%= for result <- @drift do %>
                <tr class="border-b border-gray-100 last:border-0 hover:bg-gray-50">
                  <th class="px-4 py-3 font-medium">
                    <a href={"/sensors/#{result.sensor.id}"} class="text-blue-700 hover:underline"><%= result.sensor.name %></a>
                  </th>
                  <td class="px-4 py-3">
                    <span class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{status_class(result.status)}"}>
                      <%= status_label(result.status) %>
                    </span>
                  </td>
                  <td class="px-4 py-3 text-gray-700"><%= domains_label(result.domains) %></td>
                  <td class="px-4 py-3 font-mono text-xs text-gray-700"><%= Formatters.display(short_id(result.sensor.last_deployment_id)) %></td>
                  <td class="px-4 py-3 text-gray-700"><%= Formatters.format_utc(result.sensor.last_deployed_at) %></td>
                </tr>
              <% end %>
            </tbody>
          </table>
        <% end %>
      </section>
    </main>
    """
  end

  attr(:label, :string, required: true)
  attr(:value, :any, required: true)
  attr(:status, :any, default: nil)

  def summary_tile(assigns) do
    ~H"""
    <div class="rounded border border-gray-200 bg-white p-4">
      <dt class="text-xs font-medium uppercase text-gray-500"><%= @label %></dt>
      <dd class="mt-2 flex items-center gap-2 text-2xl font-semibold text-gray-900">
        <%= @value %>
        <%= if @status do %>
          <span class={"rounded px-2 py-0.5 text-xs font-medium #{status_class(@status)}"}><%= status_label(@status) %></span>
        <% end %>
      </dd>
    </div>
    """
  end

  defp short_id(nil), do: nil
  defp short_id(id), do: String.slice(id, 0, 8)
end
