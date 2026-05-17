defmodule ConfigManagerWeb.DeploymentLive.ListLive do
  @moduledoc "Fleet-wide deployment history."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.DeploymentLive.Helpers

  alias ConfigManager.Deployments
  alias ConfigManager.Deployments.Deployment
  alias ConfigManagerWeb.Formatters

  @page_size 25

  @impl true
  def mount(params, _session, socket) do
    if connected?(socket), do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "deployments")

    {:ok,
     socket
     |> assign(:page_title, "Deployments")
     |> assign(:filters, filters(params))
     |> load_deployments(params)}
  end

  @impl true
  def handle_info(_message, socket) do
    {:noreply, load_deployments(socket, socket.assigns.filters)}
  end

  defp load_deployments(socket, params) do
    opts =
      [
        page: Map.get(params, "page", 1),
        page_size: @page_size,
        status: blank_to_nil(Map.get(params, "status")),
        operator: blank_to_nil(Map.get(params, "operator"))
      ]
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)

    assign(socket, :deployments, Deployments.list_deployments(opts))
  end

  defp filters(params) do
    %{
      "page" => Map.get(params, "page", "1"),
      "status" => Map.get(params, "status", ""),
      "operator" => Map.get(params, "operator", "")
    }
  end

  defp blank_to_nil(nil), do: nil
  defp blank_to_nil(""), do: nil
  defp blank_to_nil(value), do: value

  @impl true
  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <div class="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Deployments</h1>
          <p class="text-sm text-gray-500">Fleet-wide desired-state deployment history.</p>
        </div>
        <%= if can_manage_deployments?(@current_user) do %>
          <a href="/pools" class="w-fit rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">New Deployment</a>
        <% end %>
      </div>

      <form method="get" action="/deployments" class="mb-4 grid gap-3 rounded border border-gray-200 bg-white p-4 text-sm md:grid-cols-4">
        <label class="block">
          <span class="mb-1 block text-xs font-medium uppercase text-gray-500">Status</span>
          <select name="status" class="w-full rounded border border-gray-300 px-3 py-2">
            <option value="">Any status</option>
            <%= for status <- Deployment.statuses() do %>
              <option value={status} selected={@filters["status"] == status}><%= status_label(status) %></option>
            <% end %>
          </select>
        </label>
        <label class="block">
          <span class="mb-1 block text-xs font-medium uppercase text-gray-500">Operator</span>
          <input name="operator" value={@filters["operator"]} class="w-full rounded border border-gray-300 px-3 py-2" />
        </label>
        <div class="flex items-end gap-2">
          <button type="submit" class="rounded bg-gray-900 px-3 py-2 text-sm font-medium text-white">Apply</button>
          <a href="/deployments" class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-800 hover:bg-gray-50">Reset</a>
        </div>
      </form>

      <section class="overflow-hidden rounded border border-gray-200 bg-white">
        <%= if @deployments.entries == [] do %>
          <p class="p-6 text-sm text-gray-600">No deployments match the current filters.</p>
        <% else %>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead>
                <tr class="border-b border-gray-200 bg-gray-50 text-xs uppercase text-gray-500">
                  <th class="px-4 py-3 font-medium">Deployment</th>
                  <th class="px-4 py-3 font-medium">Pool</th>
                  <th class="px-4 py-3 font-medium">Status</th>
                  <th class="px-4 py-3 font-medium">Versions</th>
                  <th class="px-4 py-3 font-medium">Results</th>
                  <th class="px-4 py-3 font-medium">Operator</th>
                  <th class="px-4 py-3 font-medium">Started</th>
                  <th class="px-4 py-3 font-medium">Duration</th>
                </tr>
              </thead>
              <tbody>
                <%= for deployment <- @deployments.entries do %>
                  <tr class="border-b border-gray-100 last:border-0 hover:bg-gray-50">
                    <th class="px-4 py-3 font-mono text-xs font-medium">
                      <a href={"/deployments/#{deployment.id}"} class="text-blue-700 hover:underline"><%= String.slice(deployment.id, 0, 8) %></a>
                    </th>
                    <td class="px-4 py-3">
                      <%= if deployment.pool do %>
                        <a href={"/pools/#{deployment.pool_id}"} class="text-blue-700 hover:underline"><%= deployment.pool.name %></a>
                      <% else %>
                        <%= Formatters.display(deployment.pool_id) %>
                      <% end %>
                    </td>
                    <td class="px-4 py-3">
                      <span class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{status_class(deployment.status)}"}>
                        <%= status_label(deployment.status) %>
                      </span>
                    </td>
                    <td class="px-4 py-3 text-gray-700">
                      C<%= deployment.config_version %> / F<%= Formatters.display(deployment.forwarding_config_version) %> / B<%= Formatters.display(deployment.bpf_version) %>
                    </td>
                    <td class="px-4 py-3 text-gray-700"><%= result_summary(Deployments.result_summary(deployment)) %></td>
                    <td class="px-4 py-3 text-gray-700"><%= deployment.operator %></td>
                    <td class="px-4 py-3 text-gray-700"><%= Formatters.format_utc(deployment.started_at || deployment.inserted_at) %></td>
                    <td class="px-4 py-3 text-gray-700"><%= duration(deployment) %></td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        <% end %>
      </section>
    </main>
    """
  end
end
