defmodule ConfigManagerWeb.RulesLive.DeploymentsLive do
  @moduledoc "Managed and ad hoc rule deployment history."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.RulesLive.Helpers

  alias ConfigManager.{Pools, Rules}
  alias ConfigManagerWeb.Formatters

  @page_size 25

  @impl true
  def mount(params, _session, socket) do
    if connected?(socket), do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rulesets")

    {:ok,
     socket
     |> assign(:page_title, "Rule Deployments")
     |> assign(:page, page_param(params))
     |> load_deployments()}
  end

  @impl true
  def handle_info(_message, socket), do: {:noreply, load_deployments(socket)}

  @impl true
  def handle_event("page", %{"page" => page}, socket) do
    {:noreply,
     socket
     |> assign(:page, page)
     |> load_deployments()}
  end

  defp load_deployments(socket) do
    deployments = Rules.list_rule_deployments(page: socket.assigns.page, page_size: @page_size)
    pool_names = Pools.pool_name_map()

    rows =
      Enum.map(deployments.entries, fn entry ->
        detail = decoded_detail(entry.detail)
        pool_id = if entry.target_type == "pool", do: entry.target_id

        %{
          entry: entry,
          detail: detail,
          pool_id: pool_id,
          pool_name: Map.get(detail, "pool_name") || Map.get(pool_names, pool_id),
          ruleset_name: Map.get(detail, "ruleset_name"),
          version: Map.get(detail, "version"),
          out_of_sync_count: if(pool_id, do: Rules.out_of_sync_count(pool_id), else: nil)
        }
      end)

    assign(socket, deployments: deployments, rows: rows)
  end

  defp page_param(params), do: Map.get(params, "page", "1")

  defp next_page(%{page: page, total_pages: total_pages}) when page < total_pages, do: page + 1
  defp next_page(%{page: page}), do: page

  defp previous_page(%{page: page}) when page > 1, do: page - 1
  defp previous_page(%{page: page}), do: page

  defp action_label("rules_deployed"), do: "Managed Ruleset"
  defp action_label("adhoc_rules_deployed"), do: "Quick Deploy"
  defp action_label(action), do: action |> to_string() |> String.replace("_", " ")

  defp page_count_label(%{total_count: 0}), do: "No deployments"

  defp page_count_label(%{page: page, page_size: page_size, total_count: total_count}) do
    first = (page - 1) * page_size + 1
    last = min(page * page_size, total_count)
    "#{first}-#{last} of #{total_count}"
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <div class="mb-6">
        <h1 class="text-2xl font-bold text-gray-900">Rule Deployments</h1>
        <p class="text-sm text-gray-500">Managed ruleset and quick deploy audit history.</p>
      </div>

      <.rules_nav active="deployments" />

      <section class="overflow-hidden rounded border border-gray-200 bg-white">
        <%= if @rows == [] do %>
          <p class="p-6 text-sm text-gray-600">No deployments exist.</p>
        <% else %>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead>
                <tr class="border-b border-gray-200 bg-gray-50 text-xs uppercase text-gray-500">
                  <th class="px-4 py-3 font-medium">Timestamp</th>
                  <th class="px-4 py-3 font-medium">Operator</th>
                  <th class="px-4 py-3 font-medium">Pool</th>
                  <th class="px-4 py-3 font-medium">Type</th>
                  <th class="px-4 py-3 font-medium">Ruleset</th>
                  <th class="px-4 py-3 font-medium">Version</th>
                  <th class="px-4 py-3 font-medium">Result</th>
                  <th class="px-4 py-3 font-medium">Sync</th>
                </tr>
              </thead>
              <tbody>
                <%= for row <- @rows do %>
                  <tr class="border-b border-gray-100 last:border-0 hover:bg-gray-50">
                    <td class="px-4 py-3 text-gray-700"><%= Formatters.format_utc(row.entry.timestamp) %></td>
                    <td class="px-4 py-3 text-gray-700"><%= row.entry.actor %></td>
                    <td class="px-4 py-3">
                      <%= if row.pool_id do %>
                        <a href={"/pools/#{row.pool_id}"} class="text-blue-700 hover:underline"><%= Formatters.display(row.pool_name || row.pool_id) %></a>
                      <% else %>
                        <%= Formatters.display(Map.get(row.detail, "target")) %>
                      <% end %>
                    </td>
                    <td class="px-4 py-3 text-gray-700"><%= action_label(row.entry.action) %></td>
                    <td class="px-4 py-3 text-gray-700"><%= Formatters.display(row.ruleset_name) %></td>
                    <td class="px-4 py-3 text-gray-700"><%= Formatters.display(row.version) %></td>
                    <td class="px-4 py-3 text-gray-700"><%= deployment_result_summary(row.entry.detail) %></td>
                    <td class="px-4 py-3">
                      <%= if is_integer(row.out_of_sync_count) do %>
                        <span class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{if row.out_of_sync_count == 0, do: sync_status_class(:in_sync), else: sync_status_class(:out_of_sync)}"}>
                          <%= if row.out_of_sync_count == 0, do: "In Sync", else: "#{row.out_of_sync_count} Out" %>
                        </span>
                      <% else %>
                        <span class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{sync_status_class(nil)}"}>N/A</span>
                      <% end %>
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        <% end %>
      </section>

      <div class="mt-4 flex items-center justify-between gap-3 text-sm">
        <span class="text-gray-600"><%= page_count_label(@deployments) %></span>
        <div class="flex gap-2">
          <button type="button" phx-click="page" phx-value-page={previous_page(@deployments)} disabled={@deployments.page <= 1} class="rounded border border-gray-300 px-3 py-2 font-medium text-gray-800 disabled:cursor-not-allowed disabled:bg-gray-100 disabled:text-gray-400 hover:bg-gray-50">Previous</button>
          <button type="button" phx-click="page" phx-value-page={next_page(@deployments)} disabled={@deployments.page >= @deployments.total_pages} class="rounded border border-gray-300 px-3 py-2 font-medium text-gray-800 disabled:cursor-not-allowed disabled:bg-gray-100 disabled:text-gray-400 hover:bg-gray-50">Next</button>
        </div>
      </div>
    </main>
    """
  end
end
