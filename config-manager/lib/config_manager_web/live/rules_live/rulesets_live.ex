defmodule ConfigManagerWeb.RulesLive.RulesetsLive do
  @moduledoc "Ruleset list page."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.RulesLive.Helpers

  alias ConfigManager.Rules
  alias ConfigManagerWeb.Formatters

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rulesets")

    {:ok,
     socket
     |> assign(:page_title, "Rulesets")
     |> load_rulesets()}
  end

  @impl true
  def handle_info(_message, socket), do: {:noreply, load_rulesets(socket)}

  defp load_rulesets(socket), do: assign(socket, :rulesets, Rules.list_rulesets())

  @impl true
  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <div class="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Rulesets</h1>
          <p class="text-sm text-gray-500">Compose categories and SID overrides into deployable rule bundles.</p>
        </div>
        <%= if can_manage_rules?(@current_user) do %>
          <a href="/rules/rulesets/new" class="w-fit rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">Create Ruleset</a>
        <% end %>
      </div>

      <.rules_nav active="rulesets" />

      <section class="overflow-hidden rounded border border-gray-200 bg-white">
        <%= if @rulesets == [] do %>
          <p class="p-6 text-sm text-gray-600">No rulesets have been created.</p>
        <% else %>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead>
                <tr class="border-b border-gray-200 bg-gray-50 text-xs uppercase text-gray-500">
                  <th class="px-4 py-3 font-medium">Name</th>
                  <th class="px-4 py-3 font-medium">Description</th>
                  <th class="px-4 py-3 font-medium">Version</th>
                  <th class="px-4 py-3 font-medium">Rules</th>
                  <th class="px-4 py-3 font-medium">Assigned Pools</th>
                  <th class="px-4 py-3 font-medium">Last Modified</th>
                </tr>
              </thead>
              <tbody>
                <%= for %{ruleset: ruleset, effective_count: effective_count, pool_count: pool_count} <- @rulesets do %>
                  <tr class="border-b border-gray-100 last:border-0 hover:bg-gray-50">
                    <th class="px-4 py-3 font-medium">
                      <a href={"/rules/rulesets/#{ruleset.id}"} class="text-blue-700 hover:underline"><%= ruleset.name %></a>
                    </th>
                    <td class="max-w-md px-4 py-3 text-gray-700"><%= Formatters.display(ruleset.description) %></td>
                    <td class="px-4 py-3 text-gray-700"><%= ruleset.version %></td>
                    <td class="px-4 py-3 text-gray-700"><%= effective_count %></td>
                    <td class="px-4 py-3 text-gray-700"><%= pool_count %></td>
                    <td class="px-4 py-3 text-gray-700"><%= Formatters.format_utc(ruleset.updated_at) %></td>
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
