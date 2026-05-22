defmodule ConfigManagerWeb.RulesLive.CategoriesLive do
  @moduledoc "Rule category counts and category-wide enablement controls."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.RulesLive.Helpers

  alias ConfigManager.Rules

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rules")

    {:ok,
     socket
     |> assign(:page_title, "Rule Categories")
     |> load_categories()}
  end

  @impl true
  def handle_info(_message, socket), do: {:noreply, load_categories(socket)}

  @impl true
  def handle_event("toggle_category", %{"category" => category, "enabled" => enabled}, socket) do
    enabled? = enabled == "true"

    if can_manage_rules?(socket.assigns.current_user) do
      case Rules.toggle_category(category, enabled?, socket.assigns.current_user) do
        {:ok, count} ->
          {:noreply,
           socket
           |> put_flash(:info, "Updated #{count} rule(s).")
           |> load_categories()}

        {:error, reason} ->
          {:noreply, put_flash(socket, :error, "Category update failed: #{inspect(reason)}")}
      end
    else
      {:noreply, put_flash(socket, :error, "Insufficient permissions.")}
    end
  end

  defp load_categories(socket), do: assign(socket, :categories, Rules.list_categories())

  @impl true
  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-5xl px-6 py-6">
      <div class="mb-6">
        <h1 class="text-2xl font-bold text-gray-900">Rule Categories</h1>
        <p class="text-sm text-gray-500">Enable or disable groups of imported Suricata rules.</p>
      </div>

      <.rules_nav active="categories" />

      <section class="overflow-hidden rounded border border-gray-200 bg-white">
        <%= if @categories == [] do %>
          <p class="p-6 text-sm text-gray-600">No rules in store</p>
        <% else %>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead>
                <tr class="border-b border-gray-200 bg-gray-50 text-xs uppercase text-gray-500">
                  <th class="px-4 py-3 font-medium">Category</th>
                  <th class="px-4 py-3 font-medium">Total</th>
                  <th class="px-4 py-3 font-medium">Enabled</th>
                  <th class="px-4 py-3 font-medium">Disabled</th>
                  <%= if can_manage_rules?(@current_user) do %>
                    <th class="px-4 py-3 font-medium">Action</th>
                  <% end %>
                </tr>
              </thead>
              <tbody>
                <%= for category <- @categories do %>
                  <tr class="border-b border-gray-100 last:border-0 hover:bg-gray-50">
                    <th class="px-4 py-3 font-medium text-gray-900"><%= category.name %></th>
                    <td class="px-4 py-3 text-gray-700"><%= category.total %></td>
                    <td class="px-4 py-3 text-gray-700"><%= category.enabled %></td>
                    <td class="px-4 py-3 text-gray-700"><%= category.disabled %></td>
                    <%= if can_manage_rules?(@current_user) do %>
                      <td class="px-4 py-3">
                        <div class="flex gap-2">
                          <button type="button" phx-click="toggle_category" phx-value-category={category.name} phx-value-enabled="true" class="rounded bg-green-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-green-800">Enable</button>
                          <button type="button" phx-click="toggle_category" phx-value-category={category.name} phx-value-enabled="false" class="rounded bg-gray-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-gray-800">Disable</button>
                        </div>
                      </td>
                    <% end %>
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
