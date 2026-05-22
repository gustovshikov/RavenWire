defmodule ConfigManagerWeb.RulesLive.StoreLive do
  @moduledoc "Rule Store browse, search, filter, and toggle page."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.RulesLive.Helpers

  alias ConfigManager.Rules
  alias ConfigManagerWeb.Formatters

  @page_size 25
  @sort_fields ~w(sid message category revision severity)

  @impl true
  def mount(params, _session, socket) do
    if connected?(socket), do: Phoenix.PubSub.subscribe(ConfigManager.PubSub, "rules")

    filters = filters(params)

    {:ok,
     socket
     |> assign(:page_title, "Rule Store")
     |> assign(:filters, filters)
     |> assign(:selected_ids, MapSet.new())
     |> load_supporting_data()
     |> load_rules()}
  end

  @impl true
  def handle_info({:rules_updated, _repository_id}, socket), do: {:noreply, refresh(socket)}
  def handle_info({:rule_toggled, _rule_id}, socket), do: {:noreply, refresh(socket)}
  def handle_info({:rules_bulk_toggled, _ids, _enabled}, socket), do: {:noreply, refresh(socket)}
  def handle_info({:category_toggled, _category}, socket), do: {:noreply, refresh(socket)}
  def handle_info(_message, socket), do: {:noreply, refresh(socket)}

  @impl true
  def handle_event("filter", %{"filters" => params}, socket) do
    filters =
      socket.assigns.filters
      |> Map.merge(params)
      |> Map.put("page", "1")

    {:noreply,
     socket
     |> assign(:filters, filters)
     |> assign(:selected_ids, MapSet.new())
     |> load_rules()}
  end

  def handle_event("sort", %{"field" => field}, socket) when field in @sort_fields do
    filters = socket.assigns.filters
    current_field = filters["sort_by"]
    current_dir = filters["sort_dir"]

    next_dir =
      if current_field == field and current_dir == "asc",
        do: "desc",
        else: "asc"

    {:noreply,
     socket
     |> assign(:filters, %{filters | "sort_by" => field, "sort_dir" => next_dir, "page" => "1"})
     |> load_rules()}
  end

  def handle_event("page", %{"page" => page}, socket) do
    {:noreply,
     socket
     |> assign(:filters, Map.put(socket.assigns.filters, "page", page))
     |> load_rules()}
  end

  def handle_event("toggle_select", %{"id" => id}, socket) do
    selected_ids =
      if MapSet.member?(socket.assigns.selected_ids, id) do
        MapSet.delete(socket.assigns.selected_ids, id)
      else
        MapSet.put(socket.assigns.selected_ids, id)
      end

    {:noreply, assign(socket, :selected_ids, selected_ids)}
  end

  def handle_event("select_page", _params, socket) do
    selected_ids =
      socket.assigns.rules.entries
      |> Enum.map(& &1.id)
      |> Enum.reduce(socket.assigns.selected_ids, &MapSet.put(&2, &1))

    {:noreply, assign(socket, :selected_ids, selected_ids)}
  end

  def handle_event("clear_selection", _params, socket) do
    {:noreply, assign(socket, :selected_ids, MapSet.new())}
  end

  def handle_event("toggle_rule", %{"id" => id}, socket) do
    with :ok <- authorize_manage(socket),
         rule when not is_nil(rule) <- Rules.get_rule(id),
         {:ok, _updated} <- Rules.toggle_rule(rule, socket.assigns.current_user) do
      {:noreply, refresh(socket)}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      nil ->
        {:noreply, put_flash(socket, :error, "Rule not found.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Rule update failed: #{inspect(reason)}")}
    end
  end

  def handle_event("bulk_toggle", %{"enabled" => enabled}, socket) do
    enabled? = enabled == "true"
    ids = MapSet.to_list(socket.assigns.selected_ids)

    cond do
      authorize_manage(socket) != :ok ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      ids == [] ->
        {:noreply, put_flash(socket, :error, "Select at least one rule.")}

      true ->
        case Rules.bulk_toggle_rules(ids, enabled?, socket.assigns.current_user) do
          {:ok, count} ->
            {:noreply,
             socket
             |> assign(:selected_ids, MapSet.new())
             |> put_flash(:info, "Updated #{count} rule(s).")
             |> refresh()}

          {:error, reason} ->
            {:noreply, put_flash(socket, :error, "Bulk update failed: #{inspect(reason)}")}
        end
    end
  end

  defp refresh(socket) do
    socket
    |> load_supporting_data()
    |> load_rules()
  end

  defp load_supporting_data(socket) do
    assign(socket,
      categories: Rules.list_categories(),
      repositories: Rules.list_repositories()
    )
  end

  defp load_rules(socket) do
    filters = socket.assigns.filters

    rules =
      Rules.list_rules(
        page: filters["page"],
        page_size: @page_size,
        search: filters["search"],
        category: filters["category"],
        repository_id: filters["repository_id"],
        sort_by: filters["sort_by"],
        sort_dir: filters["sort_dir"]
      )

    assign(socket, :rules, rules)
  end

  defp filters(params) do
    %{
      "search" => Map.get(params, "search", ""),
      "category" => Map.get(params, "category", ""),
      "repository_id" => Map.get(params, "repository_id", ""),
      "sort_by" => Map.get(params, "sort_by", "sid"),
      "sort_dir" => Map.get(params, "sort_dir", "asc"),
      "page" => Map.get(params, "page", "1")
    }
  end

  defp authorize_manage(socket) do
    if can_manage_rules?(socket.assigns.current_user), do: :ok, else: {:error, :forbidden}
  end

  defp selected_count(selected_ids), do: MapSet.size(selected_ids)

  defp page_count_label(%{total_count: 0}), do: "No rules"

  defp page_count_label(%{page: page, page_size: page_size, total_count: total_count}) do
    first = (page - 1) * page_size + 1
    last = min(page * page_size, total_count)
    "#{first}-#{last} of #{total_count}"
  end

  defp next_page(%{page: page, total_pages: total_pages}) when page < total_pages, do: page + 1
  defp next_page(%{page: page}), do: page

  defp previous_page(%{page: page}) when page > 1, do: page - 1
  defp previous_page(%{page: page}), do: page

  defp sort_indicator(filters, field) do
    if filters["sort_by"] == field do
      if filters["sort_dir"] == "desc", do: " down", else: " up"
    else
      ""
    end
  end

  defp empty_message(categories) do
    if categories == [], do: "No rules in store", else: "No rules found"
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <div class="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Rule Store</h1>
          <p class="text-sm text-gray-500">Search, filter, and manage imported Suricata rules.</p>
        </div>
      </div>

      <.rules_nav active="store" />

      <form phx-change="filter" class="mb-4 grid gap-3 rounded border border-gray-200 bg-white p-4 text-sm md:grid-cols-4">
        <input type="hidden" name="filters[sort_by]" value={@filters["sort_by"]} />
        <input type="hidden" name="filters[sort_dir]" value={@filters["sort_dir"]} />
        <input type="hidden" name="filters[page]" value={@filters["page"]} />
        <label class="block">
          <span class="mb-1 block text-xs font-medium uppercase text-gray-500">Search</span>
          <input
            name="filters[search]"
            value={@filters["search"]}
            placeholder="SID or message"
            phx-debounce="250"
            class="w-full rounded border border-gray-300 px-3 py-2"
          />
        </label>
        <label class="block">
          <span class="mb-1 block text-xs font-medium uppercase text-gray-500">Category</span>
          <select name="filters[category]" class="w-full rounded border border-gray-300 px-3 py-2">
            <option value="">Any category</option>
            <%= for category <- @categories do %>
              <option value={category.name} selected={@filters["category"] == category.name}>
                <%= category.name %> (<%= category.total %>)
              </option>
            <% end %>
          </select>
        </label>
        <label class="block">
          <span class="mb-1 block text-xs font-medium uppercase text-gray-500">Repository</span>
          <select name="filters[repository_id]" class="w-full rounded border border-gray-300 px-3 py-2">
            <option value="">Any repository</option>
            <%= for repository <- @repositories do %>
              <option value={repository.id} selected={@filters["repository_id"] == repository.id}>
                <%= repository.name %>
              </option>
            <% end %>
          </select>
        </label>
        <div class="flex items-end">
          <a href="/rules/store" class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-800 hover:bg-gray-50">Reset</a>
        </div>
      </form>

      <%= if can_manage_rules?(@current_user) do %>
        <div class="mb-3 flex flex-wrap items-center justify-between gap-2 text-sm">
          <div class="text-gray-600"><%= selected_count(@selected_ids) %> selected</div>
          <div class="flex flex-wrap gap-2">
            <button type="button" phx-click="select_page" class="rounded border border-gray-300 px-3 py-2 font-medium text-gray-800 hover:bg-gray-50">Select Page</button>
            <button type="button" phx-click="clear_selection" class="rounded border border-gray-300 px-3 py-2 font-medium text-gray-800 hover:bg-gray-50">Clear</button>
            <button type="button" phx-click="bulk_toggle" phx-value-enabled="true" class="rounded bg-green-700 px-3 py-2 font-medium text-white hover:bg-green-800">Enable</button>
            <button type="button" phx-click="bulk_toggle" phx-value-enabled="false" class="rounded bg-gray-700 px-3 py-2 font-medium text-white hover:bg-gray-800">Disable</button>
          </div>
        </div>
      <% end %>

      <section class="overflow-hidden rounded border border-gray-200 bg-white">
        <%= if @rules.entries == [] do %>
          <p class="p-6 text-sm text-gray-600"><%= empty_message(@categories) %></p>
        <% else %>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead>
                <tr class="border-b border-gray-200 bg-gray-50 text-xs uppercase text-gray-500">
                  <%= if can_manage_rules?(@current_user) do %>
                    <th class="w-10 px-4 py-3 font-medium">Select</th>
                  <% end %>
                  <th class="px-4 py-3 font-medium">
                    <button type="button" phx-click="sort" phx-value-field="sid" class="font-medium hover:text-gray-900">SID<%= sort_indicator(@filters, "sid") %></button>
                  </th>
                  <th class="px-4 py-3 font-medium">
                    <button type="button" phx-click="sort" phx-value-field="message" class="font-medium hover:text-gray-900">Message<%= sort_indicator(@filters, "message") %></button>
                  </th>
                  <th class="px-4 py-3 font-medium">
                    <button type="button" phx-click="sort" phx-value-field="category" class="font-medium hover:text-gray-900">Category<%= sort_indicator(@filters, "category") %></button>
                  </th>
                  <th class="px-4 py-3 font-medium">Source</th>
                  <th class="px-4 py-3 font-medium">
                    <button type="button" phx-click="sort" phx-value-field="revision" class="font-medium hover:text-gray-900">Rev<%= sort_indicator(@filters, "revision") %></button>
                  </th>
                  <th class="px-4 py-3 font-medium">
                    <button type="button" phx-click="sort" phx-value-field="severity" class="font-medium hover:text-gray-900">Severity<%= sort_indicator(@filters, "severity") %></button>
                  </th>
                  <th class="px-4 py-3 font-medium">State</th>
                </tr>
              </thead>
              <tbody>
                <%= for rule <- @rules.entries do %>
                  <tr class="border-b border-gray-100 last:border-0 hover:bg-gray-50">
                    <%= if can_manage_rules?(@current_user) do %>
                      <td class="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={MapSet.member?(@selected_ids, rule.id)}
                          phx-click="toggle_select"
                          phx-value-id={rule.id}
                          class="rounded border-gray-300"
                        />
                      </td>
                    <% end %>
                    <th class="px-4 py-3 font-mono text-xs font-medium text-gray-900"><%= rule.sid %></th>
                    <td class="max-w-md px-4 py-3 text-gray-800"><%= Formatters.display(rule.message) %></td>
                    <td class="px-4 py-3 text-gray-700"><%= rule.category %></td>
                    <td class="px-4 py-3 text-gray-700"><%= Formatters.display(rule.repository_name) %></td>
                    <td class="px-4 py-3 text-gray-700"><%= rule.revision %></td>
                    <td class="px-4 py-3 text-gray-700"><%= rule.severity %></td>
                    <td class="px-4 py-3">
                      <%= if can_manage_rules?(@current_user) do %>
                        <button type="button" phx-click="toggle_rule" phx-value-id={rule.id} class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{enabled_class(rule.enabled)}"}>
                          <%= enabled_label(rule.enabled) %>
                        </button>
                      <% else %>
                        <span class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{enabled_class(rule.enabled)}"}>
                          <%= enabled_label(rule.enabled) %>
                        </span>
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
        <span class="text-gray-600"><%= page_count_label(@rules) %></span>
        <div class="flex gap-2">
          <button type="button" phx-click="page" phx-value-page={previous_page(@rules)} disabled={@rules.page <= 1} class="rounded border border-gray-300 px-3 py-2 font-medium text-gray-800 disabled:cursor-not-allowed disabled:bg-gray-100 disabled:text-gray-400 hover:bg-gray-50">Previous</button>
          <button type="button" phx-click="page" phx-value-page={next_page(@rules)} disabled={@rules.page >= @rules.total_pages} class="rounded border border-gray-300 px-3 py-2 font-medium text-gray-800 disabled:cursor-not-allowed disabled:bg-gray-100 disabled:text-gray-400 hover:bg-gray-50">Next</button>
        </div>
      </div>
    </main>
    """
  end
end
