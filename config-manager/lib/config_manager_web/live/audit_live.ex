defmodule ConfigManagerWeb.AuditLive do
  @moduledoc "Filtered audit log browser."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.{Audit, Auth}
  alias ConfigManager.Auth.Policy

  @default_page_size 50

  @impl true
  def mount(params, _session, socket) do
    users = Auth.list_users()

    socket =
      assign(socket,
        users_by_id: Map.new(users, &{&1.id, &1}),
        users_by_username: Map.new(users, &{&1.username, &1}),
        expanded_entry_id: nil
      )

    {:ok, load_entries(socket, params)}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    {:noreply, load_entries(socket, params)}
  end

  @impl true
  def handle_event("filter", %{"filters" => filters}, socket) do
    {:noreply, push_patch(socket, to: "/audit?#{URI.encode_query(clean_filters(filters))}")}
  end

  def handle_event("clear_filters", _params, socket) do
    {:noreply, push_patch(socket, to: "/audit")}
  end

  def handle_event("toggle_detail", %{"id" => id}, socket) do
    expanded_id = if socket.assigns.expanded_entry_id == id, do: nil, else: id
    {:noreply, assign(socket, expanded_entry_id: expanded_id)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <div class="flex items-center justify-between mb-6">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Audit Log</h1>
          <p class="mt-1 text-sm text-gray-500"><%= @total_count %> matching audit entries</p>
        </div>
        <%= if can_export_audit?(@current_user) do %>
          <a href={audit_export_path(@filters)} class="rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">
            Export
          </a>
        <% end %>
      </div>

      <form phx-submit="filter" class="mb-6 rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
        <div class="grid grid-cols-1 gap-3 md:grid-cols-4">
          <input class="rounded border border-gray-300 px-3 py-2 text-sm" type="date" name="filters[start_date]" value={Map.get(@filters, "start_date", "")} />
          <input class="rounded border border-gray-300 px-3 py-2 text-sm" type="date" name="filters[end_date]" value={Map.get(@filters, "end_date", "")} />
          <input class="rounded border border-gray-300 px-3 py-2 text-sm" name="filters[actor]" placeholder="actor" value={Map.get(@filters, "actor", "")} />
          <input class="rounded border border-gray-300 px-3 py-2 text-sm" name="filters[action]" placeholder="action" value={Map.get(@filters, "action", "")} />
          <input class="rounded border border-gray-300 px-3 py-2 text-sm" name="filters[target_type]" placeholder="target type" value={Map.get(@filters, "target_type", "")} />
          <input class="rounded border border-gray-300 px-3 py-2 text-sm" name="filters[target_id]" placeholder="target id" value={Map.get(@filters, "target_id", "")} />
          <select class="rounded border border-gray-300 px-3 py-2 text-sm" name="filters[result]">
            <option value="">any result</option>
            <option value="success" selected={Map.get(@filters, "result") == "success"}>success</option>
            <option value="failure" selected={Map.get(@filters, "result") == "failure"}>failure</option>
          </select>
          <div class="flex gap-2">
            <button type="submit" class="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">
              Apply Filters
            </button>
            <button type="button" phx-click="clear_filters" class="rounded border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">
              Clear
            </button>
          </div>
        </div>
      </form>

      <div class="bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-xs text-gray-500 uppercase tracking-wide bg-gray-50 border-b border-gray-200">
              <th class="px-4 py-3 font-medium">Timestamp</th>
              <th class="px-4 py-3 font-medium">Actor</th>
              <th class="px-4 py-3 font-medium">Action</th>
              <th class="px-4 py-3 font-medium">Target</th>
              <th class="px-4 py-3 font-medium">Result</th>
              <th class="px-4 py-3 font-medium">Detail</th>
            </tr>
          </thead>
          <tbody>
            <%= for entry <- @entries do %>
              <tr class="border-b border-gray-100 last:border-0">
                <td class="px-4 py-3 text-gray-600 whitespace-nowrap"><%= format_dt(entry.timestamp) %></td>
                <td class="px-4 py-3 text-gray-800"><%= format_actor(entry, @users_by_username) %></td>
                <td class="px-4 py-3 text-gray-800"><%= entry.action %></td>
                <td class="px-4 py-3 text-gray-600"><%= format_target(entry, @users_by_id) %></td>
                <td class="px-4 py-3">
                  <span class={"rounded px-2 py-0.5 text-xs font-medium #{result_class(entry.result)}"}>
                    <%= entry.result %>
                  </span>
                </td>
                <td class="px-4 py-3">
                  <button
                    phx-click="toggle_detail"
                    phx-value-id={entry.id}
                    class="text-blue-600 hover:underline"
                  >
                    <%= if @expanded_entry_id == entry.id, do: "Hide", else: "Show" %>
                  </button>
                </td>
              </tr>
              <%= if @expanded_entry_id == entry.id do %>
                <tr class="border-b border-gray-100 bg-gray-50">
                  <td colspan="6" class="px-4 py-3">
                    <pre class="overflow-auto rounded border border-gray-200 bg-white p-3 text-xs text-gray-700"><%= format_detail(entry.detail) %></pre>
                  </td>
                </tr>
              <% end %>
            <% end %>
            <%= if @entries == [] do %>
              <tr>
                <td colspan="6" class="px-4 py-10 text-center text-gray-400">No audit entries match the current filters.</td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </div>

      <div class="mt-4 flex items-center justify-between text-sm">
        <div class="text-gray-500">
          Page <%= @page %> of <%= @total_pages %>
        </div>
        <div class="flex gap-2">
          <a
            href={page_path(@filters, max(@page - 1, 1))}
            class={"rounded border border-gray-300 px-3 py-1.5 font-medium #{if @page <= 1, do: "pointer-events-none text-gray-300", else: "text-gray-700 hover:bg-gray-50"}"}
          >
            Previous
          </a>
          <a
            href={page_path(@filters, min(@page + 1, @total_pages))}
            class={"rounded border border-gray-300 px-3 py-1.5 font-medium #{if @page >= @total_pages, do: "pointer-events-none text-gray-300", else: "text-gray-700 hover:bg-gray-50"}"}
          >
            Next
          </a>
        </div>
      </div>
    </div>
    """
  end

  defp load_entries(socket, params) do
    filters = clean_filters(params)
    page = params |> Map.get("page", "1") |> parse_positive_int(1)
    total_count = Audit.count_entries(filters: filters)
    total_pages = max(ceil_div(total_count, @default_page_size), 1)
    page = min(page, total_pages)

    assign(socket,
      filters: filters,
      page: page,
      total_count: total_count,
      total_pages: total_pages,
      entries: Audit.list_entries(filters: filters, page: page, page_size: @default_page_size)
    )
  end

  defp clean_filters(params) do
    params
    |> Map.take([
      "start_date",
      "end_date",
      "actor",
      "action",
      "target_type",
      "target_id",
      "result"
    ])
    |> Enum.reject(fn {_key, value} -> is_nil(value) or String.trim(to_string(value)) == "" end)
    |> Map.new(fn {key, value} -> {key, String.trim(to_string(value))} end)
  end

  defp page_path(filters, page) do
    query = filters |> Map.put("page", page) |> URI.encode_query()
    "/audit?#{query}"
  end

  defp audit_export_path(filters) do
    case URI.encode_query(filters) do
      "" -> "/audit/export"
      query -> "/audit/export?#{query}"
    end
  end

  defp parse_positive_int(value, default) do
    case Integer.parse(to_string(value)) do
      {int, _} when int > 0 -> int
      _ -> default
    end
  end

  defp ceil_div(0, _denominator), do: 0
  defp ceil_div(numerator, denominator), do: div(numerator + denominator - 1, denominator)

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

  defp result_class("success"), do: "bg-green-100 text-green-800"
  defp result_class("failure"), do: "bg-red-100 text-red-800"
  defp result_class(_), do: "bg-gray-100 text-gray-800"

  defp can_export_audit?(nil), do: false
  defp can_export_audit?(user), do: Policy.has_permission?(user.role, "audit:export")

  defp format_detail(nil), do: "{}"
  defp format_detail(""), do: "{}"

  defp format_detail(detail) do
    case Jason.decode(detail) do
      {:ok, decoded} -> Jason.encode!(decoded, pretty: true)
      _ -> detail
    end
  end
end
