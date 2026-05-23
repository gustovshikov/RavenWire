defmodule ConfigManagerWeb.PcapLive.RequestsLive do
  @moduledoc "PCAP request history."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.Pcap
  alias ConfigManagerWeb.Formatters

  @impl true
  def mount(params, _session, socket) do
    {:ok,
     socket
     |> assign(page_title: "PCAP Requests", filters: normalize_filters(params))
     |> load_requests()}
  end

  @impl true
  def handle_event("filter", %{"filters" => params}, socket) do
    {:noreply, socket |> assign(filters: normalize_filters(params)) |> load_requests()}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-6xl px-6 py-6">
      <div class="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">PCAP Requests</h1>
          <p class="text-sm text-gray-600">Search history, carve status, manifests, and downloads.</p>
        </div>
        <a href="/pcap/search" class="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">New Search</a>
      </div>

      <form phx-change="filter" class="mt-5 grid gap-3 rounded border border-gray-200 bg-white p-4 md:grid-cols-4">
        <select name="filters[status]" class="rounded border border-gray-300 px-3 py-2 text-sm">
          <option value="">All Statuses</option>
          <%= for status <- ConfigManager.Pcap.CarveRequest.statuses() do %>
            <option value={status} selected={@filters["status"] == status}><%= String.capitalize(status) %></option>
          <% end %>
        </select>
        <select name="filters[search_type]" class="rounded border border-gray-300 px-3 py-2 text-sm">
          <option value="">All Search Types</option>
          <%= for type <- ConfigManager.Pcap.CarveRequest.search_types() do %>
            <option value={type} selected={@filters["search_type"] == type}><%= String.replace(type, "_", " ") %></option>
          <% end %>
        </select>
        <input name="filters[sensor_name]" value={@filters["sensor_name"]} class="rounded border border-gray-300 px-3 py-2 text-sm" placeholder="Sensor name" />
      </form>

      <section class="mt-5 overflow-hidden rounded border border-gray-200 bg-white">
        <table class="min-w-full divide-y divide-gray-200 text-sm">
          <thead class="bg-gray-50 text-left text-xs font-semibold uppercase text-gray-600">
            <tr>
              <th class="px-4 py-3">Submitted</th>
              <th class="px-4 py-3">User</th>
              <th class="px-4 py-3">Sensor</th>
              <th class="px-4 py-3">Search</th>
              <th class="px-4 py-3">Status</th>
              <th class="px-4 py-3">Size</th>
              <th class="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <%= if @result.entries == [] do %>
              <tr><td colspan="7" class="px-4 py-8 text-center text-gray-500">No PCAP requests found.</td></tr>
            <% end %>
            <%= for request <- @result.entries do %>
              <tr>
                <td class="px-4 py-3 text-gray-600"><%= Formatters.format_utc(request.inserted_at) %></td>
                <td class="px-4 py-3 text-gray-600"><%= request.actor %></td>
                <td class="px-4 py-3 text-gray-900"><%= request.sensor_name %></td>
                <td class="px-4 py-3 text-gray-600"><%= search_label(request) %></td>
                <td class="px-4 py-3"><.status_badge status={request.status} /></td>
                <td class="px-4 py-3 text-gray-600"><%= format_size(request.file_size_bytes) %></td>
                <td class="px-4 py-3 text-right">
                  <a href={"/pcap/requests/#{request.id}"} class="text-blue-600 hover:underline">Open</a>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  attr(:status, :string, required: true)

  defp status_badge(assigns) do
    ~H"""
    <span class={["inline-flex rounded px-2 py-1 text-xs font-semibold", status_class(@status)]}><%= String.capitalize(@status || "unknown") %></span>
    """
  end

  defp load_requests(socket) do
    assign(
      socket,
      :result,
      Pcap.list_requests_for_actor(socket.assigns.current_user, socket.assigns.filters)
    )
  end

  defp normalize_filters(params) do
    params
    |> Map.take(["status", "search_type", "sensor_name", "page"])
    |> Map.reject(fn {_key, value} -> value in [nil, ""] end)
  end

  defp search_label(request) do
    request.search_type
    |> String.replace("_", " ")
    |> String.capitalize()
  end

  defp format_size(nil), do: "—"
  defp format_size(bytes), do: "#{bytes} B"

  defp status_class("completed"), do: "bg-green-100 text-green-800"
  defp status_class("failed"), do: "bg-red-100 text-red-800"
  defp status_class("expired"), do: "bg-gray-100 text-gray-700"
  defp status_class("carving"), do: "bg-yellow-100 text-yellow-800"
  defp status_class(_status), do: "bg-blue-100 text-blue-800"
end
