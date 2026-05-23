defmodule ConfigManagerWeb.AuditLive.ExportLive do
  @moduledoc "Audit export page."

  use ConfigManagerWeb, :live_view

  alias ConfigManager.Audit

  @impl true
  def mount(params, _session, socket) do
    filters = clean_filters(params)

    {:ok,
     assign(socket,
       filters: filters,
       result_count: Audit.count_entries(filters: filters),
       export_limit: Audit.export_limit()
     )}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    filters = clean_filters(params)

    {:noreply,
     assign(socket,
       filters: filters,
       result_count: Audit.count_entries(filters: filters)
     )}
  end

  @impl true
  def handle_event("preview_filters", %{"filters" => filters}, socket) do
    {:noreply,
     push_patch(socket, to: "/audit/export?#{URI.encode_query(clean_filters(filters))}")}
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

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-5xl mx-auto">
      <div class="mb-6 flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Audit Export</h1>
          <p class="mt-1 text-sm text-gray-500">
            Export filtered audit entries as JSON or CSV. Current filters match <%= @result_count %> entries.
          </p>
        </div>
        <a href={audit_path(@filters)} class="text-sm text-blue-600 hover:underline">Back to audit log</a>
      </div>

      <%= if @result_count > @export_limit do %>
        <div class="mb-6 rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          The current export would include more than <%= @export_limit %> records. Narrow the date range or filters before exporting.
        </div>
      <% end %>

      <section class="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
        <form phx-submit="preview_filters" class="mb-6 grid grid-cols-1 gap-3 md:grid-cols-4">
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
          <button type="submit" class="rounded border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">
            Preview Filters
          </button>
        </form>

        <form action="/audit/export/download" method="get" class="flex flex-wrap items-end gap-3">
          <%= for {key, value} <- @filters do %>
            <input type="hidden" name={key} value={value} />
          <% end %>
          <div>
            <label class="mb-1 block text-sm font-medium text-gray-700">Format</label>
            <select class="rounded border border-gray-300 px-3 py-2 text-sm" name="format">
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
            </select>
          </div>
          <button
            type="submit"
            disabled={@result_count > @export_limit}
            class="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Download Export
          </button>
        </form>
      </section>
    </div>
    """
  end

  defp audit_path(filters) do
    case URI.encode_query(filters) do
      "" -> "/audit"
      query -> "/audit?#{query}"
    end
  end
end
