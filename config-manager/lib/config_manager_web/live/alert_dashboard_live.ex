defmodule ConfigManagerWeb.AlertDashboardLive do
  @moduledoc "Platform alert dashboard."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.Formatters

  alias ConfigManager.Alerts
  alias ConfigManager.Alerts.AlertRule
  alias ConfigManager.Auth.Policy
  alias ConfigManagerWeb.AuthHelpers

  @page_size 25

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:page_title, "Alerts")
     |> assign(:filters, %{})
     |> assign(:page, 1)
     |> assign(:alerts, [])
     |> assign(:meta, %{page: 1, page_size: @page_size, total_count: 0, total_pages: 1})
     |> assign(:counts, %{firing: 0, acknowledged: 0, resolved: 0})
     |> assign(:alert_types, AlertRule.alert_types())
     |> assign(:severities, AlertRule.severities())
     |> assign(:statuses, ["firing", "acknowledged", "resolved"])}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    filters = filters_from_params(params)
    page = positive_int(Map.get(params, "page"), 1)
    {:noreply, load_alerts(socket, filters, page)}
  end

  @impl true
  def handle_info({event, _alert}, socket)
      when event in [:alert_fired, :alert_updated, :alert_resolved] do
    {:noreply, load_alerts(socket, socket.assigns.filters, socket.assigns.page)}
  end

  def handle_info(_message, socket), do: {:noreply, socket}

  @impl true
  def handle_event("filter", %{"filters" => filters}, socket) do
    query =
      filters
      |> Enum.reject(fn {_key, value} -> String.trim(to_string(value)) == "" end)
      |> Map.new()

    {:noreply, push_patch(socket, to: "/alerts?#{URI.encode_query(query)}")}
  end

  def handle_event("clear_filters", _params, socket) do
    {:noreply, push_patch(socket, to: "/alerts")}
  end

  def handle_event("page", %{"page" => page}, socket) do
    query =
      socket.assigns.filters
      |> Map.put("page", page)
      |> URI.encode_query()

    {:noreply, push_patch(socket, to: "/alerts?#{query}")}
  end

  def handle_event("ack", %{"id" => id} = params, socket) do
    with :ok <- AuthHelpers.authorize(socket, "alerts:manage", "alert:acknowledge"),
         alert <- Alerts.get_alert!(id),
         {:ok, _alert} <-
           Alerts.acknowledge_alert(alert, socket.assigns.current_user, note: params["note"]) do
      {:noreply,
       socket
       |> put_flash(:info, "Alert acknowledged.")
       |> load_alerts(socket.assigns.filters, socket.assigns.page)}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Alert could not be acknowledged.")}
    end
  end

  def handle_event("resolve", %{"id" => id} = params, socket) do
    with :ok <- AuthHelpers.authorize(socket, "alerts:manage", "alert:resolve"),
         alert <- Alerts.get_alert!(id),
         {:ok, _alert} <-
           Alerts.resolve_alert(alert, socket.assigns.current_user, note: params["note"]) do
      {:noreply,
       socket
       |> put_flash(:info, "Alert resolved.")
       |> load_alerts(socket.assigns.filters, socket.assigns.page)}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Alert could not be resolved.")}
    end
  end

  def handle_event("bulk_action", %{"alert_ids" => ids, "bulk_action" => "ack"} = params, socket) do
    with :ok <- AuthHelpers.authorize(socket, "alerts:manage", "alert:bulk_acknowledge"),
         {:ok, count} <-
           Alerts.bulk_acknowledge(List.wrap(ids), socket.assigns.current_user,
             note: params["note"]
           ) do
      {:noreply,
       socket
       |> put_flash(:info, "#{count} alert(s) acknowledged.")
       |> load_alerts(socket.assigns.filters, socket.assigns.page)}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Selected alerts could not be acknowledged.")}
    end
  end

  def handle_event(
        "bulk_action",
        %{"alert_ids" => ids, "bulk_action" => "resolve"} = params,
        socket
      ) do
    with :ok <- AuthHelpers.authorize(socket, "alerts:manage", "alert:bulk_resolve"),
         {:ok, count} <-
           Alerts.bulk_resolve(List.wrap(ids), socket.assigns.current_user, note: params["note"]) do
      {:noreply,
       socket
       |> put_flash(:info, "#{count} alert(s) resolved.")
       |> load_alerts(socket.assigns.filters, socket.assigns.page)}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Selected alerts could not be resolved.")}
    end
  end

  def handle_event("bulk_action", _params, socket),
    do: {:noreply, put_flash(socket, :error, "Select at least one alert.")}

  @impl true
  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <.alert_nav active="alerts" can_manage={can_manage_alerts?(@current_user)} />

      <div class="mb-6 flex flex-col gap-3 border-b border-gray-200 pb-4 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Alerts</h1>
          <p class="text-sm text-gray-500">Platform health and operational alert center</p>
        </div>
      </div>

      <section aria-label="Alert Summary" class="mb-4 grid gap-3 md:grid-cols-3">
        <.summary_card label="Firing" count={@counts.firing} class="border-red-200 bg-red-50 text-red-800" />
        <.summary_card label="Acknowledged" count={@counts.acknowledged} class="border-yellow-200 bg-yellow-50 text-yellow-900" />
        <.summary_card label="Resolved" count={@counts.resolved} class="border-green-200 bg-green-50 text-green-800" />
      </section>

      <form phx-submit="filter" class="mb-4 rounded border border-gray-200 bg-white p-4">
        <div class="grid gap-3 md:grid-cols-5">
          <.select name="filters[severity]" label="Severity" value={@filters["severity"]} options={@severities} />
          <.select name="filters[alert_type]" label="Type" value={@filters["alert_type"]} options={@alert_types} />
          <.select name="filters[status]" label="Status" value={@filters["status"]} options={@statuses} />
          <.text_input name="filters[sensor_pod_id]" label="Sensor" value={@filters["sensor_pod_id"]} />
          <.text_input name="filters[search]" label="Search" value={@filters["search"]} />
        </div>
        <div class="mt-3 flex gap-2">
          <button type="submit" class="rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">Apply Filters</button>
          <button type="button" phx-click="clear_filters" class="rounded border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50">Clear</button>
        </div>
      </form>

      <form phx-submit="bulk_action">
        <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
          <p class="text-sm text-gray-600">
            Showing <%= length(@alerts) %> of <%= @meta.total_count %> alerts
          </p>
          <%= if can_manage_alerts?(@current_user) do %>
            <div class="flex gap-2">
              <input type="text" name="note" placeholder="Optional note" class="rounded border border-gray-300 px-3 py-2 text-sm" />
              <button type="submit" name="bulk_action" value="ack" class="rounded border border-yellow-300 px-3 py-2 text-sm text-yellow-900 hover:bg-yellow-50">Bulk Acknowledge</button>
              <button type="submit" name="bulk_action" value="resolve" class="rounded border border-green-300 px-3 py-2 text-sm text-green-900 hover:bg-green-50">Bulk Resolve</button>
            </div>
          <% end %>
        </div>

        <div class="overflow-hidden rounded border border-gray-200 bg-white">
          <table class="min-w-full divide-y divide-gray-200 text-sm">
            <thead class="bg-gray-50 text-left text-xs font-semibold uppercase tracking-wide text-gray-500">
              <tr>
                <%= if can_manage_alerts?(@current_user) do %>
                  <th class="px-4 py-3">Select</th>
                <% end %>
                <th class="px-4 py-3">Severity</th>
                <th class="px-4 py-3">Type</th>
                <th class="px-4 py-3">Sensor</th>
                <th class="px-4 py-3">Status</th>
                <th class="px-4 py-3">Message</th>
                <th class="px-4 py-3">Fired</th>
                <%= if can_manage_alerts?(@current_user) do %>
                  <th class="px-4 py-3">Actions</th>
                <% end %>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100">
              <%= if @alerts == [] do %>
                <tr>
                  <td colspan="8" class="px-4 py-8 text-center text-gray-500">No alerts match the current filters.</td>
                </tr>
              <% end %>
              <%= for alert <- @alerts do %>
                <tr>
                  <%= if can_manage_alerts?(@current_user) do %>
                    <td class="px-4 py-3"><input type="checkbox" name="alert_ids[]" value={alert.id} /></td>
                  <% end %>
                  <td class="px-4 py-3"><.badge value={alert.severity} class={Alerts.severity_class(alert.severity)} /></td>
                  <td class="px-4 py-3 font-medium text-gray-900"><%= Alerts.alert_type_label(alert.alert_type) %></td>
                  <td class="px-4 py-3">
                    <%= if alert.sensor_pod_db_id do %>
                      <a class="text-blue-600 hover:underline" href={"/sensors/#{alert.sensor_pod_db_id}"}><%= alert.sensor_pod_id %></a>
                    <% else %>
                      <%= alert.sensor_pod_id %>
                    <% end %>
                  </td>
                  <td class="px-4 py-3"><.badge value={alert.status} class={Alerts.status_class(alert.status)} /></td>
                  <td class="max-w-lg px-4 py-3 text-gray-700"><%= alert.message %></td>
                  <td class="px-4 py-3 text-gray-600"><%= format_utc(alert.fired_at) %></td>
                  <%= if can_manage_alerts?(@current_user) do %>
                    <td class="px-4 py-3">
                      <div class="flex flex-wrap gap-2">
                        <%= if alert.status == "firing" do %>
                          <button type="button" phx-click="ack" phx-value-id={alert.id} class="rounded border border-yellow-300 px-2 py-1 text-xs text-yellow-900 hover:bg-yellow-50">Acknowledge</button>
                        <% end %>
                        <%= if alert.status in ["firing", "acknowledged"] do %>
                          <button type="button" phx-click="resolve" phx-value-id={alert.id} class="rounded border border-green-300 px-2 py-1 text-xs text-green-900 hover:bg-green-50">Resolve</button>
                        <% end %>
                      </div>
                    </td>
                  <% end %>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>
      </form>

      <div class="mt-4 flex items-center justify-between text-sm text-gray-600">
        <button phx-click="page" phx-value-page={max(@meta.page - 1, 1)} disabled={@meta.page <= 1} class="rounded border border-gray-300 px-3 py-2 disabled:opacity-50">Previous</button>
        <span>Page <%= @meta.page %> of <%= @meta.total_pages %></span>
        <button phx-click="page" phx-value-page={min(@meta.page + 1, @meta.total_pages)} disabled={@meta.page >= @meta.total_pages} class="rounded border border-gray-300 px-3 py-2 disabled:opacity-50">Next</button>
      </div>
    </main>
    """
  end

  def alert_nav(assigns) do
    ~H"""
    <nav class="mb-4 flex flex-wrap gap-4 text-sm">
      <a href="/alerts" class={nav_class(@active == "alerts")}>Alerts</a>
      <%= if @can_manage do %>
        <a href="/alerts/rules" class={nav_class(@active == "rules")}>Rules</a>
      <% end %>
      <a href="/alerts/notifications" class={nav_class(@active == "notifications")}>Notifications</a>
    </nav>
    """
  end

  def summary_card(assigns) do
    ~H"""
    <div class={"rounded border p-4 #{@class}"}>
      <p class="text-xs font-semibold uppercase tracking-wide"><%= @label %></p>
      <p class="mt-1 text-3xl font-bold"><%= @count %></p>
    </div>
    """
  end

  def badge(assigns) do
    ~H"""
    <span class={"inline-flex rounded px-2 py-0.5 text-xs font-medium #{@class}"}><%= display(@value) %></span>
    """
  end

  def select(assigns) do
    ~H"""
    <label class="block text-sm">
      <span class="mb-1 block font-medium text-gray-700"><%= @label %></span>
      <select name={@name} class="w-full rounded border border-gray-300 px-3 py-2">
        <option value="">All</option>
        <%= for option <- @options do %>
          <option value={option} selected={@value == option}><%= display(option) %></option>
        <% end %>
      </select>
    </label>
    """
  end

  def text_input(assigns) do
    ~H"""
    <label class="block text-sm">
      <span class="mb-1 block font-medium text-gray-700"><%= @label %></span>
      <input type="text" name={@name} value={@value} class="w-full rounded border border-gray-300 px-3 py-2" />
    </label>
    """
  end

  defp load_alerts(socket, filters, page) do
    {alerts, meta} = Alerts.list_alerts(filters, %{page: page, page_size: @page_size})

    assign(socket,
      alerts: alerts,
      meta: meta,
      filters: filters,
      page: meta.page,
      counts: Alerts.alert_status_counts()
    )
  end

  defp filters_from_params(params) do
    params
    |> Map.take(["severity", "alert_type", "status", "sensor_pod_id", "search"])
    |> Enum.reject(fn {_key, value} -> String.trim(to_string(value)) == "" end)
    |> Map.new()
  end

  defp positive_int(value, fallback) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} when int > 0 -> int
      _ -> fallback
    end
  end

  defp positive_int(_value, fallback), do: fallback

  defp can_manage_alerts?(user), do: Policy.has_permission?(user.role, "alerts:manage")

  defp nav_class(true), do: "font-semibold text-blue-700 underline"
  defp nav_class(false), do: "text-blue-600 hover:underline"
end
