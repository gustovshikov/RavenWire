defmodule ConfigManagerWeb.AlertRulesLive do
  @moduledoc "Platform alert rule management page."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.Formatters

  alias ConfigManager.Alerts
  alias ConfigManagerWeb.AuthHelpers

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:page_title, "Alert Rules")
     |> assign(:rules, Alerts.list_rules())
     |> assign(:changeset, nil)}
  end

  @impl true
  def handle_event("save", %{"rule_id" => id, "rule" => attrs}, socket) do
    with :ok <- AuthHelpers.authorize(socket, "alerts:manage", "alert_rule:update"),
         rule <- Alerts.get_rule!(id),
         {:ok, _updated} <-
           Alerts.update_rule(rule, normalize_rule_attrs(attrs), socket.assigns.current_user) do
      {:noreply,
       socket
       |> put_flash(:info, "Alert rule updated.")
       |> assign(:rules, Alerts.list_rules())
       |> assign(:changeset, nil)}
    else
      {:error, :forbidden} ->
        {:noreply, put_flash(socket, :error, "Insufficient permissions.")}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:noreply, assign(socket, changeset: changeset)}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Alert rule could not be updated.")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <.alert_nav active="rules" />

      <div class="mb-6 border-b border-gray-200 pb-4">
        <h1 class="text-2xl font-bold text-gray-900">Alert Rules</h1>
        <p class="text-sm text-gray-500">Built-in platform alert thresholds and enablement</p>
      </div>

      <%= if @changeset do %>
        <div class="mb-4 rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          Alert rule validation failed. Check the threshold and severity values.
        </div>
      <% end %>

      <div class="overflow-hidden rounded border border-gray-200 bg-white">
        <table class="min-w-full divide-y divide-gray-200 text-sm">
          <thead class="bg-gray-50 text-left text-xs font-semibold uppercase tracking-wide text-gray-500">
            <tr>
              <th class="px-4 py-3">Type</th>
              <th class="px-4 py-3">Description</th>
              <th class="px-4 py-3">Severity</th>
              <th class="px-4 py-3">Threshold</th>
              <th class="px-4 py-3">Enabled</th>
              <th class="px-4 py-3">Action</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            <%= for rule <- @rules do %>
              <tr>
                <td class="px-4 py-3 font-medium text-gray-900"><%= Alerts.alert_type_label(rule.alert_type) %></td>
                <td class="max-w-xl px-4 py-3 text-gray-700">
                  <%= rule.description %>
                  <%= if rule.alert_type in ["vector_sink_down", "bpf_validation_failed", "pcap_prune_failed"] do %>
                    <span class="ml-2 rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-700">Deferred source</span>
                  <% end %>
                </td>
                <td class="px-4 py-3">
                  <form id={"rule-form-#{rule.id}"} phx-submit="save">
                    <input type="hidden" name="rule_id" value={rule.id} />
                    <select name="rule[severity]" class="rounded border border-gray-300 px-2 py-1">
                      <%= for severity <- ["critical", "warning", "info"] do %>
                        <option value={severity} selected={rule.severity == severity}><%= display(severity) %></option>
                      <% end %>
                    </select>
                  </form>
                </td>
                <td class="px-4 py-3">
                  <input form={"rule-form-#{rule.id}"} type="number" step="0.1" min="0" name="rule[threshold_value]" value={rule.threshold_value} class="w-24 rounded border border-gray-300 px-2 py-1" />
                  <span class="ml-1 text-gray-500"><%= rule.threshold_unit %></span>
                </td>
                <td class="px-4 py-3">
                  <input form={"rule-form-#{rule.id}"} type="hidden" name="rule[enabled]" value="false" />
                  <input form={"rule-form-#{rule.id}"} type="checkbox" name="rule[enabled]" value="true" checked={rule.enabled} />
                </td>
                <td class="px-4 py-3">
                  <button form={"rule-form-#{rule.id}"} type="submit" class="rounded bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700">Save</button>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </div>
    </main>
    """
  end

  def alert_nav(assigns) do
    ~H"""
    <nav class="mb-4 flex flex-wrap gap-4 text-sm">
      <a href="/alerts" class={nav_class(@active == "alerts")}>Alerts</a>
      <a href="/alerts/rules" class={nav_class(@active == "rules")}>Rules</a>
      <a href="/alerts/notifications" class={nav_class(@active == "notifications")}>Notifications</a>
    </nav>
    """
  end

  defp normalize_rule_attrs(attrs) do
    attrs
    |> Map.update("enabled", false, &(&1 in ["true", true]))
  end

  defp nav_class(true), do: "font-semibold text-blue-700 underline"
  defp nav_class(false), do: "text-blue-600 hover:underline"
end
