defmodule ConfigManagerWeb.AlertNotificationsLive do
  @moduledoc "Placeholder page for future alert notification channels."

  use ConfigManagerWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, :page_title, "Alert Notifications")}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <.alert_nav active="notifications" />

      <div class="mb-6 border-b border-gray-200 pb-4">
        <h1 class="text-2xl font-bold text-gray-900">Alert Notifications</h1>
        <p class="text-sm text-gray-500">Notification channels are planned for a future release.</p>
      </div>

      <section class="rounded border border-gray-200 bg-white p-6">
        <h2 class="text-lg font-semibold text-gray-900">Channels</h2>
        <p class="mt-2 text-sm text-gray-600">
          Email and webhook notification delivery are not configured in this release.
          Alerts are available in the browser dashboard and sensor detail pages.
        </p>
      </section>
    </main>
    """
  end

  def alert_nav(assigns) do
    ~H"""
    <nav class="mb-4 flex flex-wrap gap-4 text-sm">
      <a href="/alerts" class={nav_class(@active == "alerts")}>Alerts</a>
      <a href="/alerts/notifications" class={nav_class(@active == "notifications")}>Notifications</a>
    </nav>
    """
  end

  defp nav_class(true), do: "font-semibold text-blue-700 underline"
  defp nav_class(false), do: "text-blue-600 hover:underline"
end
