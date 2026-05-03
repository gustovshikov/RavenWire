defmodule ConfigManagerWeb.EnrollmentLive do
  @moduledoc """
  Enrollment approval LiveView — lists pending enrollment requests and allows
  operators to approve or deny them. Also shows enrolled pods with cert details.

  Requirements: 19.2, 19.3
  """

  use ConfigManagerWeb, :live_view

  alias ConfigManager.Enrollment

  # ── Mount ────────────────────────────────────────────────────────────────────

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(ConfigManager.PubSub, "enrollments")
      Phoenix.PubSub.subscribe(ConfigManager.PubSub, "sensor_pods")
    end

    {:ok,
     socket
     |> assign(:pending, Enrollment.list_pending_enrollments())
     |> assign(:enrolled, Enrollment.list_enrolled_pods())}
  end

  # ── Events ───────────────────────────────────────────────────────────────────

  @impl true
  def handle_event("approve", %{"id" => id}, socket) do
    case Enrollment.approve_enrollment(id) do
      {:ok, _cert_bundle} ->
        {:noreply,
         socket
         |> put_flash(:info, "Enrollment approved and certificate issued.")
         |> assign(:pending, Enrollment.list_pending_enrollments())
         |> assign(:enrolled, Enrollment.list_enrolled_pods())}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Approval failed: #{inspect(reason)}")}
    end
  end

  def handle_event("deny", %{"id" => id}, socket) do
    case Enrollment.deny_enrollment(id) do
      {:ok, _} ->
        {:noreply,
         socket
         |> put_flash(:info, "Enrollment request denied.")
         |> assign(:pending, Enrollment.list_pending_enrollments())
         |> assign(:enrolled, Enrollment.list_enrolled_pods())}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Denial failed: #{inspect(reason)}")}
    end
  end

  # ── PubSub handlers ──────────────────────────────────────────────────────────

  @impl true
  def handle_info({:enrollment_updated, _id}, socket) do
    {:noreply,
     socket
     |> assign(:pending, Enrollment.list_pending_enrollments())
     |> assign(:enrolled, Enrollment.list_enrolled_pods())}
  end

  def handle_info({:pod_updated, _id}, socket) do
    {:noreply, assign(socket, :enrolled, Enrollment.list_enrolled_pods())}
  end

  def handle_info({:pod_recovered, _pod_id, _reason}, socket), do: {:noreply, socket}
  def handle_info({:pod_degraded, _pod_id, _reason, _detail}, socket), do: {:noreply, socket}

  # ── Helpers ──────────────────────────────────────────────────────────────────

  defp format_datetime(nil), do: "—"

  defp format_datetime(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  end

  defp format_datetime(%NaiveDateTime{} = ndt) do
    ndt
    |> DateTime.from_naive!("Etc/UTC")
    |> format_datetime()
  end

  defp cert_expired?(%{cert_expires_at: nil}), do: false

  defp cert_expired?(%{cert_expires_at: expires_at}) do
    DateTime.compare(expires_at, DateTime.utc_now()) == :lt
  end

  # ── Render ───────────────────────────────────────────────────────────────────

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold text-gray-900">RavenWire Enrollment</h1>
        <a href="/" class="text-sm text-blue-600 hover:underline">← Dashboard</a>
      </div>

      <%!-- Flash messages --%>
      <%= if Phoenix.Flash.get(@flash, :info) do %>
        <div class="mb-4 px-4 py-3 rounded bg-green-50 border border-green-200 text-green-800 text-sm">
          <%= Phoenix.Flash.get(@flash, :info) %>
        </div>
      <% end %>
      <%= if Phoenix.Flash.get(@flash, :error) do %>
        <div class="mb-4 px-4 py-3 rounded bg-red-50 border border-red-200 text-red-800 text-sm">
          <%= Phoenix.Flash.get(@flash, :error) %>
        </div>
      <% end %>

      <%!-- Pending enrollments section --%>
      <section class="mb-10">
        <div class="flex items-center gap-3 mb-3">
          <h2 class="text-lg font-semibold text-gray-800">Pending Requests</h2>
          <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
            <%= length(@pending) %>
          </span>
        </div>

        <%= if Enum.empty?(@pending) do %>
          <div class="text-center py-10 text-gray-400 bg-white border border-gray-200 rounded-lg">
            <p>No pending enrollment requests.</p>
          </div>
        <% else %>
          <div class="bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden">
            <table class="w-full text-sm">
              <thead>
                <tr class="text-left text-xs text-gray-500 uppercase tracking-wide bg-gray-50 border-b border-gray-200">
                  <th class="px-4 py-3 font-medium">Pod Name</th>
                  <th class="px-4 py-3 font-medium">Public Key Fingerprint (SHA-256)</th>
                  <th class="px-4 py-3 font-medium">Requested At</th>
                  <th class="px-4 py-3 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                <%= for pod <- @pending do %>
                  <tr class="border-b border-gray-100 last:border-0 hover:bg-gray-50">
                    <td class="px-4 py-3 font-mono font-semibold text-gray-800"><%= pod.name %></td>
                    <td class="px-4 py-3">
                      <code class="text-xs font-mono text-gray-600 break-all">
                        <%= pod.key_fingerprint || "—" %>
                      </code>
                    </td>
                    <td class="px-4 py-3 text-gray-600 whitespace-nowrap">
                      <%= format_datetime(pod.inserted_at) %>
                    </td>
                    <td class="px-4 py-3">
                      <div class="flex gap-2">
                        <button
                          phx-click="approve"
                          phx-value-id={pod.id}
                          class="inline-flex items-center px-3 py-1.5 rounded text-xs font-medium bg-green-600 text-white hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500"
                        >
                          Approve
                        </button>
                        <button
                          phx-click="deny"
                          phx-value-id={pod.id}
                          data-confirm="Deny this enrollment request?"
                          class="inline-flex items-center px-3 py-1.5 rounded text-xs font-medium bg-red-100 text-red-700 hover:bg-red-200 focus:outline-none focus:ring-2 focus:ring-red-400"
                        >
                          Deny
                        </button>
                      </div>
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        <% end %>
      </section>

      <%!-- Enrolled pods section --%>
      <section>
        <div class="flex items-center gap-3 mb-3">
          <h2 class="text-lg font-semibold text-gray-800">Enrolled Pods</h2>
          <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
            <%= length(@enrolled) %>
          </span>
        </div>

        <%= if Enum.empty?(@enrolled) do %>
          <div class="text-center py-10 text-gray-400 bg-white border border-gray-200 rounded-lg">
            <p>No enrolled pods yet.</p>
          </div>
        <% else %>
          <div class="bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden">
            <table class="w-full text-sm">
              <thead>
                <tr class="text-left text-xs text-gray-500 uppercase tracking-wide bg-gray-50 border-b border-gray-200">
                  <th class="px-4 py-3 font-medium">Pod Name</th>
                  <th class="px-4 py-3 font-medium">Cert Serial</th>
                  <th class="px-4 py-3 font-medium">Cert Expires</th>
                  <th class="px-4 py-3 font-medium">Last Seen</th>
                  <th class="px-4 py-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                <%= for pod <- @enrolled do %>
                  <% expired = cert_expired?(pod) %>
                  <tr class="border-b border-gray-100 last:border-0 hover:bg-gray-50">
                    <td class="px-4 py-3 font-mono font-semibold text-gray-800"><%= pod.name %></td>
                    <td class="px-4 py-3">
                      <code class="text-xs font-mono text-gray-600"><%= pod.cert_serial || "—" %></code>
                    </td>
                    <td class={"px-4 py-3 whitespace-nowrap #{if expired, do: "text-red-600 font-medium", else: "text-gray-600"}"}>
                      <%= format_datetime(pod.cert_expires_at) %>
                      <%= if expired do %><span class="ml-1 text-xs">(expired)</span><% end %>
                    </td>
                    <td class="px-4 py-3 text-gray-600 whitespace-nowrap">
                      <%= format_datetime(pod.last_seen_at) %>
                    </td>
                    <td class="px-4 py-3">
                      <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                        enrolled
                      </span>
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        <% end %>
      </section>
    </div>
    """
  end
end
