defmodule ConfigManagerWeb.SupportBundleLive do
  @moduledoc """
  LiveView for triggering and downloading per-Sensor_Pod support bundles.

  Operators click "Generate Support Bundle" for a pod; the request is dispatched
  asynchronously so the UI remains responsive. On success a "Download" link
  appears pointing to the download controller action.

  Requirements: 25.4
  """

  use ConfigManagerWeb, :live_view

  import Ecto.Query

  alias ConfigManager.Repo
  alias ConfigManager.SensorPod
  alias ConfigManager.SensorAgentClient

  # ── Mount ────────────────────────────────────────────────────────────────────

  @impl true
  def mount(_params, _session, socket) do
    pods = Repo.all(from p in SensorPod, where: p.status == "enrolled", order_by: p.name)

    pod_states =
      Map.new(pods, fn pod ->
        {pod.id, %{status: :idle, bundle_path: nil, error: nil}}
      end)

    {:ok, assign(socket, pods: pods, pod_states: pod_states)}
  end

  # ── Events ───────────────────────────────────────────────────────────────────

  @impl true
  def handle_event("generate", %{"pod-id" => pod_id}, socket) do
    pod = Enum.find(socket.assigns.pods, &(&1.id == pod_id))

    if pod do
      pod_states = put_in(socket.assigns.pod_states, [pod_id], %{status: :generating, bundle_path: nil, error: nil})
      socket = assign(socket, pod_states: pod_states)

      Task.async(fn -> {pod_id, SensorAgentClient.request_support_bundle(pod)} end)

      {:noreply, socket}
    else
      {:noreply, socket}
    end
  end

  # ── Async task result ────────────────────────────────────────────────────────

  @impl true
  def handle_info({ref, {pod_id, result}}, socket) when is_reference(ref) do
    Process.demonitor(ref, [:flush])

    pod_states =
      case result do
        {:ok, %{"bundle_path" => path}} ->
          put_in(socket.assigns.pod_states, [pod_id], %{status: :ready, bundle_path: path, error: nil})

        {:ok, _other} ->
          put_in(socket.assigns.pod_states, [pod_id], %{
            status: :error,
            bundle_path: nil,
            error: "Unexpected response from Sensor_Agent"
          })

        {:error, reason} ->
          put_in(socket.assigns.pod_states, [pod_id], %{
            status: :error,
            bundle_path: nil,
            error: format_error(reason)
          })
      end

    socket =
      socket
      |> assign(pod_states: pod_states)
      |> maybe_flash_error(pod_id, pod_states)

    {:noreply, socket}
  end

  def handle_info({:DOWN, _ref, :process, _pid, _reason}, socket), do: {:noreply, socket}

  # ── Helpers ──────────────────────────────────────────────────────────────────

  defp maybe_flash_error(socket, pod_id, pod_states) do
    case get_in(pod_states, [pod_id, :status]) do
      :error ->
        error_msg = get_in(pod_states, [pod_id, :error])
        put_flash(socket, :error, "Support bundle failed: #{error_msg}")

      _ ->
        socket
    end
  end

  defp format_error({:http_error, status, body}), do: "HTTP #{status}: #{body}"
  defp format_error(:no_control_api_host), do: "Pod has no control API host configured"
  defp format_error(reason), do: inspect(reason)

  defp download_url(pod_id, bundle_path) do
    "/support-bundle/download/#{pod_id}?path=#{URI.encode_www_form(bundle_path)}"
  end

  defp format_last_seen(nil), do: "—"

  defp format_last_seen(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  end

  defp format_last_seen(_), do: "—"

  # ── Render ───────────────────────────────────────────────────────────────────

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold text-gray-900">Support Bundles</h1>
        <div class="flex items-center gap-4">
          <a href="/enrollment" class="text-sm text-blue-600 hover:underline">Enrollment</a>
          <a href="/pcap-config" class="text-sm text-blue-600 hover:underline">PCAP Config</a>
          <a href="/rules" class="text-sm text-blue-600 hover:underline">Rules</a>
          <a href="/support-bundle" class="text-sm text-blue-600 hover:underline">Support Bundles</a>
        </div>
      </div>

      <%= if @flash[:error] do %>
        <div class="mb-4 px-4 py-3 rounded bg-red-50 border border-red-200 text-red-700 text-sm">
          <%= @flash[:error] %>
        </div>
      <% end %>

      <div class="bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden">
        <%= if @pods == [] do %>
          <div class="text-center py-16 text-gray-400">
            <p class="text-lg">No enrolled sensor pods.</p>
            <p class="text-sm mt-1">Pods must be enrolled before generating support bundles.</p>
          </div>
        <% else %>
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-xs text-gray-500 border-b border-gray-200 bg-gray-50">
                <th class="px-5 py-3 font-medium">Pod Name</th>
                <th class="px-5 py-3 font-medium">Status</th>
                <th class="px-5 py-3 font-medium">Last Seen</th>
                <th class="px-5 py-3 font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              <%= for pod <- @pods do %>
                <% state = Map.get(@pod_states, pod.id, %{status: :idle, bundle_path: nil, error: nil}) %>
                <tr class="border-b border-gray-100 last:border-0">
                  <td class="px-5 py-3 font-mono text-gray-800"><%= pod.name %></td>
                  <td class="px-5 py-3">
                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                      <%= pod.status %>
                    </span>
                  </td>
                  <td class="px-5 py-3 text-gray-600"><%= format_last_seen(pod.last_seen_at) %></td>
                  <td class="px-5 py-3">
                    <div class="flex items-center gap-3">
                      <button
                        phx-click="generate"
                        phx-value-pod-id={pod.id}
                        disabled={state.status == :generating}
                        class="px-3 py-1.5 text-sm font-medium rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
                      >
                        <%= if state.status == :generating do %>
                          Generating…
                        <% else %>
                          Generate Support Bundle
                        <% end %>
                      </button>

                      <%= if state.status == :ready && state.bundle_path do %>
                        <a
                          href={download_url(pod.id, state.bundle_path)}
                          class="px-3 py-1.5 text-sm font-medium rounded bg-gray-100 text-gray-700 hover:bg-gray-200 border border-gray-300"
                        >
                          Download
                        </a>
                      <% end %>

                      <%= if state.status == :error do %>
                        <span class="text-red-600 text-sm"><%= state.error %></span>
                      <% end %>
                    </div>
                  </td>
                </tr>
              <% end %>
            </tbody>
          </table>
        <% end %>
      </div>
    </div>
    """
  end
end
