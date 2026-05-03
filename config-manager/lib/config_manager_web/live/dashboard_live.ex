defmodule ConfigManagerWeb.DashboardLive do
  @moduledoc """
  Health dashboard LiveView — shows all connected Sensor_Pods with real-time
  operational status. Updated via LiveView within 2 seconds of any state change.

  Requirements: 10.3, 10.4, 22.2, 22.3
  """

  use ConfigManagerWeb, :live_view

  alias ConfigManager.Health.Registry

  # ── Mount ────────────────────────────────────────────────────────────────────

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(ConfigManager.PubSub, "sensor_pods")
    end

    pods = Registry.get_all() |> index_by_id()

    degraded_pods =
      Registry.get_degraded_pods() |> Map.new(fn {k, v} -> {k, MapSet.to_list(v)} end)

    {:ok, assign(socket, pods: pods, degraded_pods: degraded_pods)}
  end

  # ── PubSub handlers ──────────────────────────────────────────────────────────

  @impl true
  def handle_info({:pod_updated, pod_id}, socket) do
    pods =
      case Registry.get(pod_id) do
        nil -> Map.delete(socket.assigns.pods, pod_id)
        pod -> Map.put(socket.assigns.pods, pod_id, pod)
      end

    {:noreply, assign(socket, pods: pods)}
  end

  def handle_info({:pod_degraded, pod_id, reason, _offset_ms}, socket) do
    degraded_pods =
      Map.update(socket.assigns.degraded_pods, pod_id, [reason], fn reasons ->
        if reason in reasons, do: reasons, else: [reason | reasons]
      end)

    {:noreply, assign(socket, degraded_pods: degraded_pods)}
  end

  def handle_info({:pod_recovered, pod_id, reason}, socket) do
    degraded_pods =
      case Map.get(socket.assigns.degraded_pods, pod_id) do
        nil ->
          socket.assigns.degraded_pods

        reasons ->
          updated = List.delete(reasons, reason)

          if updated == [] do
            Map.delete(socket.assigns.degraded_pods, pod_id)
          else
            Map.put(socket.assigns.degraded_pods, pod_id, updated)
          end
      end

    {:noreply, assign(socket, degraded_pods: degraded_pods)}
  end

  # ── Helpers ──────────────────────────────────────────────────────────────────

  defp index_by_id(pods) do
    Map.new(pods, fn pod -> {pod.sensor_pod_id, pod} end)
  end

  @doc "Derives overall pod status from container states."
  def pod_status([]), do: "stopped"

  def pod_status(containers) do
    states = Enum.map(containers, & &1.state)

    cond do
      "error" in states -> "error"
      "restarting" in states -> "restarting"
      Enum.all?(states, &(&1 == "running")) -> "running"
      true -> "stopped"
    end
  end

  @doc "Derives overall pod status, factoring in degradation reasons."
  def pod_status_with_degraded(containers, degradation_reasons) do
    base = pod_status(containers)

    if base == "running" and degradation_reasons != [] do
      "degraded"
    else
      base
    end
  end

  @doc "Returns a Tailwind CSS class for a given container/pod state badge."
  def status_color("running"), do: "bg-green-100 text-green-800"
  def status_color("stopped"), do: "bg-gray-100 text-gray-700"
  def status_color("error"), do: "bg-red-100 text-red-800"
  def status_color("restarting"), do: "bg-yellow-100 text-yellow-800"
  def status_color("degraded"), do: "bg-orange-100 text-orange-800"
  def status_color("ok"), do: "bg-green-100 text-green-800"
  def status_color("warning"), do: "bg-yellow-100 text-yellow-800"
  def status_color("critical"), do: "bg-red-100 text-red-800"
  def status_color(_), do: "bg-gray-100 text-gray-500"

  @doc "Formats uptime seconds into a human-readable string like '2d 3h 15m'."
  def format_uptime(nil), do: "—"
  def format_uptime(seconds) when seconds < 0, do: "—"
  def format_uptime(seconds) when seconds < 60, do: "#{seconds}s"

  def format_uptime(seconds) do
    days = div(seconds, 86_400)
    rem = rem(seconds, 86_400)
    hours = div(rem, 3_600)
    rem2 = rem(rem, 3_600)
    minutes = div(rem2, 60)

    [
      if(days > 0, do: "#{days}d", else: nil),
      if(hours > 0, do: "#{hours}h", else: nil),
      "#{minutes}m"
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" ")
  end

  @doc "Formats bytes into a human-readable string like '1.2 GB'."
  def format_bytes(nil), do: "—"

  def format_bytes(bytes) when bytes >= 1_073_741_824 do
    :erlang.float_to_binary(bytes / 1_073_741_824, decimals: 1) <> " GB"
  end

  def format_bytes(bytes) when bytes >= 1_048_576 do
    :erlang.float_to_binary(bytes / 1_048_576, decimals: 1) <> " MB"
  end

  def format_bytes(bytes) when bytes >= 1_024 do
    :erlang.float_to_binary(bytes / 1_024, decimals: 1) <> " KB"
  end

  def format_bytes(bytes), do: "#{bytes} B"

  def format_percent(value, decimals \\ 1)

  def format_percent(nil, decimals),
    do: :erlang.float_to_binary(0.0, decimals: decimals) <> "%"

  def format_percent(value, decimals) do
    :erlang.float_to_binary(value || 0.0, decimals: decimals) <> "%"
  end

  defp format_timestamp(nil), do: "—"

  defp format_timestamp(unix_ms) do
    unix_ms
    |> div(1_000)
    |> DateTime.from_unix!()
    |> Calendar.strftime("%Y-%m-%d %H:%M:%S UTC")
  end

  # ── Render ───────────────────────────────────────────────────────────────────

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold text-gray-900">RavenWire Sensor Health</h1>
        <div class="flex items-center gap-4">
          <a href="/enrollment" class="text-sm text-blue-600 hover:underline">Enrollment</a>
          <a href="/pcap-config" class="text-sm text-blue-600 hover:underline">PCAP Config</a>
          <a href="/rules" class="text-sm text-blue-600 hover:underline">Rules</a>
          <a href="/support-bundle" class="text-sm text-blue-600 hover:underline">Support Bundles</a>
          <span class="text-sm text-gray-500"><%= map_size(@pods) %> pod(s) connected</span>
        </div>
      </div>

      <%= if map_size(@pods) == 0 do %>
        <div class="text-center py-16 text-gray-400">
          <p class="text-lg">No sensor pods connected.</p>
          <p class="text-sm mt-1">Pods will appear here once they start reporting health data.</p>
        </div>
      <% else %>
        <div class="space-y-6">
          <%= for {_id, pod} <- Enum.sort_by(@pods, fn {id, _} -> id end) do %>
            <% degradation_reasons = Map.get(@degraded_pods, pod.sensor_pod_id, []) %>
            <% overall = pod_status_with_degraded(pod.containers, degradation_reasons) %>
            <div class="bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden">
              <%!-- Pod header --%>
              <div class="flex items-center justify-between px-5 py-4 bg-gray-50 border-b border-gray-200">
                <div class="flex items-center gap-3">
                  <span class="font-mono font-semibold text-gray-800"><%= pod.sensor_pod_id %></span>
                  <span class={"inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium #{status_color(overall)}"}>
                    <%= overall %>
                  </span>
                  <%= if degradation_reasons != [] do %>
                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-800">
                      ⚠ degraded
                    </span>
                  <% end %>
                </div>
                <span class="text-xs text-gray-500">Last seen: <%= format_timestamp(pod.timestamp_unix_ms) %></span>
              </div>

              <%!-- Host system section --%>
              <%= if pod.system do %>
                <div class="px-5 py-4 border-b border-gray-100">
                  <div class="flex items-center justify-between mb-3">
                    <h3 class="text-xs font-semibold text-gray-500 uppercase tracking-wide">Host System</h3>
                    <span class={"inline-flex items-center px-2 py-0.5 rounded text-xs font-medium #{status_color(pod.system.health)}"}>
                      <%= pod.system.health || "unknown" %>
                    </span>
                  </div>
                  <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <div class="text-xs text-gray-500">Uptime</div>
                      <div class="font-medium text-gray-800"><%= format_uptime(pod.system.uptime_seconds) %></div>
                    </div>
                    <div>
                      <div class="text-xs text-gray-500">CPU</div>
                      <div class="font-medium text-gray-800">
                        <%= format_percent(pod.system.cpu_percent) %>
                        <span class="text-xs text-gray-500">/ <%= pod.system.cpu_count %> cores</span>
                      </div>
                    </div>
                    <div>
                      <div class="text-xs text-gray-500">RAM</div>
                      <div class="font-medium text-gray-800">
                        <%= format_percent(pod.system.memory_used_percent) %>
                        <span class="text-xs text-gray-500">
                          <%= format_bytes(pod.system.memory_used_bytes) %> / <%= format_bytes(pod.system.memory_total_bytes) %>
                        </span>
                      </div>
                    </div>
                    <div>
                      <div class="text-xs text-gray-500">Disk <span class="font-mono"><%= pod.system.disk_path %></span></div>
                      <div class="font-medium text-gray-800">
                        <%= format_percent(pod.system.disk_used_percent) %>
                        <span class="text-xs text-gray-500">
                          <%= format_bytes(pod.system.disk_used_bytes) %> / <%= format_bytes(pod.system.disk_total_bytes) %>
                        </span>
                      </div>
                    </div>
                  </div>
                  <div class="mt-3 text-xs text-gray-500">
                    Load average:
                    <span class="font-mono text-gray-700"><%= :erlang.float_to_binary(pod.system.load1 || 0.0, decimals: 2) %></span>,
                    <span class="font-mono text-gray-700"><%= :erlang.float_to_binary(pod.system.load5 || 0.0, decimals: 2) %></span>,
                    <span class="font-mono text-gray-700"><%= :erlang.float_to_binary(pod.system.load15 || 0.0, decimals: 2) %></span>
                  </div>
                </div>
              <% end %>

              <%!-- Storage section retained for PCAP alert storage path --%>
              <%= if pod.storage do %>
                <div class="px-5 py-3 border-b border-gray-100">
                  <h3 class="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">PCAP Storage</h3>
                  <div class="flex flex-wrap gap-6 text-sm">
                    <div>
                      <span class="text-gray-500">Path: </span>
                      <span class="font-mono text-gray-800"><%= pod.storage.path %></span>
                    </div>
                    <div>
                      <span class="text-gray-500">Used: </span>
                      <span class="font-medium text-gray-800"><%= format_percent(pod.storage.used_percent) %></span>
                    </div>
                    <div>
                      <span class="text-gray-500">Available: </span>
                      <span class="font-medium text-gray-800"><%= format_bytes(pod.storage.available_bytes) %></span>
                    </div>
                  </div>
                </div>
              <% end %>

              <%!-- Containers table --%>
              <%= if pod.containers != [] do %>
                <div class="px-5 py-3">
                  <h3 class="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Containers</h3>
                  <table class="w-full text-sm">
                    <thead>
                      <tr class="text-left text-xs text-gray-500 border-b border-gray-100">
                        <th class="pb-1 pr-4 font-medium">Name</th>
                        <th class="pb-1 pr-4 font-medium">State</th>
                        <th class="pb-1 pr-4 font-medium">Uptime</th>
                        <th class="pb-1 pr-4 font-medium">CPU%</th>
                        <th class="pb-1 font-medium">Memory</th>
                      </tr>
                    </thead>
                    <tbody>
                      <%= for container <- pod.containers do %>
                        <tr class="border-b border-gray-50 last:border-0">
                          <td class="py-1.5 pr-4 font-mono text-gray-800"><%= container.name %></td>
                          <td class="py-1.5 pr-4">
                            <span class={"inline-flex items-center px-2 py-0.5 rounded text-xs font-medium #{status_color(container.state)}"}>
                              <%= container.state %>
                            </span>
                          </td>
                          <td class="py-1.5 pr-4 text-gray-600"><%= format_uptime(container.uptime_seconds) %></td>
                          <td class="py-1.5 pr-4 text-gray-600"><%= format_percent(container.cpu_percent) %></td>
                          <td class="py-1.5 text-gray-600"><%= format_bytes(container.memory_bytes) %></td>
                        </tr>
                      <% end %>
                    </tbody>
                  </table>
                </div>
              <% end %>

              <%!-- Consumers table --%>
              <%= if pod.capture && map_size(pod.capture.consumers) > 0 do %>
                <div class="px-5 py-3 border-t border-gray-100">
                  <h3 class="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Capture Consumers</h3>
                  <table class="w-full text-sm">
                    <thead>
                      <tr class="text-left text-xs text-gray-500 border-b border-gray-100">
                        <th class="pb-1 pr-4 font-medium">Consumer</th>
                        <th class="pb-1 pr-4 font-medium">Packets Received</th>
                        <th class="pb-1 pr-4 font-medium">Packets Dropped</th>
                        <th class="pb-1 pr-4 font-medium">Drop%</th>
                        <th class="pb-1 font-medium">BPF Restart</th>
                      </tr>
                    </thead>
                    <tbody>
                      <%= for {name, stats} <- Enum.sort_by(pod.capture.consumers, fn {k, _} -> k end) do %>
                        <tr class="border-b border-gray-50 last:border-0">
                          <td class="py-1.5 pr-4 font-mono text-gray-800"><%= name %></td>
                          <td class="py-1.5 pr-4 text-gray-600"><%= stats.packets_received %></td>
                          <td class="py-1.5 pr-4 text-gray-600"><%= stats.packets_dropped %></td>
                          <td class={"py-1.5 pr-4 font-medium #{if stats.drop_percent > 5.0, do: "text-red-600", else: "text-gray-600"}"}>
                            <%= :erlang.float_to_binary(stats.drop_percent || 0.0, decimals: 2) %>%
                          </td>
                          <td class="py-1.5">
                            <%= if Map.get(stats, :bpf_restart_pending, false) do %>
                              <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-orange-100 text-orange-800">
                                restart required
                              </span>
                            <% else %>
                              <span class="text-gray-400">—</span>
                            <% end %>
                          </td>
                        </tr>
                      <% end %>
                    </tbody>
                  </table>
                </div>
              <% end %>

              <%!-- Clock section --%>
              <%= if pod.clock do %>
                <% clock_drift_degraded = :clock_drift in degradation_reasons %>
                <div class="px-5 py-3 border-t border-gray-100">
                  <h3 class="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Clock</h3>
                  <div class="flex flex-wrap gap-6 text-sm">
                    <div>
                      <span class="text-gray-500">Offset: </span>
                      <span class={"font-medium #{if clock_drift_degraded, do: "text-red-600", else: "text-gray-800"}"}>
                        <%= pod.clock.offset_ms %> ms
                        <%= if clock_drift_degraded do %>⚠<% end %>
                      </span>
                    </div>
                    <div>
                      <span class="text-gray-500">NTP Sync: </span>
                      <span class={"font-medium #{if pod.clock.synchronized, do: "text-green-700", else: "text-red-600"}"}>
                        <%= if pod.clock.synchronized, do: "yes", else: "no" %>
                      </span>
                    </div>
                    <%= if pod.clock.source && pod.clock.source != "" do %>
                      <div>
                        <span class="text-gray-500">Source: </span>
                        <span class="font-mono text-gray-800"><%= pod.clock.source %></span>
                      </div>
                    <% end %>
                  </div>
                </div>
              <% end %>
            </div>
          <% end %>
        </div>
      <% end %>
    </div>
    """
  end
end
