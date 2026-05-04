defmodule ConfigManagerWeb.DashboardLive do
  @moduledoc """
  Health dashboard LiveView — shows all connected Sensor_Pods with real-time
  operational status. Updated via LiveView within 2 seconds of any state change.

  Requirements: 10.3, 10.4, 22.2, 22.3
  """

  use ConfigManagerWeb, :live_view

  import Ecto.Query

  alias ConfigManager.{Repo, SensorPod}
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

    {:ok, assign(socket, pods: pods, degraded_pods: degraded_pods, pod_db_ids: pod_db_ids())}
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

  defp pod_db_ids do
    Repo.all(from(p in SensorPod, select: {p.name, p.id}))
    |> Map.new()
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

  defp format_age(nil), do: "—"

  defp format_age(unix_ms) do
    seconds =
      DateTime.utc_now()
      |> DateTime.diff(DateTime.from_unix!(div(unix_ms, 1_000)), :second)
      |> max(0)

    cond do
      seconds < 60 -> "#{seconds}s ago"
      seconds < 3_600 -> "#{div(seconds, 60)}m ago"
      seconds < 86_400 -> "#{div(seconds, 3_600)}h ago"
      true -> "#{div(seconds, 86_400)}d ago"
    end
  end

  defp container_summary(containers) do
    total = length(containers || [])
    running = Enum.count(containers || [], &(&1.state == "running"))

    cond do
      total == 0 -> "No containers"
      running == total -> "#{running}/#{total} running"
      true -> "#{running}/#{total} running"
    end
  end

  defp max_drop_percent(nil), do: 0.0
  defp max_drop_percent(%{consumers: consumers}) when consumers in [nil, %{}], do: 0.0

  defp max_drop_percent(%{consumers: consumers}) do
    consumers
    |> Map.values()
    |> Enum.map(&(&1.drop_percent || 0.0))
    |> Enum.max(fn -> 0.0 end)
  end

  defp issue_count(overall, degradation_reasons, pod) do
    [
      if(overall in ["running", "ok"], do: nil, else: overall),
      if(degradation_reasons == [], do: nil, else: "degraded"),
      if(max_drop_percent(pod.capture) > 5.0, do: "packet drops", else: nil),
      if(system_disk_used_percent(pod) > 85.0, do: "disk", else: nil)
    ]
    |> Enum.reject(&is_nil/1)
    |> length()
  end

  defp system_disk_used_percent(%{system: %{disk_used_percent: percent}}) when is_number(percent),
    do: percent

  defp system_disk_used_percent(_pod), do: 0.0

  defp disk_free(%{storage: %{available_bytes: bytes}}) when is_integer(bytes),
    do: format_bytes(bytes)

  defp disk_free(%{system: %{disk_available_bytes: bytes}}) when is_integer(bytes),
    do: format_bytes(bytes)

  defp disk_free(_pod), do: "—"

  # ── Render ───────────────────────────────────────────────────────────────────

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <div class="mb-6 flex items-center justify-between gap-4">
        <div>
          <h1 class="text-2xl font-bold text-gray-900">Sensors</h1>
          <p class="mt-1 text-sm text-gray-500"><%= map_size(@pods) %> reporting sensor pod(s)</p>
        </div>
      </div>

      <%= if map_size(@pods) == 0 do %>
        <div class="text-center py-16 text-gray-400">
          <p class="text-lg">No sensor pods connected.</p>
          <p class="text-sm mt-1">Pods will appear here once they start reporting health data.</p>
        </div>
      <% else %>
        <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          <%= for {_id, pod} <- Enum.sort_by(@pods, fn {id, _} -> id end) do %>
            <% degradation_reasons = Map.get(@degraded_pods, pod.sensor_pod_id, []) %>
            <% overall = pod_status_with_degraded(pod.containers, degradation_reasons) %>
            <% issues = issue_count(overall, degradation_reasons, pod) %>
            <% max_drop = max_drop_percent(pod.capture) %>
            <article class="rounded border border-gray-200 bg-white p-4 shadow-sm">
              <div class="mb-4 flex items-start justify-between gap-3">
                <div class="min-w-0">
                  <%= if db_id = Map.get(@pod_db_ids, pod.sensor_pod_id) do %>
                    <a
                      href={"/sensors/#{db_id}"}
                      aria-label={"View details for #{pod.sensor_pod_id}"}
                      class="block truncate font-mono text-sm font-semibold text-blue-700 hover:underline"
                    >
                      <%= pod.sensor_pod_id %>
                    </a>
                  <% else %>
                    <span class="block truncate font-mono text-sm font-semibold text-gray-800"><%= pod.sensor_pod_id %></span>
                  <% end %>
                  <p class="mt-1 text-xs text-gray-500" title={format_timestamp(pod.timestamp_unix_ms)}>
                    Last report <%= format_age(pod.timestamp_unix_ms) %>
                  </p>
                </div>
                <span class={"shrink-0 rounded px-2 py-0.5 text-xs font-medium #{status_color(overall)}"}>
                  <%= overall %>
                </span>
              </div>

              <dl class="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <dt class="text-xs font-medium uppercase text-gray-500">Issues</dt>
                  <dd class="mt-1 font-medium text-gray-900"><%= issues %></dd>
                </div>
                <div>
                  <dt class="text-xs font-medium uppercase text-gray-500">Host</dt>
                  <dd class="mt-1 font-medium text-gray-900"><%= if pod.system, do: pod.system.health || "unknown", else: "unknown" %></dd>
                </div>
                <div>
                  <dt class="text-xs font-medium uppercase text-gray-500">CPU</dt>
                  <dd class="mt-1 font-medium text-gray-900"><%= if pod.system, do: format_percent(pod.system.cpu_percent), else: "—" %></dd>
                </div>
                <div>
                  <dt class="text-xs font-medium uppercase text-gray-500">RAM</dt>
                  <dd class="mt-1 font-medium text-gray-900"><%= if pod.system, do: format_percent(pod.system.memory_used_percent), else: "—" %></dd>
                </div>
                <div>
                  <dt class="text-xs font-medium uppercase text-gray-500">Disk Free</dt>
                  <dd class="mt-1 font-medium text-gray-900"><%= disk_free(pod) %></dd>
                </div>
                <div>
                  <dt class="text-xs font-medium uppercase text-gray-500">Containers</dt>
                  <dd class="mt-1 font-medium text-gray-900"><%= container_summary(pod.containers) %></dd>
                </div>
                <div>
                  <dt class="text-xs font-medium uppercase text-gray-500">Max Drop</dt>
                  <dd class={"mt-1 font-medium #{if max_drop > 5.0, do: "text-red-700", else: "text-gray-900"}"}>
                    <%= format_percent(max_drop, 2) %>
                  </dd>
                </div>
                <div>
                  <dt class="text-xs font-medium uppercase text-gray-500">Clock</dt>
                  <dd class="mt-1 font-medium text-gray-900">
                    <%= if pod.clock do %>
                      <%= pod.clock.offset_ms %> ms
                    <% else %>
                      —
                    <% end %>
                  </dd>
                </div>
              </dl>
            </article>
          <% end %>
        </div>
      <% end %>
    </div>
    """
  end
end
