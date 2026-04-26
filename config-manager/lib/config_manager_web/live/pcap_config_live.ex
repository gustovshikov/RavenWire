defmodule ConfigManagerWeb.PcapConfigLive do
  @moduledoc """
  Alert-Driven PCAP configuration LiveView.

  Displays per-Sensor_Pod Alert-Driven PCAP settings and allows operators to
  update ring size, pre/post-alert windows, and alert severity threshold.

  On form submit: persists config to DB, then dispatches `switch_capture_mode`
  to the Sensor_Agent control API via mTLS.

  Requirements: 10.5, 10.6, 10.7
  """

  use ConfigManagerWeb, :live_view

  alias ConfigManager.{Repo, SensorPod, SensorAgentClient}
  import Ecto.Query, only: [from: 2]

  # ── Mount ────────────────────────────────────────────────────────────────────

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(ConfigManager.PubSub, "sensor_pods")
    end

    {:ok, assign(socket, pods: list_enrolled_pods(), pod_results: %{})}
  end

  # ── Events ───────────────────────────────────────────────────────────────────

  @impl true
  def handle_event("save_pcap_config", %{"pod_id" => pod_id} = params, socket) do
    config = %{
      pcap_ring_size_mb: parse_int(params["pcap_ring_size_mb"]),
      pre_alert_window_sec: parse_int(params["pre_alert_window_sec"]),
      post_alert_window_sec: parse_int(params["post_alert_window_sec"]),
      alert_severity_threshold: parse_int(params["alert_severity_threshold"])
    }

    pod = Repo.get!(SensorPod, pod_id)
    changeset = SensorPod.pcap_config_changeset(pod, config)

    case Repo.update(changeset) do
      {:ok, updated_pod} ->
        result =
          case SensorAgentClient.switch_capture_mode(updated_pod, config) do
            {:ok, _resp} -> {:ok, "Configuration applied successfully."}
            {:error, :no_control_api_host} -> {:warn, "Saved to DB. Pod has no control API host configured — not dispatched."}
            {:error, reason} -> {:error, "Saved to DB, but dispatch failed: #{format_error(reason)}"}
          end

        pod_results = Map.put(socket.assigns.pod_results, pod_id, result)
        {:noreply, assign(socket, pods: list_enrolled_pods(), pod_results: pod_results)}

      {:error, changeset} ->
        errors = format_changeset_errors(changeset)
        pod_results = Map.put(socket.assigns.pod_results, pod_id, {:error, "Validation failed: #{errors}"})
        {:noreply, assign(socket, pod_results: pod_results)}
    end
  end

  # ── PubSub handlers ──────────────────────────────────────────────────────────

  @impl true
  def handle_info({:pod_updated, _pod_id}, socket) do
    {:noreply, assign(socket, pods: list_enrolled_pods())}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  # ── Helpers ──────────────────────────────────────────────────────────────────

  defp list_enrolled_pods do
    Repo.all(from p in SensorPod, where: p.status == "enrolled", order_by: p.name)
  end

  defp parse_int(nil), do: nil
  defp parse_int(""), do: nil
  defp parse_int(val) when is_integer(val), do: val
  defp parse_int(val) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> n
      :error -> nil
    end
  end

  defp format_error({:http_error, status, body}), do: "HTTP #{status}: #{body}"
  defp format_error(reason), do: inspect(reason)

  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> Enum.map(fn {field, msgs} -> "#{field}: #{Enum.join(msgs, ", ")}" end)
    |> Enum.join("; ")
  end

  defp severity_label(1), do: "Low"
  defp severity_label(2), do: "Medium"
  defp severity_label(3), do: "High"
  defp severity_label(_), do: "Medium"

  defp result_class({:ok, _}), do: "bg-green-50 border-green-200 text-green-800"
  defp result_class({:warn, _}), do: "bg-yellow-50 border-yellow-200 text-yellow-800"
  defp result_class({:error, _}), do: "bg-red-50 border-red-200 text-red-800"

  defp result_message({_, msg}), do: msg

  # ── Render ───────────────────────────────────────────────────────────────────

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-5xl mx-auto">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold text-gray-900">Alert-Driven PCAP Configuration</h1>
        <a href="/" class="text-sm text-blue-600 hover:underline">← Dashboard</a>
      </div>

      <p class="text-sm text-gray-500 mb-6">
        Configure per-pod Alert-Driven PCAP settings. Changes are persisted to the database
        and dispatched to the Sensor_Agent control API via mTLS.
      </p>

      <%= if Enum.empty?(@pods) do %>
        <div class="text-center py-16 text-gray-400 bg-white border border-gray-200 rounded-lg">
          <p class="text-lg">No enrolled sensor pods.</p>
          <p class="text-sm mt-1">Pods must be enrolled before PCAP configuration is available.</p>
        </div>
      <% else %>
        <div class="space-y-6">
          <%= for pod <- @pods do %>
            <% result = Map.get(@pod_results, pod.id) %>
            <div class="bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden">
              <div class="px-5 py-4 bg-gray-50 border-b border-gray-200 flex items-center justify-between">
                <div>
                  <span class="font-mono font-semibold text-gray-800"><%= pod.name %></span>
                  <span class="ml-3 text-xs text-gray-500">
                    <%= if pod.control_api_host && pod.control_api_host != "" do %>
                      control API: <code class="font-mono"><%= pod.control_api_host %>:9091</code>
                    <% else %>
                      <span class="text-yellow-600">⚠ no control API host</span>
                    <% end %>
                  </span>
                </div>
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                  alert-driven mode
                </span>
              </div>

              <%= if result do %>
                <div class={"mx-5 mt-4 px-4 py-3 rounded border text-sm #{result_class(result)}"}>
                  <%= result_message(result) %>
                </div>
              <% end %>

              <form phx-submit="save_pcap_config" class="px-5 py-4">
                <input type="hidden" name="pod_id" value={pod.id} />

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <%# Ring size %>
                  <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">
                      Ring Buffer Size (MB)
                    </label>
                    <input
                      type="number"
                      name="pcap_ring_size_mb"
                      value={pod.pcap_ring_size_mb || 4096}
                      min="1"
                      required
                      class="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <p class="mt-1 text-xs text-gray-400">Default: 4096 MB (4 GB)</p>
                  </div>

                  <%# Alert severity threshold %>
                  <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">
                      Alert Severity Threshold
                    </label>
                    <select
                      name="alert_severity_threshold"
                      class="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <%= for {val, label} <- [{1, "Low"}, {2, "Medium"}, {3, "High"}] do %>
                        <option value={val} selected={pod.alert_severity_threshold == val}>
                          <%= label %>
                        </option>
                      <% end %>
                    </select>
                    <p class="mt-1 text-xs text-gray-400">
                      Current: <%= severity_label(pod.alert_severity_threshold) %>
                    </p>
                  </div>

                  <%# Pre-alert window %>
                  <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">
                      Pre-Alert Window (seconds)
                    </label>
                    <input
                      type="number"
                      name="pre_alert_window_sec"
                      value={pod.pre_alert_window_sec || 60}
                      min="0"
                      required
                      class="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <p class="mt-1 text-xs text-gray-400">Packets preserved before alert fires. Default: 60s</p>
                  </div>

                  <%# Post-alert window %>
                  <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">
                      Post-Alert Window (seconds)
                    </label>
                    <input
                      type="number"
                      name="post_alert_window_sec"
                      value={pod.post_alert_window_sec || 30}
                      min="0"
                      required
                      class="w-full rounded border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <p class="mt-1 text-xs text-gray-400">Packets captured after alert fires. Default: 30s</p>
                  </div>
                </div>

                <div class="mt-4 flex justify-end">
                  <button
                    type="submit"
                    class="inline-flex items-center px-4 py-2 rounded text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    Apply Configuration
                  </button>
                </div>
              </form>
            </div>
          <% end %>
        </div>
      <% end %>
    </div>
    """
  end
end
