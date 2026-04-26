defmodule ConfigManager.Health.Registry do
  @moduledoc """
  In-memory registry of connected Sensor_Pod health state.

  Updated by the gRPC health stream server as HealthReport messages arrive.
  The dashboard LiveView subscribes to PubSub and reads from this registry
  to render real-time pod status without hitting the database on every update.

  Requirements: 22.2, 22.3
  """

  use GenServer

  @table :health_registry

  # ── Public API ──────────────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Returns a list of all known pod health snapshots."
  def list_pods do
    :ets.tab2list(@table) |> Enum.map(fn {_id, pod} -> pod end)
  end

  @doc "Returns all known pod health snapshots (alias for list_pods/0)."
  def get_all, do: list_pods()

  @doc "Returns the health snapshot for a single pod, or nil."
  def get_pod(pod_id) do
    case :ets.lookup(@table, pod_id) do
      [{^pod_id, pod}] -> pod
      [] -> nil
    end
  end

  @doc "Returns the health snapshot for a single pod, or nil (alias for get_pod/1)."
  def get(pod_id), do: get_pod(pod_id)

  @doc "Upserts a pod health snapshot from a received HealthReport."
  def update_pod(pod_id, health_report) do
    GenServer.cast(__MODULE__, {:update, pod_id, health_report})
  end

  @doc "Upserts a pod health snapshot from a received HealthReport (alias for update_pod/2)."
  def update(pod_id, health_report), do: update_pod(pod_id, health_report)

  @doc "Returns the current degraded pods map: %{pod_id => MapSet of reasons}."
  def get_degraded_pods do
    GenServer.call(__MODULE__, :get_degraded_pods)
  end

  # ── GenServer callbacks ──────────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    # state: %{degraded: %{pod_id => MapSet.t(atom)}}
    {:ok, %{degraded: %{}}}
  end

  @impl true
  def handle_call(:get_degraded_pods, _from, state) do
    {:reply, state.degraded, state}
  end

  @impl true
  def handle_cast({:update, pod_id, report}, state) do
    :ets.insert(@table, {pod_id, report})
    Phoenix.PubSub.broadcast(ConfigManager.PubSub, "sensor_pods", {:pod_updated, pod_id})

    state = check_clock_drift(pod_id, report, state)

    {:noreply, state}
  end

  # ── Private helpers ──────────────────────────────────────────────────────────

  defp clock_drift_threshold do
    Application.get_env(:config_manager, :clock_drift_threshold_ms, 100)
  end

  defp check_clock_drift(pod_id, report, state) do
    threshold = clock_drift_threshold()
    offset_ms = get_in(report, [Access.key(:clock), Access.key(:offset_ms)]) || 0

    currently_degraded =
      state.degraded
      |> Map.get(pod_id, MapSet.new())
      |> MapSet.member?(:clock_drift)

    cond do
      abs(offset_ms) > threshold and not currently_degraded ->
        Phoenix.PubSub.broadcast(
          ConfigManager.PubSub,
          "sensor_pods",
          {:pod_degraded, pod_id, :clock_drift, offset_ms}
        )

        reasons = state.degraded |> Map.get(pod_id, MapSet.new()) |> MapSet.put(:clock_drift)
        %{state | degraded: Map.put(state.degraded, pod_id, reasons)}

      abs(offset_ms) <= threshold and currently_degraded ->
        Phoenix.PubSub.broadcast(
          ConfigManager.PubSub,
          "sensor_pods",
          {:pod_recovered, pod_id, :clock_drift}
        )

        reasons = state.degraded |> Map.get(pod_id, MapSet.new()) |> MapSet.delete(:clock_drift)

        if MapSet.size(reasons) == 0 do
          %{state | degraded: Map.delete(state.degraded, pod_id)}
        else
          %{state | degraded: Map.put(state.degraded, pod_id, reasons)}
        end

      true ->
        state
    end
  end
end
