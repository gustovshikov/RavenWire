defmodule ConfigManagerWeb.PipelineLive.SensorPipelineLive do
  @moduledoc "Per-sensor live data-flow pipeline visualization."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.PipelineComponent

  alias ConfigManager.{Forwarding, Pools, Repo, SensorPod}
  alias ConfigManager.Health.Registry
  alias ConfigManager.Pipeline.Derivation
  alias ConfigManagerWeb.Formatters

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Repo.get(SensorPod, id) do
      nil ->
        {:ok,
         socket
         |> assign(:page_title, "Sensor Not Found")
         |> assign(:not_found, true)}

      %SensorPod{} = pod ->
        if connected?(socket) do
          Phoenix.PubSub.subscribe(ConfigManager.PubSub, Registry.pod_topic(pod.name))

          if pod.pool_id do
            Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pod.pool_id}:forwarding")
          end
        end

        {:ok,
         socket
         |> assign(:page_title, "#{pod.name} Pipeline")
         |> assign(:not_found, false)
         |> assign(:pod, pod)
         |> assign(:health_key, pod.name)
         |> assign_pipeline_context()}
    end
  end

  @impl true
  def handle_info({:pod_updated, health_key}, %{assigns: %{health_key: health_key}} = socket),
    do: {:noreply, assign_pipeline_context(socket)}

  def handle_info(
        {:pod_degraded, health_key, _reason, _value},
        %{assigns: %{health_key: health_key}} = socket
      ),
      do: {:noreply, assign_pipeline_context(socket)}

  def handle_info(
        {:pod_recovered, health_key, _reason},
        %{assigns: %{health_key: health_key}} = socket
      ),
      do: {:noreply, assign_pipeline_context(socket)}

  def handle_info(
        {:pool_assignment_changed, sensor_id, pool_id},
        %{assigns: %{pod: %{id: sensor_id}}} = socket
      ) do
    if pool_id do
      Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool_id}:forwarding")
    end

    pod = Repo.get!(SensorPod, sensor_id)

    {:noreply,
     socket
     |> assign(:pod, pod)
     |> assign_pipeline_context()}
  end

  def handle_info({event, _payload}, socket)
      when event in [
             :sink_created,
             :sink_updated,
             :sink_deleted,
             :sink_toggled,
             :schema_mode_changed
           ],
      do: {:noreply, assign_pipeline_context(socket)}

  def handle_info({:connection_test_complete, _sink_id, _result}, socket),
    do: {:noreply, assign_pipeline_context(socket)}

  def handle_info(_message, socket), do: {:noreply, socket}

  @impl true
  def render(%{not_found: true} = assigns) do
    ~H"""
    <main class="mx-auto max-w-3xl px-6 py-12">
      <a href="/" class="text-sm text-blue-600 hover:underline">Back to dashboard</a>
      <h1 class="mt-6 text-2xl font-bold text-gray-900">Sensor Not Found</h1>
      <p class="mt-2 text-gray-600">The requested sensor was not found.</p>
    </main>
    """
  end

  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <div class="mb-6 flex flex-col gap-3 border-b border-gray-200 pb-4 md:flex-row md:items-center md:justify-between">
        <div>
          <div class="flex flex-wrap gap-3 text-sm">
            <a href={"/sensors/#{@pod.id}"} class="text-blue-600 hover:underline">Back to sensor</a>
            <a href={"/sensors/#{@pod.id}/pipeline/graph"} class="text-blue-600 hover:underline">Node Graph</a>
            <a href={"/sensors/#{@pod.id}/metrics"} class="text-blue-600 hover:underline">Metrics</a>
            <a href={"/sensors/#{@pod.id}/baselines"} class="text-blue-600 hover:underline">Baselines</a>
            <a :if={@pod.pool_id} href={"/pools/#{@pod.pool_id}/pipeline"} class="text-blue-600 hover:underline">Pool Pipeline</a>
          </div>
          <h1 class="mt-2 text-2xl font-bold text-gray-900"><%= @pod.name %> Pipeline</h1>
          <p class="text-sm text-gray-500">
            Last report:
            <%= Formatters.format_utc(Map.get(@pipeline_state, :last_report_timestamp)) %>
          </p>
        </div>
        <span class="w-fit rounded border border-gray-200 px-3 py-2 text-sm font-medium text-gray-800">
          <%= @pod.status %>
        </span>
      </div>

      <.pipeline_visualization pipeline_state={@pipeline_state} mode={:sensor} />
    </main>
    """
  end

  defp assign_pipeline_context(socket) do
    pod = Repo.get!(SensorPod, socket.assigns.pod.id)
    pool = if pod.pool_id, do: Pools.get_pool(pod.pool_id)
    health_key = pod.name

    pipeline_state =
      Derivation.derive_sensor_pipeline(Registry.get(health_key), pod,
        now: DateTime.utc_now(),
        stale_threshold_sec: stale_threshold_sec(),
        forwarding_sinks: forwarding_sinks(pool),
        forwarding_summary: forwarding_summary(pool),
        capture_mode: capture_mode(pool),
        degradation_reasons: Registry.get_degradation_reasons(health_key)
      )

    assign(socket,
      pod: pod,
      health_key: health_key,
      pool: pool,
      pipeline_state: pipeline_state
    )
  end

  defp forwarding_sinks(nil), do: []
  defp forwarding_sinks(pool), do: Forwarding.list_sinks(pool.id)

  defp forwarding_summary(nil),
    do: %{sink_count: 0, enabled_count: 0, schema_mode: nil}

  defp forwarding_summary(pool), do: Forwarding.forwarding_summary(pool.id)

  defp capture_mode(nil), do: "alert_driven"
  defp capture_mode(pool), do: pool.capture_mode

  defp stale_threshold_sec do
    :config_manager
    |> Application.get_env(:sensor_detail_stale_threshold_sec, 60)
    |> max(1)
  end
end
