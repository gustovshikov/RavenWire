defmodule ConfigManagerWeb.PipelineLive.PoolPipelineLive do
  @moduledoc "Pool-level aggregate live data-flow pipeline visualization."

  use ConfigManagerWeb, :live_view

  import ConfigManagerWeb.PipelineComponent

  alias ConfigManager.{Forwarding, Pools}
  alias ConfigManager.Health.Registry
  alias ConfigManager.Pipeline.Derivation
  alias ConfigManagerWeb.Formatters

  @debounce_ms 500

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case Pools.get_pool(id) do
      nil ->
        {:ok, assign(socket, not_found: true, page_title: "Pool Not Found")}

      pool ->
        members = Pools.list_pool_sensors(pool.id)

        if connected?(socket) do
          Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool.id}")
          Phoenix.PubSub.subscribe(ConfigManager.PubSub, "pool:#{pool.id}:forwarding")
          subscribe_member_topics(members)
        end

        {:ok,
         socket
         |> assign(:not_found, false)
         |> assign(:page_title, "#{pool.name} Pipeline")
         |> assign(:pool, pool)
         |> assign(:members, members)
         |> assign(:member_health_keys, member_health_keys(members))
         |> assign(:debounce_timer, nil)
         |> assign(:debounce_token, nil)
         |> assign_pipeline_state()}
    end
  end

  @impl true
  def handle_info({:pod_updated, health_key}, socket),
    do: maybe_schedule_rederive(socket, health_key)

  def handle_info({:pod_degraded, health_key, _reason, _value}, socket),
    do: maybe_schedule_rederive(socket, health_key)

  def handle_info({:pod_recovered, health_key, _reason}, socket),
    do: maybe_schedule_rederive(socket, health_key)

  def handle_info({:rederive, token}, %{assigns: %{debounce_token: token}} = socket) do
    {:noreply,
     socket
     |> assign(:debounce_timer, nil)
     |> assign(:debounce_token, nil)
     |> assign_pipeline_state()}
  end

  def handle_info({:rederive, _stale_token}, socket), do: {:noreply, socket}

  def handle_info({:pool_deleted, pool_id}, %{assigns: %{pool: %{id: pool_id}}} = socket),
    do: {:noreply, push_navigate(socket, to: "/pools")}

  def handle_info(
        {:sensors_assigned, pool_id, _sensor_ids},
        %{assigns: %{pool: %{id: pool_id}}} = socket
      ),
      do: {:noreply, reload_pool_members(socket)}

  def handle_info(
        {:sensors_removed, pool_id, _sensor_ids},
        %{assigns: %{pool: %{id: pool_id}}} = socket
      ),
      do: {:noreply, reload_pool_members(socket)}

  def handle_info({:pool_config_updated, pool_id}, %{assigns: %{pool: %{id: pool_id}}} = socket),
    do: {:noreply, reload_pool_members(socket)}

  def handle_info({event, _payload}, socket)
      when event in [
             :sink_created,
             :sink_updated,
             :sink_deleted,
             :sink_toggled,
             :schema_mode_changed
           ],
      do: {:noreply, assign_pipeline_state(socket)}

  def handle_info({:connection_test_complete, _sink_id, _result}, socket),
    do: {:noreply, assign_pipeline_state(socket)}

  def handle_info(_message, socket), do: {:noreply, socket}

  @impl true
  def render(%{not_found: true} = assigns) do
    ~H"""
    <main class="mx-auto max-w-3xl px-6 py-10">
      <a href="/pools" class="text-sm text-blue-600 hover:underline">Back to pools</a>
      <h1 class="mt-6 text-2xl font-bold text-gray-900">Pool Not Found</h1>
    </main>
    """
  end

  def render(assigns) do
    ~H"""
    <main class="mx-auto max-w-7xl px-6 py-6">
      <div class="mb-6 flex flex-col gap-3 border-b border-gray-200 pb-4 md:flex-row md:items-center md:justify-between">
        <div>
          <div class="flex flex-wrap gap-3 text-sm">
            <a href={"/pools/#{@pool.id}"} class="text-blue-600 hover:underline">Back to pool</a>
            <a href={"/pools/#{@pool.id}/sensors"} class="text-blue-600 hover:underline">Sensors</a>
            <a href={"/pools/#{@pool.id}/metrics"} class="text-blue-600 hover:underline">Metrics</a>
            <a href={"/pools/#{@pool.id}/baselines"} class="text-blue-600 hover:underline">Baselines</a>
          </div>
          <h1 class="mt-2 text-2xl font-bold text-gray-900"><%= @pool.name %> Pipeline</h1>
          <p class="text-sm text-gray-500">
            <%= length(@members) %> member sensor(s), capture mode <%= Formatters.display(@pool.capture_mode) %>
          </p>
        </div>
      </div>

      <section :if={@members == []} class="mb-4 rounded border border-gray-200 bg-white p-4">
        <h2 class="text-lg font-semibold text-gray-900">No Sensors Assigned</h2>
        <p class="mt-1 text-sm text-gray-500">Assign sensors to this pool to see aggregate pipeline health.</p>
      </section>

      <.pipeline_visualization
        pipeline_state={@aggregate_state}
        mode={:pool}
        pool_member_links={member_links(@members)}
      />
    </main>
    """
  end

  defp maybe_schedule_rederive(socket, health_key) do
    if MapSet.member?(socket.assigns.member_health_keys, health_key) do
      {:noreply, schedule_rederive(socket)}
    else
      {:noreply, socket}
    end
  end

  defp schedule_rederive(socket) do
    if socket.assigns.debounce_timer do
      Process.cancel_timer(socket.assigns.debounce_timer)
    end

    token = make_ref()
    timer = Process.send_after(self(), {:rederive, token}, @debounce_ms)

    assign(socket, debounce_timer: timer, debounce_token: token)
  end

  defp reload_pool_members(socket) do
    pool = Pools.get_pool!(socket.assigns.pool.id)
    members = Pools.list_pool_sensors(pool.id)

    if connected?(socket), do: subscribe_member_topics(members)

    socket
    |> assign(:pool, pool)
    |> assign(:members, members)
    |> assign(:member_health_keys, member_health_keys(members))
    |> assign_pipeline_state()
  end

  defp assign_pipeline_state(socket) do
    pool = Pools.get_pool!(socket.assigns.pool.id)
    members = socket.assigns.members
    sinks = Forwarding.list_sinks(pool.id)
    forwarding_summary = Forwarding.forwarding_summary(pool.id)

    member_states =
      Enum.map(members, fn pod ->
        pipeline_state =
          Derivation.derive_sensor_pipeline(Registry.get(pod.name), pod,
            now: DateTime.utc_now(),
            stale_threshold_sec: stale_threshold_sec(),
            forwarding_sinks: sinks,
            forwarding_summary: forwarding_summary,
            capture_mode: pool.capture_mode,
            degradation_reasons: Registry.get_degradation_reasons(pod.name)
          )

        {pod.id, pod.name, pipeline_state}
      end)

    assign(socket,
      pool: pool,
      aggregate_state: Derivation.aggregate_pool_pipeline(member_states)
    )
  end

  defp subscribe_member_topics(members) do
    Enum.each(members, fn member ->
      Phoenix.PubSub.subscribe(ConfigManager.PubSub, Registry.pod_topic(member.name))
    end)
  end

  defp member_health_keys(members), do: members |> Enum.map(& &1.name) |> MapSet.new()

  defp member_links(members) do
    Enum.map(members, fn member ->
      %{label: member.name, href: "/sensors/#{member.id}/pipeline/graph"}
    end)
  end

  defp stale_threshold_sec do
    :config_manager
    |> Application.get_env(:sensor_detail_stale_threshold_sec, 60)
    |> max(1)
  end
end
